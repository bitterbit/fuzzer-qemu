// #[cfg(target_family = "unix")]
// use std::os::unix::process::ExitStatusExt;

use core::marker::PhantomData;
use std::process::Stdio;
use std::{
    process::{Child, Command},
    thread,
};

use libafl::{
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{
        Executor, ExitKind, HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    state::HasSolutions,
    Error,
};

use crate::{
    outfile::OutFile,
    pipe::Pipe,
};

// use hexdump;
use log::{debug, info, log_enabled, warn, Level};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

// taken from qemuafl/imported/config.h
const FORKSRV_FD: i32 = 198;

pub struct Forkserver {
    qemu: String,
    target: String,
    ld_library_path: String,
    afl_persistent_addr: Option<String>,

    status_pipe: Arc<Pipe>,
    control_pipe: Pipe,

    pid: u32,       // pid of forkserver. this is the father which children will fork from
    child_pid: i32, // pid of fuzzed program (our grand child)
    status: i32,
    is_qemu_alive: bool,

    child_status_sender: Sender<i32>,
    child_status_receiver: Arc<Mutex<Receiver<i32>>>,
}

impl Forkserver {
    pub fn new(qemu: String, ld_library_path: String, target: String) -> Self {
        // NAME | Who | R/W   | ID
        // -------------------------
        // CTL  | AFL | Read  | 198
        // CTL  | Us  | Write | Anon
        // ST   | AFL | Write | 199
        // ST   | Us  | Read  | Anon
        let mut control_pipe = Pipe::new("control_pipe".to_owned());
        let mut status_pipe = Pipe::new("status_pipe".to_owned());

        // pass down to afl CTL:read and ST:write
        control_pipe.dup_read(FORKSRV_FD);
        status_pipe.dup_write(FORKSRV_FD + 1);

        // multiplex child exit events and forkserver status messages to a single incoming pipe
        // this way we can avoid blocking forever if the forkserver crashes
        let (sender, receiver) = channel();

        Self {
            qemu,
            target,
            ld_library_path,
            afl_persistent_addr: None,
            pid: 0,
            child_pid: 0,
            status: 0,
            is_qemu_alive: false,
            status_pipe: Arc::new(status_pipe),
            control_pipe,
            child_status_sender: sender,
            child_status_receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub fn set_persistent_addr(&mut self, addr: String) {
        self.afl_persistent_addr = Some(addr);
    }

    pub fn start(&mut self, args: Vec<String>) {
        if self.is_qemu_alive {
            panic!("Cannot start a new qemu server while one is still running");
        }

        // input pipe --> sender channel
        Forkserver::async_collect_status_pipe(self.child_status_sender.clone(), self.status_pipe.clone());
        self.restart(args);
    }

    pub fn restart(&mut self, args: Vec<String>) {
        let child = self.run_qemu(args);
        let pid = child.id();

        // signal --> sender channel
        Forkserver::update_on_child_exit(child, self.child_status_sender.clone());

        self.pid = pid;
        self.is_qemu_alive = true;
        self.status = 0;
    }

    pub fn run_qemu(&self, args: Vec<String>) -> Child {
        debug!("[+] run qemu forkserver. target={} args={:?}", self.target, args);
        let mut cmd = Command::new(self.qemu.clone());
        cmd.arg(self.target.clone());
        cmd.args(args);
        cmd.env("QEMU_SET_ENV", &format!("LD_LIBRARY_PATH={}", self.ld_library_path));

        if log_enabled!(Level::Debug){
            cmd.env("AFL_DEBUG", "1");
            cmd.env("AFL_QEMU_DEBUG_MAPS", "1");
        } else {
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
        }

        if let Some(persistent_addr) = &self.afl_persistent_addr {
            cmd.env("AFL_QEMU_PERSISTENT_GPR", "1");
            cmd.env("AFL_QEMU_PERSISTENT_ADDR", persistent_addr); // 0x5500000000 + $(nm --dynamic | grep main)
        }

        cmd.env("AFL_INST_LIBS", "1"); // TODO make configurable

        let mut child = cmd.spawn().expect("Failed to run QEMU"); // start AFL ForkServer in QEMU mode in different process
        if let Ok(Some(exit_status)) = child.try_wait() {
            warn!("child is dead :/ exit_status={}", exit_status);
        }

        return child;
    }

    pub fn do_handshake(&self) {
        self.try_read_status();
        info!("[+] forkserver is alive!");
    }

    /// wait for a `process::Child` to exit and send it's status code on a `Sender` channel
    /// sends the status code negated on the channel
    /// this function does not block
    fn update_on_child_exit(mut child: Child, sender: Sender<i32>) {
        thread::spawn(move || {
            debug!("[!] update_on_child_exit: new thread");

            let status = child
                .wait()
                .expect("Error while waiting for QEMU to finish");

            debug!("Child is done. status={}", status);

            let code = status.code().unwrap();
            assert!(code >= 0);
            sender.send(-code).unwrap();

            debug!("[*] update_on_child_exit is done");
        });
    }

    /// collect all messages from an input Pipe and channel them to a `Sender` channel
    pub fn async_collect_status_pipe(output: Sender<i32>, input: Arc<Pipe>) {
        thread::spawn(move || {
            let mut first = true;
            loop {
                let v = input.read_i32();
                if first {
                    // this can be seen using AFL_DEBUG=1 and observing the value logged by 
                    // Debug: Sending status c00007ff
                    debug!("Received start status {}", v); 
                    output.send(0).unwrap();
                    first = false;
                    continue;
                }

                output.send(v).unwrap();
                debug!("drink_status_pipe loop. read_i32() = {}", v);
            }
        });
    }

    /// try read forkserver status from status channel
    /// if forkserver died returns None
    pub fn try_read_status(&self) -> Option<i32> {
        let status = self
            .child_status_receiver
            .lock()
            .expect("Error taking lock for status receiver")
            .recv()
            .expect("Error reading from status receiver");

        if status >= 0 {
            return Some(status);
        }

        info!("Got error from status pipe. error: {}", -status);
        return None;
    }
}

pub struct ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    target: String,
    args: Vec<String>,
    // use_stdin: bool,
    out_file: OutFile,
    forkserver: Forkserver,
    observers: OT,
    phantom: PhantomData<(EM, I, S)>,
}

fn parse_argv(v: &Vec<String>, out_filename: &str) -> Vec<String> {
    let mut final_args = Vec::new();
    for item in v {
        if item == "@@" {
            final_args.push(out_filename.to_string());
            continue;
        }
        final_args.push(item.to_string());
    }

    final_args
}

impl<EM, I, OT, S> ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new<OC, OF, Z>(
        qemu: &str,
        ld_library_path: &str,
        afl_persistent_addr: Option<String>,
        bin: &str,
        argv: Vec<String>,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<I, S> + EventRestarter<S>,
        OC: Corpus<I>,
        OF: Feedback<I, S>,
        S: HasSolutions<OC, I>,
        Z: HasObjective<I, OF, S>,
    {
        let target = bin.to_string();
        let out_filename = format!("out-{}", 123456789); //TODO: replace it with a random number
        let out_file = OutFile::new(&out_filename, 2048);
        let args = parse_argv(&argv, &out_filename);

        let mut forkserver = Forkserver::new(
            qemu.to_string(),
            ld_library_path.to_string(),
            bin.to_string());

        if let Some(persistent_addr) = afl_persistent_addr {
            forkserver.set_persistent_addr(persistent_addr);
        }

        forkserver.start(args.clone());
        forkserver.do_handshake();

        return Ok(Self {
            target,
            args,
            out_file,
            forkserver,
            observers,
            phantom: PhantomData,
        });
    }

    pub fn target(&self) -> &String {
        &self.target
    }

    pub fn args(&self) -> &Vec<String> {
        &self.args
    }

    pub fn forkserver(&self) -> &Forkserver {
        &self.forkserver
    }

    fn mut_forkserver(&mut self) -> &mut Forkserver {
        &mut self.forkserver
    }
}

impl<EM, I, OT, S, Z> Executor<EM, I, S, Z> for ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {

       // write new testcase to input file
       self.out_file
           .write_buf(&input.target_bytes().as_slice().to_vec());

        let forkserver = self.mut_forkserver();

        forkserver.control_pipe.write_i32(0);
        debug!("[+] sent alive signal to child");

        if let Some(child_pid) = forkserver.try_read_status() {
            debug!("[+] child pid {}", child_pid);
            forkserver.child_pid = child_pid;
        } else {
            panic!("forkserver is misbehaving");
        }

        if let Some(child_status) = forkserver.try_read_status() {
            debug!("[+] child status {}", child_status);
            if child_status != 4991 {
                info!("target crashed but QEMU is still alive. exit_code={}", child_status);
                return Ok(ExitKind::Crash);
            }
        } else {
            forkserver.is_qemu_alive = false;
            info!("[!] target crashed");
            return Ok(ExitKind::Crash);
        }

        // rewind to start before new testcase
        self.out_file.rewind();
        Ok(ExitKind::Ok)
    }
}

impl<EM, I, OT, S> HasObservers<OT> for ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn observers(&self) -> &OT {
        &self.observers
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<EM, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z> for ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}
