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
        Executor, ExitKind, HasExecHooks, HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    state::HasSolutions,
    Error,
};

use crate::qemu::{outfile::OutFile, pipe::Pipe};

// use hexdump;
use log::{debug, info, log_enabled, warn, Level};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

// taken from qemuafl/imported/config.h
const FORKSRV_FD: i32 = 198;
// const MAP_SIZE: usize = 1 << 16;
const AFL_QEMU_PERSISTENT_ADDR: &str = "0x550000b848";

pub struct Forkserver {
    // don't use this member directly
    // status_pipe: Arc<Pipe>,
    control_pipe: Pipe,

    pid: u32,       // pid of forkserver. this is the father which children will fork from
    child_pid: i32, // pid of fuzzed program (our grand child)
    status: i32,
    is_child_alive: bool,

    child_status_sender: Sender<i32>,
    child_status_receiver: Arc<Mutex<Receiver<i32>>>,
}

impl Forkserver {
    pub fn new(target: String, args: Vec<String>) -> Self {
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
        // let status_pipe = Arc::new(_status_pipe);

        let child = Self::run_qemu(target, args);
        let pid = child.id();

        let (sender, receiver) = channel();
        // multiplex child exit events and forkserver status messages to a single incoming pipe
        // this way we can avoid blocking forever if the forkserver crashes
        Forkserver::async_collect_status_pipe(sender.clone(), status_pipe);
        Forkserver::update_on_child_exit(child, sender.clone());

        Self {
            control_pipe,
            // status_pipe,
            pid,
            child_pid: 0,
            status: 0,
            is_child_alive: true,
            child_status_sender: sender,
            child_status_receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub fn run_qemu(target: String, args: Vec<String>) -> Child {
        let ld_library_path = "/fuzz/bin/arm64-v8a";
        let qemuafl = "/AFLplusplus/qemu_mode/qemuafl/build/aarch64-linux-user/qemu-aarch64";

        let mut stdout = Stdio::null();
        let mut stderr = Stdio::null();
        if log_enabled!(Level::Debug) {
            stdout = Stdio::inherit();
            stderr = Stdio::inherit();
        }

        let mut child = Command::new(qemuafl)
            .arg(target)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .env(
                "QEMU_SET_ENV",
                &format!("LD_LIBRARY_PATH={}", ld_library_path),
            )
            // .env("AFL_DEBUG", "1")
            .env("AFL_QEMU_PERSISTENT_GPR", "1") // TODO make this configurable by api
            .env("AFL_QEMU_PERSISTENT_ADDR", AFL_QEMU_PERSISTENT_ADDR) // 0x5500000000 + $(nm --dynamic | grep main)
            .env("AFL_INST_LIBS", "1")
            // .env("AFL_QEMU_PERSISTENT_CNT", "100")
            .spawn()
            .expect("Failed to run QEMU"); // start AFL ForkServer in QEMU mode in different process

        if let Ok(Some(exit_status)) = child.try_wait() {
            warn!("child is dead :/ exit_status={}", exit_status);
        }

        return child;
    }

    pub fn restart(&mut self, target: String, args: Vec<String>) {
        debug!("[+] restart forkserver. target={} args={:?}", target, args);

        let child = Self::run_qemu(target, args);
        let pid = child.id();

        Forkserver::update_on_child_exit(child, self.child_status_sender.clone());

        self.pid = pid;
        self.is_child_alive = true;
        self.status = 0;
    }

    // pub fn pid(&self) -> u32 {
    //     self.pid
    // }

    // pub fn status(&self) -> i32 {
    //     self.status
    // }

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
    pub fn async_collect_status_pipe(output: Sender<i32>, input: Pipe) {
        thread::spawn(move || loop {
            let v = input.read_i32();
            if v == -1073610753 {
                output.send(0).unwrap();
                debug!("drink_status_pipe loop. read_i32() = FORKSERVER_ACK");
                continue;
            }

            output.send(v).unwrap();
            debug!("drink_status_pipe loop. read_i32() = {}", v);
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

impl<EM, I, OT, S> ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new<OC, OF, Z>(
        bin: &'static str,
        argv: Vec<&'static str>,
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
        let mut args = Vec::<String>::new();

        let out_filename = format!("out-{}", 123456789); //TODO: replace it with a random number
        let out_file = OutFile::new(&out_filename, 2048);

        for item in argv {
            if item == "@@" {
                args.push(out_filename.clone());
                continue;
            }

            args.push(item.to_owned());
        }

        let forkserver = Forkserver::new(target.clone(), args.clone());
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

impl<EM, I, OT, S> Executor<I> for ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn run_target(&mut self, _input: &I) -> Result<ExitKind, Error> {
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
        } else {
            forkserver.is_child_alive = false;
            info!("[!] target crashed");
            return Ok(ExitKind::Crash);
        }

        Ok(ExitKind::Ok)
    }
}

impl<EM, I, OT, S, Z> HasExecHooks<EM, I, S, Z> for ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        debug!("[-] pre exec");

        self.out_file
            .write_buf(&input.target_bytes().as_slice().to_vec());

        Ok(())
    }

    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        //move the head back
        self.out_file.rewind();

        if !self.forkserver().is_child_alive {
            let target = self.target().clone();
            let args = self.args().clone();

            // let mut forkserver = self.mut_forkserver();

            info!("Child has exited. respawning...");
            self.mut_forkserver().restart(target, args);
            self.forkserver().do_handshake();
        }

        debug!("[-] post exec");
        Ok(())
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
