use core::marker::PhantomData; 
use std::process::Command;
use std::process::Stdio;

// use libafl::bolts::shmem::{ShMemProvider, StdShMemProvider, ShMem};
use libafl::bolts::tuples::Named;
use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
}; 

use crate::qemu::{
    pipe::Pipe,
    outfile::OutFile,
};

use log::{debug, info, log_enabled, Level};
use hexdump;


// taken from qemuafl/imported/config.h
const FORKSRV_FD: i32 = 198;
// const MAP_SIZE: usize = 1 << 16;
const AFL_QEMU_PERSISTENT_ADDR: &str = "0x550000b848";

pub struct Forkserver {
    status_pipe: Pipe,
    control_pipe: Pipe,
    pid: u32, // pid of forkserver. this is the father which children will fork from
    child_pid: i32, // pid of fuzzed program (our grand child)
    status: i32,
}

impl Forkserver {
    pub fn new(target: String, args: Vec<String>) -> Self {
        // NAME | Who | R/W   | ID
        // -------------------------
        // CTL  | AFL | Read  | 198 
        // CTL  | Us  | Write | Anon
        // ST   | AFL | Write | 199
        // ST   | Us  | Read  | Anon
        let control_pipe = Pipe::new("control_pipe".to_owned());
        let status_pipe = Pipe::new("status_pipe".to_owned());
        
        // pass down to afl CTL:read and ST:write
        control_pipe.dup_read(FORKSRV_FD);
        status_pipe.dup_write(FORKSRV_FD + 1);

        let ld_library_path = "/fuzz/bin/arm64-v8a";
        let qemuafl = "/AFLplusplus/qemu_mode/qemuafl/build/aarch64-linux-user/qemu-aarch64";


        let mut stdout = Stdio::null();
        let mut stderr= Stdio::null();
        if log_enabled!(Level::Debug) {
            stdout = Stdio::inherit();
            stderr = Stdio::inherit();
        }

        let child = Command::new(qemuafl)
            .arg(target)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .env("QEMU_SET_ENV", &format!("LD_LIBRARY_PATH={}", ld_library_path))
            // .env("AFL_DEBUG", "1")
            .env("AFL_QEMU_PERSISTENT_GPR", "1") // TODO make this configurable by api
            .env("AFL_QEMU_PERSISTENT_ADDR", AFL_QEMU_PERSISTENT_ADDR) // 0x5500000000 + $(nm --dynamic | grep main)
            // .env("AFL_QEMU_PERSISTENT_CNT", "100")
            .spawn().expect("Failed to run QEMU"); // start AFL ForkServer in QEMU mode in different process
        
        Self {
            control_pipe,
            status_pipe,
            pid: child.id(),
            child_pid: 0,
            status: 0,
        }
    }

    pub fn pid(&self) -> u32{
        self.pid
    }

    pub fn status(&self) -> i32{
        self.status
    }

    pub fn start(&self) {
        // initial handshake
        self.status_pipe.read_i32();
        info!("[+] forkserver is alive!");
    }
}

pub struct ForkserverExecutor<I, OT>
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
    phantom: PhantomData<I>,
}

impl<I, OT> ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(bin: &'static str, argv: Vec<&'static str>, observers: OT) -> Result<Self, Error> {
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

        let forkserver = Forkserver::new(target.clone(), args.clone()); // Forkserver::new(target.clone(), args.clone(), out_file.as_raw_fd(), use_stdin, 0);
        forkserver.start();
        
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

    pub fn args(&self) -> &Vec<String>{
        &self.args
    }

    pub fn forkserver(&self) -> &Forkserver{
        &self.forkserver
    }
}

impl<I, OT> Named for ForkserverExecutor<I, OT> 
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        return "fork server executor!";
    }
}

impl<I, OT> Executor<I> for ForkserverExecutor <I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn run_target(&mut self, _input: &I) -> Result<ExitKind, Error> {
        let forkserver = &mut self.forkserver;

        forkserver.control_pipe.write_i32(0);
        debug!("[+] sent alive signal to child");

        forkserver.child_pid = forkserver.status_pipe.read_i32();
        debug!("[+] child pid {}", forkserver.child_pid);

        if forkserver.child_pid < 0 {
            panic!("forkserver is misbehaving");
        }

        forkserver.status = forkserver.status_pipe.read_i32();
        debug!("[+] status={}", forkserver.status);

        Ok(ExitKind::Ok)
    }

    #[inline]
    fn pre_exec<EM, S>(&mut self,_state: &mut S,_event_mgr: &mut EM, input: &I)-> Result<(), Error> {
        debug!("[-] pre exec");
        self.out_file.write_buf(&input.target_bytes().as_slice().to_vec());

        if log_enabled!(Level::Debug) {
            // hexdump::hexdump(&input.target_bytes().as_slice());
            // hexdump::hexdump(std::fs::read("./out-123456789").unwrap().as_slice());
        }

        Ok(())
    }

    fn post_exec<EM, S>(&mut self, _state: &mut S, _event_mgr: &mut EM, _input: &I) -> Result<(), Error>{
       if !libc::WIFSTOPPED(self.forkserver.status()) {
            self.forkserver.child_pid = 0;
        }

        //move the head back
        self.out_file.rewind();

        if libc::WIFSIGNALED(self.forkserver.status()) {
            info!("CRASH");
        }

        debug!("[-] post exec");
        Ok(())
    }
}

impl<I, OT> HasObservers<OT> for ForkserverExecutor<I, OT>
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
