use core::marker::PhantomData;
use std::process::{ExitStatus, Stdio};
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

pub struct SimpleQEMU {
    target: String,
    args: Vec<String>,
}

impl SimpleQEMU {
    pub fn new(target: String, args: Vec<String>) -> Self {
        Self {
            target, 
            args,
        }
    }

    pub fn sync_run(&self) -> ExitKind {
        let ld_library_path = "/fuzz/bin/arm64-v8a";
        let qemuafl = "/AFLplusplus/qemu_mode/qemuafl/build/aarch64-linux-user/qemu-aarch64";

        let mut stdout = Stdio::null();
        let mut stderr = Stdio::null();
        if log_enabled!(Level::Debug) {
            stdout = Stdio::inherit();
            stderr = Stdio::inherit();
        }

        let output = Command::new(qemuafl)
            .arg(self.target.to_string())
            .args(self.args.clone())
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .env(
                "QEMU_SET_ENV",
                &format!("LD_LIBRARY_PATH={}", ld_library_path),
            )
            // .env("AFL_DEBUG", "1")
            // .env("AFL_INST_LIBS", "1")
            .output()
            .expect("Failed to run QEMU"); // start AFL ForkServer in QEMU mode in different process

        if output.status.success() {
            return ExitKind::Ok;
        }

        ExitKind::Crash
    }
}
