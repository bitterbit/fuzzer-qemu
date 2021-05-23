#[cfg(target_family = "unix")]
use std::os::unix::process::ExitStatusExt;

use std::process::Command;
use std::process::Stdio;

use libafl::executors::ExitKind;

// use hexdump;
use log::{debug, log_enabled, Level};

pub struct SimpleQEMU {
    target: String,
    args: Vec<String>,
}

impl SimpleQEMU {
    pub fn new(target: String, args: Vec<String>) -> Self {
        Self { target, args }
    }

    pub fn sync_run(&self, ignore_out: bool) -> ExitKind {
        let ld_library_path = "/fuzz/bin/arm64-v8a";
        let qemuafl = "/AFLplusplus/qemu_mode/qemuafl/build/aarch64-linux-user/qemu-aarch64";

        let mut stdout = Stdio::null();
        let mut stderr = Stdio::null();

        if !ignore_out { 
            stdout = Stdio::inherit();
            stderr = Stdio::inherit();
        }

        let mut cmd = Command::new(qemuafl);

        cmd
            .arg(self.target.to_string())
            .args(self.args.clone())
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .env("QEMU_SET_ENV",&format!("LD_LIBRARY_PATH={}", ld_library_path))
            .env("AFL_INST_LIBS", "1");

        if log_enabled!(Level::Debug) {
            // cmd.env("AFL_QEMU_DEBUG_MAPS", "1");
            cmd.env("AFL_DEBUG", "1");
        }

        let output = cmd.output()
            .expect("Failed to run QEMU"); // start AFL ForkServer in QEMU mode in different process


        if output.status.success() {
            return ExitKind::Ok;
        }

        #[cfg(target_family="unix")]
        if let Some(signal) = output.status.signal() {
            debug!("QEMU signal exit {}", signal);
            return ExitKind::Crash;
        }

        ExitKind::Ok
    }
}
