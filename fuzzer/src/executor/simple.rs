#[cfg(target_family = "unix")]
use std::os::unix::process::ExitStatusExt;

use std::process::Command;
use std::process::Stdio;

use libafl::executors::ExitKind;

use log::{debug, log_enabled, Level};

pub struct SimpleQEMU {
    qemu_path: String,
    ld_library_path: Option<String>,
    // target: String,
    // args: Vec<String>,
}

impl SimpleQEMU {
    pub fn new(qemu_path: String, ld_library_path: Option<String>) -> Self {
        Self {
            qemu_path,
            ld_library_path,
        }
    }

    pub fn sync_run(&self, target: &str, args: Vec<String>, ignore_out: bool) -> ExitKind {
        let mut stdout = Stdio::null();
        let mut stderr = Stdio::null();

        if !ignore_out { 
            stdout = Stdio::inherit();
            stderr = Stdio::inherit();
        }

        let mut cmd = Command::new(&self.qemu_path);

        cmd
            .arg(target)
            .args(args.clone())
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .env("AFL_INST_LIBS", "1");

        if let Some(ld_library) = &self.ld_library_path {
            cmd.env("QEMU_SET_ENV",&format!("LD_LIBRARY_PATH={}", ld_library));
        }

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
