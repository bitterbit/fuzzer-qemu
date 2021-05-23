use std::process::Command;
use std::process::Stdio;

use libafl::executors::ExitKind;

// use hexdump;
use log::{log_enabled, Level};

pub struct SimpleQEMU {
    target: String,
    args: Vec<String>,
}

impl SimpleQEMU {
    pub fn new(target: String, args: Vec<String>) -> Self {
        Self { target, args }
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
