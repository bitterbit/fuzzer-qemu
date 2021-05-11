use libc;
use std::{convert::TryInto, process};
use std::process::Command;
use std::process::Stdio;
// use std::io::{self, Write};
use pretty_hex::*;

mod pipe;
use pipe::Pipe;


// taken from qemuafl/imported/config.h
const FORKSRV_FD: i32 = 198;
const MAP_SIZE: usize = 1 << 16;

fn create_shmem() -> i32 {
    unsafe {
        // DEFAULT_PERMISSION 0600
        let fd = libc::shmget(libc::IPC_PRIVATE, MAP_SIZE, libc::IPC_CREAT | libc::IPC_EXCL | 0o0600);
        if libc::ftruncate(fd, MAP_SIZE.try_into().unwrap()) == 0 {
            panic!("Could not truncate shared memory");
        }
        return fd;
    }

}

fn close_shmem(shm_id: i32) {
    unsafe {
        let _ret = libc::shmctl(shm_id, libc::IPC_RMID, std::ptr::null_mut());
    }
}

fn get_shmem(shm_id: i32) -> *mut u8 {
    let afl_area_ptr = unsafe {
        libc::shmat(shm_id, std::ptr::null(), 0)
    };

    return afl_area_ptr as *mut u8;
}

fn dump_afl_area(shm_id: i32) {
    let afl_area_ptr = get_shmem(shm_id);
    dbg!(afl_area_ptr);

    let mut cov: Vec<u8> = Vec::new();
    for i in 0..0xffff {
        unsafe {
            cov.push(*(afl_area_ptr.add(i)));
        }
    }

    let cov_slice = cov.as_slice();
    let hex = cov_slice.hex_dump();
    println!("{:?}", hex);
}


fn main() {
    let shm_id = create_shmem();
    dbg!(shm_id);

    let ld_library_path = "/fuzz/bin/arm64-v8a";
    // env::set_var("AFL_QEMU_DEBUG_MAPS", "1");
    // env::set_var("AFL_QEMU_PERSISTENT_ADDR", "0xb96c"); // address of main, extracted using nm
    // env::set_var("AFL_QEMU_PERSISTENT_HOOK", "/fuzz/bin/libpersistent.so");

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

    // let qemuafl = "/AFLplusplus/afl-qemu-trace";
    let qemuafl = "/AFLplusplus/qemu_mode/qemuafl/build/aarch64-linux-user/qemu-aarch64";

    let mut child = Command::new(qemuafl)
        .arg("/fuzz/bin/harness")
        .arg("/fuzz/samples/sample")
        // .arg("--backtrace")
        .env("QEMU_SET_ENV", format!("LD_LIBRARY_PATH={}", ld_library_path))
        .env("AFL_DEBUG", "1")
        .env("AFL_QEMU_PERSISTENT_GPR", "1")
        .env("AFL_QEMU_PERSISTENT_ADDR", "0x550000b744") // 0x5500000000 + $(nm --dynamic | grep main)
        // .env("AFL_QEMU_PERSISTENT_CNT", "100")
        .env("__AFL_SHM_ID", format!("{}", shm_id))
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn().expect("Failed to run QEMU"); // start AFL ForkServer in QEMU mode in different process

    // control_pipe.close_read();
    // status_pipe.close_write();

    let mut status = status_pipe.read_i32();
    println!("[+] forkserver is alive! status={}", status);



    loop {
        println!("[+] sending alive signal to child");
        control_pipe.write_i32(0);

        let child_pid = status_pipe.read_i32();
        println!("[+] child pid {}", child_pid);

        if child_pid < 0 {
            break;
        }

        status = status_pipe.read_i32();
        println!("[+] status={}", status);
    }


    let exit_status = child.wait().unwrap();
    dbg!(exit_status);
    // io::stdout().write_all(&output.stdout).unwrap();
    // io::stderr().write_all(&output.stderr).unwrap();  

    // dump_afl_area(shm_id);

    println!("closing shm_id {}", shm_id);
    close_shmem(shm_id);

    unsafe {
        libc::close(FORKSRV_FD);
        libc::close(FORKSRV_FD + 1);
    }
}

