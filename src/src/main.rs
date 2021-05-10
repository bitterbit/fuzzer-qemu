use libc;
use std::{convert::TryInto, process};
use std::process::Command;
use std::str;
use std::env;
use std::io::{self, Write};
use pretty_hex::*;

// taken from qemuafl/imported/config.h
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


fn main() {
    let shm_id = create_shmem();
    dbg!(shm_id);

    let ld_library_path = "/fuzz/bin/arm64-v8a";
    env::set_var("QEMU_SET_ENV", format!("LD_LIBRARY_PATH={}", ld_library_path));
    env::set_var("AFL_DEBUG", "1");
    // env::set_var("AFL_QEMU_PERSISTENT_ADDR", "0xb96c"); // address of main, extracted using nm
    // env::set_var("AFL_QEMU_PERSISTENT_HOOK", "/fuzz/bin/libpersistent.so");
    env::set_var("__AFL_SHM_ID", format!("{}", shm_id));

    // let qemuafl = "/AFLplusplus/afl-qemu-trace";
    let qemuafl = "/AFLplusplus/qemu_mode/qemuafl/build/aarch64-linux-user/qemu-aarch64";
    let output = Command::new(qemuafl)
        .arg("/fuzz/bin/harness")
        .arg("/fuzz/samples/sample")
        .arg("--backtrace")
        .output().expect("Failed to run QEMU");

    println!("status: {}", output.status);
    io::stdout().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();  


    let afl_area_ptr = get_shmem(shm_id);
    dbg!(afl_area_ptr);

    let mut cov: Vec<u8> = Vec::new();
    for i in 0..0xffff {
        unsafe {
            cov.push(*(afl_area_ptr.add(i)));
        }
    }

    // let cov = unsafe { shmem.as_slice() };
    let cov_slice = cov.as_slice();
    let hex = cov_slice.hex_dump();
    println!("{:?}", hex);

    println!("closing shm_id {}", shm_id);
    close_shmem(shm_id);
}
