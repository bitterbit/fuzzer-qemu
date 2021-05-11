use libc;
use std::{io::Write, os::raw::c_int};

use std::{
    fs::File,
    io::{self, Read},
    os::unix::io::FromRawFd,
};

#[derive(Debug, Clone)]
pub struct Pipe {
    read_end: c_int,
    write_end: c_int,
    name: String,
}

impl Pipe {
    pub fn new(name: String) -> Self {
        let mut fds = [-1 as c_int, -1 as c_int];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret < 0 {
            panic!("pipe() failed");
        }
        Self {
            read_end: fds[0],
            write_end: fds[1],
            name,
        }
    }

    pub fn write_i32(&self, value: i32) -> isize {
        println!("[+] write to [{} fd={}]", self.name, self.write_end);
        let v: i32 = value; // store a copy
        let rlen = unsafe {
            libc::write(
                self.write_end,
                (&v) as *const libc::c_int as *mut libc::c_void,
                4
            )
        };

        println!("[+] done write");

        return rlen;
    }

    pub fn read_i32(&self) -> i32 {
        let mut value: i32 = 0;
        let rlen;
        unsafe {
            rlen = libc::read(
                self.read_end,
                (&mut value) as *mut libc::c_int as *mut libc::c_void,
                4
            );
        }

        assert_eq!(rlen, 4);
        return value;
    }

    pub fn read(&self, buf: &mut[u8]) {
        println!("read from fd={}", self.read_end);
        unsafe {
            let mut f: File = File::from_raw_fd(self.read_end);
            f.read_exact(buf).expect("Could not read from pipe");
        }
    }

    pub fn dup_read(&self, dst_fd: i32) {
        let ret = unsafe {
            libc::dup2(self.read_end, dst_fd)
        };

        if ret < 0 {
            panic!("dup2() failed");
        }
    }

    pub fn dup_write(&self, dst_fd: i32) {
        let ret = unsafe {
            libc::dup2(self.write_end, dst_fd)
        };

        if ret < 0 {
            panic!("dup2() failed");
        }

    }

    pub fn close_read(&mut self) {
        println!("closing read_end={}", self.read_end);
        unsafe {
            libc::close(self.read_end);
        }

        self.read_end = -1;
    }

    pub fn close_write(&mut self) {
        println!("closing write_end={}", self.read_end);
        unsafe {
            libc::close(self.read_end);
        }

        self.write_end = -1;
    }
}

impl Drop for Pipe{
    fn drop(&mut self){
        println!("[*] dropping {}", self.name);
        unsafe {
            libc::close(self.read_end);
            libc::close(self.write_end);
            libc::close(self.read_end);
            libc::close(self.write_end);
        }
    }
}
