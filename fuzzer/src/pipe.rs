use libc;
use std::os::raw::c_int;
use log::debug;

#[derive(Debug, Clone)]
pub struct Pipe {
    read_end: c_int,
    write_end: c_int,
    name: String,
    dups: Vec<c_int>,
}

impl Pipe {
    pub fn new(name: String) -> Self {
        let mut fds = [-1 as c_int, -1 as c_int];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret < 0 {
            panic!("pipe() failed");
        }

        debug!("[*] new pipe {} ({},{})", name, fds[0], fds[1]);
        Self {
            read_end: fds[0],
            write_end: fds[1],
            name,
            dups: Vec::new(),
        }
    }

    pub fn write_i32(&self, value: i32) -> isize {
        // debug!("[+] {} write_i32({});", self.name, value);
        let v: i32 = value; // store a copy
        let rlen = unsafe {
            libc::write(
                self.write_end,
                (&v) as *const libc::c_int as *mut libc::c_void,
                4
            )
        };

        return rlen;
    }

    pub fn read_i32(&self) -> i32 {
        // debug!("[+] {} read_i32()...", self.name); 
        let mut value: i32 = 0;
        let rlen;
        unsafe {
            rlen = libc::read(
                self.read_end,
                (&mut value) as *mut libc::c_int as *mut libc::c_void,
                4
            );
        }

        // debug!("[+] {} read_i32() = {};", self.name, value);

        assert_eq!(rlen, 4);
        return value;
    }

    pub fn dup_read(&mut self, dst_fd: i32) {
        let ret = unsafe {
            libc::dup2(self.read_end, dst_fd)
        };

        if ret < 0 {
            panic!("dup2() failed");
        }

        self.dups.push(dst_fd);
    }

    pub fn dup_write(&mut self, dst_fd: i32) {
        let ret = unsafe {
            libc::dup2(self.write_end, dst_fd)
        };

        if ret < 0 {
            panic!("dup2() failed");
        }

        self.dups.push(dst_fd);
    }

    #[allow(dead_code)]
    pub fn close_read(&mut self) {
        debug!("closing read_end={}", self.read_end);
        unsafe {
            libc::close(self.read_end);
        }

        self.read_end = -1;
    }

    #[allow(dead_code)]
    pub fn close_write(&mut self) {
        debug!("closing write_end={}", self.read_end);
        unsafe {
            libc::close(self.read_end);
        }

        self.write_end = -1;
    }

}

impl Drop for Pipe{
    fn drop(&mut self){
        debug!("[*] dropping {}", self.name);
        unsafe {
            libc::close(self.read_end);
            libc::close(self.write_end);
            libc::close(self.read_end);
            libc::close(self.write_end);

            for fd in self.dups.iter() {
                libc::close(*fd);
            }
        }
    }
}
