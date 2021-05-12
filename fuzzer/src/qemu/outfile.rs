use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom},
    os::unix::io::{AsRawFd, RawFd},
};

pub struct OutFile {
    file: File,
}

impl OutFile {
    pub fn new(file_name: &str) -> Self {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_name)
            .expect("Failed to open the input file");
        Self { file: f }
    }
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn write_buf(&mut self, buf: &Vec<u8>) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
        self.file.write(buf).unwrap();
        self.file.set_len(buf.len() as u64).unwrap();
        self.file.flush().unwrap();
    }

    pub fn rewind(&mut self) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
    }
}
