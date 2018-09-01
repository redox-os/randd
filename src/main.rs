#![feature(asm)]
#![feature(rand)]

extern crate syscall;
extern crate raw_cpuid;
extern crate rand;

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

use rand::chacha::ChaChaRng;
use rand::Rng;

use raw_cpuid::CpuId;

use syscall::{Error, Result, SchemeMut, EINVAL, MODE_CHR};
use syscall::data::{Packet, Stat};

//TODO: Use a CSPRNG, allow write of entropy
struct RandScheme {
    socket: File,
    prng: ChaChaRng
}

impl SchemeMut for RandScheme {
    fn open(&mut self, _path: &[u8], _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        Ok(0)
    }

    fn dup(&mut self, file: usize, buf: &[u8]) -> Result<usize> {
        if ! buf.is_empty() {
            return Err(Error::new(EINVAL));
        }

        Ok(file)
    }

    fn read(&mut self, _file: usize, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        for chunk in buf.chunks_mut(8) {
            let mut rand = self.prng.next_u64();
            for b in chunk.iter_mut() {
                *b = rand as u8;
                rand = rand >> 8;
                i += 1;
            }
        }
        Ok(i)
    }

    fn fpath(&mut self, _file: usize, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let scheme_path = b"rand";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(i)
    }

    fn fstat(&mut self, _id: usize, stat: &mut Stat) -> Result<usize> {
        *stat = Stat {
            st_mode: MODE_CHR | 0o666,
            ..Default::default()
        };

        Ok(0)
    }

    fn fevent(&mut self, id: usize, _flags: usize) -> Result<usize> {
        syscall::write(self.socket.as_raw_fd(), &syscall::Packet {
            a: syscall::SYS_FEVENT,
            b: id,
            c: syscall::EVENT_READ,
            d: 1,
            ..Default::default()
        })?;
        Ok(0)
    }

    fn fcntl(&mut self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&mut self, _file: usize) -> Result<usize> {
        Ok(0)
    }
}

fn main(){
    let has_rdrand = CpuId::new().get_feature_info().unwrap().has_rdrand();

    // Daemonize
    if unsafe { syscall::clone(0).unwrap() } == 0 {
        let socket = File::create(":rand").expect("rand: failed to create rand scheme");

        let mut rng = ChaChaRng::new_unseeded();

        if has_rdrand {
            println!("rand: seeding with rdrand");
            let rand: u64;
            unsafe {
                asm!("rdrand rax"
                    : "={rax}"(rand)
                    :
                    :
                    : "intel", "volatile");
            }
            rng.set_counter(0, rand);
        } else {
            println!("rand: unseeded");
        }

        let mut scheme = RandScheme{socket, prng: rng};

        syscall::setrens(0, 0).expect("randd: failed to enter null namespace");

        loop {
            let mut packet = Packet::default();
            scheme.socket.read(&mut packet).expect("rand: failed to read events from rand scheme");
            scheme.handle(&mut packet);
            scheme.socket.write(&packet).expect("rand: failed to write responses to rand scheme");
        }
    }
}
