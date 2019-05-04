

use libc::{
    MAP_ANON,
    MAP_FILE,
    MAP_FIXED,
    MAP_SHARED,
    MAP_FAILED,
    O_CREAT,
    O_EXCL,
    O_RDWR,
    PROT_NONE,
    PROT_READ,
    PROT_WRITE,
    _SC_PAGESIZE,
    c_int,
    c_void,
    close,
    ftruncate,
    mmap,
    munmap,
    shm_open,
    shm_unlink,
    sysconf,
};
use rand::{thread_rng};
use rand::seq::SliceRandom;

use std::ffi::CString;
use std::ptr;
use std::slice;

pub use std::io::Error;

fn random_string() -> String {
    const CHARSET: &[u8] =  b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = thread_rng();
    (0..8).map(|_| *CHARSET.choose(&mut rng).expect("CHARSET should have len > 0") as char).collect::<String>()
}

#[derive(Debug)]
struct Fd {
    raw: c_int
}

impl From<c_int> for Fd {
    fn from(f: c_int) -> Fd {
        Fd{
            raw: f,

        }
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        // Best-effort. Mac OS X deterministically errors on this (despite succeeding).
        unsafe{ libc::close(self.raw) };
    }
}

fn shm_create() -> Result<Fd, Error> {
    let filename = format!("/ring-{}", random_string());
    let name = CString::new(filename).expect("filename has no NULLS");
    let fd = unsafe { shm_open(name.as_ptr(), O_CREAT|O_EXCL|O_RDWR, 0o600 ) };
    if fd < 0 {
        Err(Error::last_os_error())
    } else {
        let res = unsafe { shm_unlink(name.as_ptr()) };
        if res < 0 {
            unsafe { close(fd) };
            Err(Error::last_os_error())
        } else {
            Ok(fd.into())
        }
    }
}

#[derive(Debug)]
pub struct RingBuffer {
    shm: Fd,
    mmapped_region: *mut c_void,
    size_bytes: usize,
}

impl RingBuffer {
    pub fn new(min_size: usize) -> Result<RingBuffer, Error> {
        let shm = shm_create()?;
        let page_size = unsafe{ sysconf(_SC_PAGESIZE) };
        if page_size < 0 {
            return Err(Error::last_os_error());
        }
        let page_size = page_size as usize;
        let size_bytes = (((min_size - 1) / page_size) + 1) * page_size;

        // Grow the shm space:
        let ft = unsafe {
            ftruncate(shm.raw, size_bytes as i64)
        };
        if ft < 0 {
            return Err(Error::last_os_error());
        }

        // Allocate the region
        let mmapped_region = unsafe {
            let addr = ptr::null_mut();
            let size = size_bytes * 2;
            let prot = PROT_NONE;
            let map = MAP_ANON | MAP_SHARED;
            let fd = -1;
            mmap(addr, size, prot, map, fd, 0)
        };
        if mmapped_region == MAP_FAILED {
            return Err(Error::last_os_error());
        }

        // mmap the back half:
        let back = unsafe {
           mmap(mmapped_region.offset(size_bytes as isize), size_bytes, PROT_READ|PROT_WRITE, MAP_FILE|MAP_FIXED|MAP_SHARED, shm.raw, 0)
        };
        if back == MAP_FAILED {
            let res = Err(Error::last_os_error());
            unsafe{ munmap(mmapped_region, size_bytes*2) };
            return res;
        }

        // mmap the front half:
        let front = unsafe {
           mmap(mmapped_region, size_bytes, PROT_READ|PROT_WRITE, MAP_FILE|MAP_FIXED|MAP_SHARED, shm.raw, 0)
        };
        if front == MAP_FAILED {
            let res = Err(Error::last_os_error());
            unsafe{ munmap(back, size_bytes) };
            unsafe{ munmap(mmapped_region, size_bytes*2) };
            return res;
        }

        Ok(RingBuffer{
            shm,
            mmapped_region,
            size_bytes
        })
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        // Best-effort clean up the mappings:
        unsafe {
            let r = munmap(self.mmapped_region, self.size_bytes);
            assert!(r >= 0, "Error munmapping RW {}", Error::last_os_error());
            let r = munmap(self.mmapped_region.offset(self.size_bytes as isize), self.size_bytes);
            assert!(r >= 0, "Error munmapping RO {}", Error::last_os_error());
            let r = munmap(self.mmapped_region, self.size_bytes*2);
            assert!(r >= 0, "Error munmapping Region {}", Error::last_os_error());
        }
    }
}

impl RingBuffer {
    pub fn get_ro(&self, start: usize, end: usize) -> &[u8] {
        let s = unsafe{ slice::from_raw_parts(self.mmapped_region as *const u8, self.size_bytes*2) };
        assert!(end - start <= self.size_bytes, "Can only view 1 copy of data.");
        &s[start..end]
    }

    pub fn get_rw(&mut self, start: usize, end: usize) -> &mut [u8] {
        let s = unsafe{
            slice::from_raw_parts_mut(self.mmapped_region as *mut u8, self.size_bytes*2)
        };
        assert!(end - start <= self.size_bytes, "Can only write 1 copy of data.");
        &mut s[start..end]
    }

    pub fn len(&self) -> usize {
        self.size_bytes
    }
}

#[cfg(test)]
mod test {
    //use super::{shm_create, RingBuffer, _SC_PAGESIZE, sysconf};
    use super::{shm_create};

    //fn page_size() -> usize {
    //    let page_size = unsafe{ sysconf(_SC_PAGESIZE) };
    //    assert!(page_size > 0, "Failure to get page size.");
    //    page_size as usize
    //}

    #[test]
    fn shm_create_test() {
        // Ensure creating doesn't panic somehow:
        let _res = shm_create().unwrap();
    }

    #[test]
    fn ring_buffer_simple() {
        /*
        for (req_size, size) in vec![
            (1, page_size()),
            (page_size(), page_size()),
            (page_size() * 2 + 1, 3*page_size())
        ] {
            let mut ring = RingBuffer::new(req_size).unwrap();
            assert_eq!(ring.len(), size);
            assert_eq!(ring.get_ro(0, size).len(), size);
            assert_eq!(ring.get_rw(0, size).len(), size);
            assert_eq!(ring.get_ro(size, size*2).len(), size);
            assert_eq!(ring.get_rw(size, size*2).len(), size);
            for i in 0..size {
                ring.get_rw(0, size)[i] = i as u8;
            }
            for i in 0..size {
                assert_eq!(ring.get_ro(size, size*2)[i], i as u8);
            }
        }
        */
    }
}
