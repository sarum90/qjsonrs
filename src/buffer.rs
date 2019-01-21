
use crate::ring;
use crate::ring::{RingBuffer};
use std::io::Read;
use std::str;

pub struct Buffer<R> {
    ring: RingBuffer,
    checked_utf8_start: usize,
    checked_utf8_end: usize,
    written_end: usize,
    inner: R,
}

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    BufferOutOfSpace,
    InvalidUnicode,
    UnexpectedEOF,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl<R: Read> Buffer<R> {
    pub fn new(min_size: usize, inner: R) -> Result<Buffer<R>, ring::Error> {
        let ring = RingBuffer::new(min_size)?;
        Ok(
            Buffer{
                ring,
                checked_utf8_start:0,
                checked_utf8_end:0,
                written_end: 0,
                inner,
            }
        )
    }

    pub fn buffer(&self) -> &str {
        let bs = self.ring.get_ro(self.checked_utf8_start, self.checked_utf8_end);
        unsafe{
            str::from_utf8_unchecked(bs)
        }
    }

    pub fn size(&self) -> usize {
        self.ring.len()
    }

    // n is the number of bytes to consume from the buffer.
    //
    // requires n <= self.buffer().len()
    pub fn consume(&mut self, n: usize) {
        self.checked_utf8_start += n;
        assert!(self.checked_utf8_start <= self.checked_utf8_end);
    }

    pub fn consume_all(&mut self) {
        self.checked_utf8_start = self.checked_utf8_end;
    }

    fn read_more_internal(&mut self) -> Result<usize, Error> {
        let size = self.ring.len();
        let full_buffer = self.ring.get_rw(
            self.checked_utf8_start,
            self.checked_utf8_start + size
        );
        let bytes_read = {
            let write_offset = self.written_end - self.checked_utf8_start;
            let read_dst = &mut full_buffer[write_offset..];
            if read_dst.len() == 0 {
                return Err(Error::BufferOutOfSpace);
            }
            self.inner.read(read_dst)?
        };
        self.written_end += bytes_read;
        // Verify the UTF encoding:
        {
            let new_utf8_start = self.checked_utf8_end - self.checked_utf8_start;
            let new_utf8_end = self.written_end - self.checked_utf8_start;
            let new_utf8 = &full_buffer[new_utf8_start..new_utf8_end];
            match str::from_utf8(new_utf8) {
                Ok(_) => {
                    self.checked_utf8_end = self.written_end;
                },
                Err(e) => {
                    match e.error_len() {
                        None => {
                            self.checked_utf8_end = self.checked_utf8_start + e.valid_up_to();
                        },
                        Some(_) => {
                            return Err(Error::InvalidUnicode);
                        }
                    }
                }
            }
        }
        Ok(bytes_read)
    }

    pub fn read_more(&mut self) -> Result<usize, Error> {
        // Adjust indices:
        let size = self.ring.len();
        if self.checked_utf8_start >= size {
            self.checked_utf8_start -= size;
            self.checked_utf8_end -= size;
            self.written_end -= size;
        }
        let initial = self.checked_utf8_end;
        let mut total_read = 0;
        loop {
            let n = self.read_more_internal()?;
            total_read += n;
            if n == 0 {
                if self.written_end == self.checked_utf8_end {
                    return Ok(0);
                } else {
                    return Err(Error::UnexpectedEOF);
                }
            }
            if self.checked_utf8_end != initial {
                return Ok(total_read);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use libc::{_SC_PAGESIZE, sysconf};
    use os_pipe::pipe;
    use std::io::Write;
    use std::str;
    use super::{Buffer, Error};

    fn page_size() -> usize {
        let page_size = unsafe{ sysconf(_SC_PAGESIZE) };
        assert!(page_size > 0, "Failure to get page size.");
        page_size as usize
    }

    #[test]
    fn test_simple() {
        let first = (0..page_size()).map(|_| '1').collect::<String>();
        let second = (0..page_size()).map(|_| '2').collect::<String>();
        let input = first.clone() + &second;
        let mut buff = Buffer::new(1, input.as_bytes()).unwrap();
        assert_eq!(buff.buffer().len(), 0);
        assert_eq!(buff.ring.len(), page_size());
        assert_eq!(buff.read_more().unwrap(), page_size());
        assert_eq!(buff.buffer().len(), page_size());
        assert_eq!(buff.buffer(), first);
        buff.consume(page_size()-6);
        assert_eq!(buff.buffer(), &first[first.len()-6..]);
        assert_eq!(buff.read_more().unwrap(), page_size()-6);
        assert_eq!(buff.buffer(), &(first[first.len()-6..].to_owned() + &second)[..page_size()]);
        buff.consume(page_size());
        assert_eq!(buff.buffer().len(), 0);
        assert_eq!(buff.read_more().unwrap(), 6);
        assert_eq!(buff.buffer(), &second[second.len()-6..]);
        assert_eq!(buff.read_more().unwrap(), 0);
    }

    #[test]
    fn test_buffer_too_small() {
        let first = (0..page_size()).map(|_| '1').collect::<String>();
        let second = (0..page_size()).map(|_| '2').collect::<String>();
        let input = first.clone() + &second;
        let mut buff = Buffer::new(1, input.as_bytes()).unwrap();
        assert_eq!(buff.read_more().unwrap(), page_size());
        assert!(matches!(buff.read_more(), Err(Error::BufferOutOfSpace)));
    }

    #[test]
    fn test_slowly() {
        let (rd, mut wr) = pipe().unwrap();
        let mut buff = Buffer::new(1, rd).unwrap();
        for i in 0..page_size()*2 {
            const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz!";
            let idx = i % CHARSET.len();
            let c = &CHARSET[idx..idx+1];
            wr.write(c).unwrap();
            assert_eq!(buff.read_more().unwrap(), 1);
            assert_eq!(buff.buffer(), str::from_utf8(c).unwrap());
            buff.consume(1);
        }
        drop(wr);
        assert_eq!(buff.read_more().unwrap(), 0);
    }

    #[test]
    fn error_invalid_utf8() {
        let inv = b"\x80abcdef";
        let mut buff = Buffer::new(1, &inv[..]).unwrap();
        assert!(matches!(buff.read_more(), Err(Error::InvalidUnicode)));
    }

    #[test]
    fn error_unfinished_utf8() {
        let bball = b"\xF0\x9F\x8F\x80";
        let mut buff = Buffer::new(1, &bball[..2]).unwrap();
        assert!(matches!(buff.read_more(), Err(Error::UnexpectedEOF)));
    }

    #[test]
    fn valid_unfinished_utf8() {
        let bball = str::from_utf8(&b"\xF0\x9F\x8F\x80"[..]).unwrap();
        let start = (0..page_size()-2).map(|_| '1').collect::<String>();
        let input = start.clone() + bball;
        let mut buff = Buffer::new(1, input.as_bytes()).unwrap();
        assert_eq!(buff.read_more().unwrap(), page_size());
        assert_eq!(buff.buffer(), &start);
        buff.consume(start.len());
        assert_eq!(buff.read_more().unwrap(), 2);
        assert_eq!(buff.buffer(), bball);
    }

}
