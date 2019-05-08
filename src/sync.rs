
use std::io::{Read, Error as IoError};
use crate::decode::{JsonDecoder, DecodeError, ConsumableBytes};
use crate::token::{JsonToken, JsonString};
use std::str;

#[derive(Debug)]
struct StreamIndices {
    start: usize,
    scanned: usize,
    end: usize,
}

struct Slice {
    start: usize,
    end: usize,
}

impl Slice {
    fn new(haystack: &[u8], needle: &str) -> Slice {
        let start = (needle.as_ptr() as usize) - (haystack.as_ptr() as usize);
        let end = start + needle.len();
        Slice{start, end}
    }

    fn to_json_string<'a>(self, buffer: &'a [u8]) -> JsonString<'a> {
        let s = unsafe {
            str::from_utf8_unchecked(&buffer[self.start..self.end])
        };
        let r = unsafe {
            JsonString::from_str_unchecked(s)
        };
        r
    }
}

enum DerefJsonToken {
    StartObject,
    EndObject,
    StartArray,
    EndArray,
    JsNull,
    JsBoolean(bool),
    JsNumber(Slice),
    JsString(Slice),
    JsKey(Slice),
}

impl DerefJsonToken {
    fn new<'a>(token: JsonToken<'a>, buffer: &'a [u8]) -> DerefJsonToken {
        match token {
            JsonToken::StartObject => DerefJsonToken::StartObject,
            JsonToken::EndObject => DerefJsonToken::EndObject,
            JsonToken::StartArray => DerefJsonToken::StartArray,
            JsonToken::EndArray => DerefJsonToken::EndArray,
            JsonToken::JsNull => DerefJsonToken::JsNull,
            JsonToken::JsBoolean(b) => DerefJsonToken::JsBoolean(b),
            JsonToken::JsNumber(s) => DerefJsonToken::JsNumber(Slice::new(buffer, s)),
            JsonToken::JsString(s) => DerefJsonToken::JsString(Slice::new(buffer, s.to_raw_str())),
            JsonToken::JsKey(s) => DerefJsonToken::JsKey(Slice::new(buffer, s.to_raw_str())),
        }
    }

    fn reref<'a>(self, buffer: &'a [u8]) -> JsonToken<'a> {
        match self {
            DerefJsonToken::StartObject => JsonToken::StartObject,
            DerefJsonToken::EndObject => JsonToken::EndObject,
            DerefJsonToken::StartArray => JsonToken::StartArray,
            DerefJsonToken::EndArray => JsonToken::EndArray,
            DerefJsonToken::JsNull => JsonToken::JsNull,
            DerefJsonToken::JsString(s) => JsonToken::JsString(s.to_json_string(buffer)),
            _ => unimplemented!("Thing"),
        }
    }
}

/// Stream of JSON values from an std::io::Read built on top of a decoder.
pub struct Stream<R> {
    buffer: Vec<u8>,
    indices: StreamIndices,
    decoder: JsonDecoder,
    src: R,
}

#[derive(Debug)]
pub enum StreamError {
    IoError(IoError),
    DecodeError(DecodeError),
}

impl From<IoError> for StreamError {
    fn from(io: IoError) -> StreamError {
        StreamError::IoError(io)
    }
}

impl From<DecodeError> for StreamError {
    fn from(d: DecodeError) -> StreamError {
        StreamError::DecodeError(d)
    }
}

struct ConsumeableByteAdvance<'a, 'b> {
    source: &'b mut StreamIndices,
    bytes: ConsumableBytes<'a>,
    in_len: usize,
}

impl<'a, 'b> Drop for ConsumeableByteAdvance<'a, 'b> {
    fn drop(&mut self) {
	self.source.start += self.in_len - self.bytes.len();
        if self.source.scanned < self.source.start {
            self.source.scanned = self.source.start;
        }
    }
}

impl<'a, 'b> ConsumeableByteAdvance<'a, 'b> {
    fn new(source: &'b mut StreamIndices, _end: bool, bytes: &'a [u8]) -> ConsumeableByteAdvance<'a, 'b> {
	let in_len = source.end - source.start;
        // TODO: conditionally set it to end_of_stream:
	//let bytes = if end {
        //ConsumableBytes::new_end_of_stream(&source.bytes[source.start..source.end])
	//} else {
	//};
	let bytes = ConsumableBytes::new(&bytes[source.start..source.end]);
	ConsumeableByteAdvance{
	    source,
	    bytes,
	    in_len,
	}
    }

    fn scanned_to_end(&mut self) {
        self.source.scanned = self.source.end;
    }

    fn bytes(&mut self) -> &mut ConsumableBytes<'a> {
	&mut self.bytes
    }
}

impl<R> Stream<R> where R: Read {
    /// Create a Stream from a std::io::Read.
    pub fn from_read_with_initial_capacity(src: R, cap: usize) -> Stream<R> {
        Stream {
            buffer: vec![0; cap],
            indices: StreamIndices{
                start: 0,
                scanned: 0,
                end: 0,
            },
            decoder: JsonDecoder::new(),
            src,
        }
    }

    fn ensure_bytes(&mut self) -> Result<(), IoError> {
        if self.indices.scanned >= self.indices.end {
            if self.indices.start > 0 {
                let to_move = self.indices.end - self.indices.start;
                if to_move > 0 {
                    // TODO: use copy_within once stable.
                    let mut new_buff = vec![0; self.buffer.len()];
                    new_buff[..to_move].copy_from_slice(
                        &self.buffer[self.indices.start..self.indices.end]);
                    self.buffer = new_buff;
                }
                self.indices.end -= self.indices.start;
                self.indices.scanned -= self.indices.start;
                self.indices.start -= self.indices.start;
            }
            if self.indices.scanned >= self.buffer.len() {
                self.buffer.resize(self.buffer.len()*2, b'0');
            }
            let bytes = &mut self.buffer[self.indices.scanned..];
            assert!(
                bytes.len() > 0,
                "Need to add shuffling / compacting: {:?}, {:?}", self.indices, self.buffer.len()
            );
            let n = self.src.read(bytes)?;
            self.indices.end = self.indices.scanned + n;
        }
        Ok(())
    }

    /// Advance to the next JsonToken and return it, reading additional bytes from the underlying
    /// stream if necessary.
    pub fn next<'a>(&'a mut self) -> Result<Option<JsonToken<'a>>, StreamError> {
        let v = self.next_impl();
        let b = &self.buffer[..];
        v.map(|o| o.map(|d| d.reref(b)))
        //loop {
        //    match self.next_impl() {
        //        Err(StreamError::DecodeError(DecodeError::NeedsMore)) => {},
        //        n => {return n;},
        //    }
        //}
    }

    fn decode<'a>(buffer: &'a [u8], indices: &mut StreamIndices, decoder: &mut JsonDecoder) -> Result<Option<JsonToken<'a>>, StreamError> {
        let mut cb = ConsumeableByteAdvance::new(indices, false, buffer);
        let r = decoder.decode(cb.bytes());
        match r {
            Err(DecodeError::NeedsMore) => {
                cb.scanned_to_end()
            },
            _ => {},
        }
        Ok(r?)
    }

    fn next_impl(&mut self) -> Result<Option<DerefJsonToken>, StreamError> {
        loop {
            self.ensure_bytes()?;
            match Self::decode(&self.buffer[..], &mut self.indices, &mut self.decoder) {
                Err(StreamError::DecodeError(DecodeError::NeedsMore)) => {},
                n => {return n.map(|o| o.map(|t| DerefJsonToken::new(t, &self.buffer[..])));},
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Stream};
    use crate::token::{JsonToken, JsonString};

    #[test]
    fn simple_stream() {
        let bytes = &b"[null]"[..];
        let mut s = Stream::from_read_with_initial_capacity(bytes, 10);
        assert_eq!(JsonToken::StartArray, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::JsNull, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::EndArray, s.next().unwrap().unwrap());
        assert_eq!(None, s.next().unwrap());
    }

    #[test]
    fn simple_stream_over_cap() {
        let bytes = &b"[null,null,null,null]"[..];
        let mut s = Stream::from_read_with_initial_capacity(bytes, 10);
        assert_eq!(JsonToken::StartArray, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::JsNull, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::JsNull, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::JsNull, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::JsNull, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::EndArray, s.next().unwrap().unwrap());
        assert_eq!(None, s.next().unwrap());
    }

    #[test]
    fn single_large_over_cap() {
        let bytes = &b"[\"1234567890123456789\",null,null,null]"[..];
        let mut s = Stream::from_read_with_initial_capacity(bytes, 10);
        assert_eq!(JsonToken::StartArray, s.next().unwrap().unwrap());
        assert_eq!(
            JsonToken::JsString(JsonString::from_str("1234567890123456789").unwrap()),
            s.next().unwrap().unwrap()
        );
        assert_eq!(JsonToken::JsNull, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::JsNull, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::JsNull, s.next().unwrap().unwrap());
        assert_eq!(JsonToken::EndArray, s.next().unwrap().unwrap());
        assert_eq!(None, s.next().unwrap());
    }
}
