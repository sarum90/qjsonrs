
#[cfg(test)] #[macro_use] extern crate hamcrest2;
#[cfg(test)] #[macro_use] extern crate matches;
#[cfg(test)] #[macro_use] extern crate serde_json;
#[cfg(test)]  extern crate os_pipe;
extern crate libc;
extern crate rand;

mod ring;
mod buffer;

use crate::buffer::Buffer;

use std::io::Read;
use std::str;

#[derive(Clone)]
enum ParsedState {
    StartObject,
    EndObject,
    StartArray,
    EndArray,
    JsNull,
    JsBoolean(bool),
    JsNumber(usize),
    JsString(usize),
    JsKey(usize),
}

#[derive(Clone, Copy, Debug)]
enum ParseContext {
    Base,
    Array,
    Object,
}

pub struct JsonStream<R> where R: Read {
    buffer: Buffer<R>,

    context_stack: Vec<ParseContext>,
    parsed: Option<ParsedState>,
}

#[derive(Debug, PartialEq)]
pub struct JsonString<'a> {
    pub raw: &'a str,
}

impl<'a> From<&'a str> for JsonString<'a> {
    fn from(s: &'a str) -> JsonString<'a> {
        JsonString{
            raw: s
        }
    }
}

unsafe fn unescape(s: &str) -> String {
    let mut res = String::with_capacity(s.len());
    let mut chs = s.chars();
    while let Some(c) = chs.next() {
        if c == '\\' {
            let c = chs.next().expect("unescape off end of string.");
            res.push(match c {
                'u' => {
                    let a = chs.next().expect("unescape unicode off end of string.");
                    let b = chs.next().expect("unescape unicode off end of string.");
                    let c = chs.next().expect("unescape unicode off end of string.");
                    let d = chs.next().expect("unescape unicode off end of string.");
                    std::char::from_u32(
                        ((a.to_digit(16).expect("Bad hex digit in \\u escape") as u32) << 12) +
                        ((b.to_digit(16).expect("Bad hex digit in \\u escape") as u32) << 8) +
                        ((c.to_digit(16).expect("Bad hex digit in \\u escape") as u32) << 4) +
                        (d.to_digit(16).expect("Bad hex digit in \\u escape") as u32)
                    ).expect("")
                },
                '"' => '"',
                'n' => '\n',
                '\\' => '\\',
                '/' => '/',
                'b' => '\x08',
                'r' => '\r',
                't' => '\t',
                unk => panic!("Unhandled escape {:?}", unk),
            })
        } else {
            res.push(c);
        }
    };
    res
}

impl Into<String> for JsonString<'_> {
    fn into(self) -> String {
        // self.raw must be a valid set of escaped JSON string utf-8 bytes.
        unsafe {
            unescape(self.raw.into())
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum JsonToken<'a> {
    StartObject,
    EndObject,
    StartArray,
    EndArray,
    JsNull,
    JsBoolean(bool),
    JsNumber(&'a str),
    JsString(JsonString<'a>),
    JsKey(JsonString<'a>),
}

#[derive(Debug)]
pub struct ParseError {
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Parse(ParseError),
    Unimplemented(&'static str),
    UnexpectedChar(char),
    BufferOutOfSpace,
    InvalidUnicode,
    UnexpectedEOF,
}

impl From<std::io::Error> for Error {
    fn from(io_error: std::io::Error) -> Error {
        Error::Io(io_error)
    }
}

impl From<buffer::Error> for Error {
    fn from(berr: buffer::Error) -> Error {
        match berr {
            buffer::Error::IoError(ioe) => ioe.into(),
            buffer::Error::BufferOutOfSpace => Error::BufferOutOfSpace,
            buffer::Error::InvalidUnicode => Error::InvalidUnicode,
            buffer::Error::UnexpectedEOF => Error::UnexpectedEOF,
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

struct JsonStreamIter<'a, S> where S: Read {
    inner: &'a mut JsonStream<S>,
    idx: usize,
}

impl<'a, S> JsonStreamIter<'a, S>  where S: Read {
    fn new(stream: &'a mut JsonStream<S>, idx: usize) -> JsonStreamIter<'a, S> {
        JsonStreamIter{
            inner: stream,
            idx,
        }
    }

    fn next(&mut self) -> Result<Option<(usize, char)>> {
        if self.idx >= self.inner.curr_str().len() {
            if self.inner.buffer.read_more()? == 0 {
                return Ok(None);
            }
        }

        let c = self.inner.curr_str()[self.idx..].chars().next().expect("Verified there should be a char here.");
        let idx = self.idx;
        self.idx += c.len_utf8();

        // TODO: consider erring out on control characters.

        Ok(Some((idx, c)))
    }

    fn js_string(mut self) -> Result<usize> {
        let (mut pos, mut c) = self.next()?.unwrap();
        loop {
            match c {
                '"' => {break;},
                '\\' => {
                    self.next()?.unwrap(); // consume the next escaped char.
                    let (p, nc) = self.next()?.unwrap();
                    pos = p;
                    c = nc;
                },
                _ => {
                    let (p, nc) = self.next()?.unwrap();
                    pos = p;
                    c = nc;
                },
            }
        }
        Ok(pos)
    }

    fn int_digits(mut self) -> Result<usize> {
        loop {
            match self.next()? {
                Some((_, '0'...'9')) => {},
                Some((_, '.')) => {return self.fraction_first_digit()},
                Some((_, 'e')) | Some((_, 'E')) => {return self.exp()},
                Some((i, _)) => {return Ok(i)},
                None => {return Ok(self.idx)},
            }
        }
    }

    fn exp(mut self) -> Result<usize> {
        match self.next()? {
            Some((_, '+')) | Some((_, '-')) => {self.exp_first_digit()},
            Some((_, '0' ... '9')) => {self.exp_digits()},
            Some((_, c)) => Err(Error::UnexpectedChar(c)),
            None => Err(Error::UnexpectedEOF),
        }
    }

    fn exp_first_digit(mut self) -> Result<usize> {
        match self.next()? {
            Some((_, '0' ... '9')) => {self.exp_digits()},
            Some((_, c)) => Err(Error::UnexpectedChar(c)),
            None => Err(Error::UnexpectedEOF),
        }
    }

    fn exp_digits(mut self) -> Result<usize> {
        loop {
            match self.next()? {
                Some((_, '0'...'9')) => {},
                Some((i, _)) => {return Ok(i)},
                None => {return Ok(self.idx)},
            }
        }
    }

    fn decimal_point(mut self) -> Result<usize> {
        match self.next()? {
            Some((_, '.')) => {self.fraction_first_digit()},
            Some((_, 'e')) | Some((_, 'E')) => {self.exp()},
            Some((i, _)) => {Ok(i)},
            None => {Ok(self.idx)},
        }
    }


    fn unsigned_number(mut self) -> Result<usize> {
        match self.next()? {
            Some((_, '1' ... '9')) => self.int_digits(),
            Some((_, '0')) => self.decimal_point(),
            Some((_, c)) => Err(Error::UnexpectedChar(c)),
            None => Err(Error::UnexpectedEOF),
        }
    }

    fn fraction_first_digit(mut self) -> Result<usize> {
        match self.next()? {
            Some((_, '0'...'9')) => self.fraction_digits(),
            Some((_, c)) => Err(Error::UnexpectedChar(c)),
            None => Err(Error::UnexpectedEOF),
        }
    }

    fn fraction_digits(mut self) -> Result<usize> {
        loop {
            match self.next()? {
                Some((_, '0'...'9')) => {},
                Some((_, 'e')) | Some((_, 'E')) => {return self.exp()},
                Some((i, _)) => {return Ok(i)},
                None => {return Ok(self.idx)},
            }
        }
    }
}

impl<R> JsonStream<R> where R: Read {
    pub fn from_read(r: R) -> Result<JsonStream<R>> {
        Ok(
            JsonStream::<R> {
                buffer: Buffer::new(4096, r)?,
                context_stack: vec![ParseContext::Base],
                parsed: None,
            }
        )
    }

    pub fn buffer_size(&self) -> usize {
        self.buffer.size()
    }

    fn curr_str(&self) -> &str {
        self.buffer.buffer()
    }

    fn advance_jsstring(&mut self) -> Result<usize> {
        self.consume_token("\"")?;
        JsonStreamIter::new(self, 0).js_string()
    }

    fn advance_value(&mut self) -> Result<()> {
        let c = self.curr_str().chars().next();
        let parsed = match c {
            Some('"') => {
                ParsedState::JsString(self.advance_jsstring()?)
            },
            Some('t') => {
                self.consume_bytes("t".len())?;
                self.consume_token("rue")?;
                ParsedState::JsBoolean(true)
            },
            Some('f') => {
                self.consume_bytes("f".len())?;
                self.consume_token("alse")?;
                ParsedState::JsBoolean(false)
            },
            Some('n') => {
                self.consume_bytes("n".len())?;
                self.consume_token("ull")?;
                ParsedState::JsNull
            },
            Some('1' ... '9') => {
                ParsedState::JsNumber(JsonStreamIter::new(self, 1).int_digits()?)
            },
            Some('0') => {
                ParsedState::JsNumber(JsonStreamIter::new(self, 1).decimal_point()?)
            },
            Some('-') => {
                ParsedState::JsNumber(JsonStreamIter::new(self, 1).unsigned_number()?)
            },
            Some('[') => {
                self.consume_bytes("[".len())?;
                self.context_stack.push(ParseContext::Array);
                ParsedState::StartArray
            }
            Some('{') => {
                self.consume_bytes("{".len())?;
                self.context_stack.push(ParseContext::Object);
                ParsedState::StartObject
            }
            Some(unex) => return Err(Error::UnexpectedChar(unex)),
            None => panic!("advance_value can only be called if there is more we can do"),
        };
        self.parsed = Some(parsed);
        Ok(())
    }

    fn consume_while<P>(&mut self, mut p: P) -> Result<()>
        where P: FnMut(char) -> bool
    {
        loop {
            for (i, ch) in self.buffer.buffer().char_indices() {
                if !p(ch) {
                    self.buffer.consume(i);
                    return Ok(());
                }
            }
            self.buffer.consume_all();
            if self.buffer.read_more()? == 0 {
                return Ok(());
            }
        }
    }

    fn consume_ws(&mut self) -> Result<()> {
        self.consume_while(|c| c.is_whitespace())
    }

    fn consume_bytes(&mut self, bytes: usize) -> Result<()> {
        self.buffer.consume(bytes);
        if self.curr_str().len() == 0 {
            self.buffer.read_more()?;
        }
        Ok(())
    }

    fn consume_token(&mut self, tok: &str) -> Result<()> {
        // Fast path: (only valid because tok is always ASCII)
        let t_len = tok.len();
        if self.curr_str().len() >= t_len {
            if &self.curr_str().as_bytes()[..t_len] == tok.as_bytes() {
                self.consume_bytes(t_len)?;
                return Ok(())
            }
        }

        // Slow path: (for when we must load more data into the buffer)
        let mut chinds = tok.chars();
        let mut unexpected = None;
        {
            let ci = &mut chinds;
            let unex = &mut unexpected;
            self.consume_while(|c| {
                match ci.next() {
                    None => false,
                    Some(ec) => {
                        if c == ec {
                            true
                        }  else {
                            *unex = Some(c);
                            false
                        }
                    }
                }
            })?;
        }
        match unexpected {
            None => Ok(()),
            Some(c) => Err(Error::UnexpectedChar(c)),
        }
    }

    pub fn advance(&mut self) -> Result<()> {
        // First, consume the previous result:
        match self.parsed {
            // String plus trailing '"':
            Some(ParsedState::JsString(len)) => {self.consume_bytes(len+"\"".len())?},
            // String plus trailing '"':
            Some(ParsedState::JsKey(len)) => {self.consume_bytes(len+"\"".len())?},
            // Number:
            Some(ParsedState::JsNumber(len)) => {self.consume_bytes(len)?},
            // All other types have already been consumed:
            _ => {},
        }

        // Then consume any whitespace:
        self.consume_ws()?;

        // Then parse the next thing:
        if self.curr_str().is_empty() {
            self.parsed = None;
        } else {
            match (self.context_stack.last().expect("Context_stack should always have 1 element."), self.parsed.clone()) {
                // Stream of values with only whitespace separating:
                (ParseContext::Base, _) => {
                    self.advance_value()?;
                },
                // First element of an array:
                (ParseContext::Array, Some(ParsedState::StartArray)) => {
                    let c = self.curr_str().chars().next();
                    match c {
                        Some(']') => {
                            self.consume_bytes("]".len())?;
                            self.context_stack.pop().expect("Must have array on stack to get here.");
                            self.parsed = Some(ParsedState::EndArray);
                        },
                        Some(_) => {
                            self.advance_value()?;
                        },
                        None => {
                            return Err(Error::UnexpectedEOF);
                        }
                    };
                },
                // Continuation of an array:
                (ParseContext::Array, _) => {
                    let c = self.curr_str().chars().next();
                    match c {
                        Some(',') => {
                            self.consume_bytes(",".len())?;
                            self.consume_ws()?;
                            self.advance_value()?;
                        },
                        Some(']') => {
                            self.consume_bytes("]".len())?;
                            self.context_stack.pop().expect("Must have array on stack to get here.");
                            self.parsed = Some(ParsedState::EndArray);
                        },
                        Some(c) => {
                            return Err(Error::UnexpectedChar(c));
                        },
                        None => {
                            return Err(Error::UnexpectedEOF);
                        }
                    };
                },
                // Start of an object:
                (ParseContext::Object, Some(ParsedState::StartObject)) => {
                    let c = self.curr_str().chars().next();
                    match c {
                        Some('"') => {
                            self.parsed = Some(ParsedState::JsKey(self.advance_jsstring()?));
                        },
                        Some('}') => {
                            self.consume_bytes("}".len())?;
                            self.context_stack.pop().expect("Must have object on stack to get here.");
                            self.parsed = Some(ParsedState::EndObject);
                        },
                        Some(c) => {
                            return Err(Error::UnexpectedChar(c));
                        },
                        None => {
                            return Err(Error::UnexpectedEOF);
                        }
                    };
                },
                // Continuation of an object after a key:
                (ParseContext::Object, Some(ParsedState::JsKey(_))) => {
                    let c = self.curr_str().chars().next();
                    match c {
                        Some(':') => {
                            self.consume_bytes(":".len())?;
                            self.consume_ws()?;
                            self.advance_value()?;
                        },
                        Some(c) => {
                            return Err(Error::UnexpectedChar(c));
                        },
                        None => {
                            return Err(Error::UnexpectedEOF);
                        }
                    }
                }
                // Continuation of an object after a value:
                (ParseContext::Object, _) => {
                    let c = self.curr_str().chars().next();
                    match c {
                        Some(',') => {
                            self.consume_bytes(",".len())?;
                            self.consume_ws()?;
                            let c = self.curr_str().chars().next();
                            match c {
                                Some('"') => {
                                    self.parsed = Some(ParsedState::JsKey(self.advance_jsstring()?));
                                },
                                Some(c) => {
                                    return Err(Error::UnexpectedChar(c));
                                },
                                None => {
                                    return Err(Error::UnexpectedEOF);
                                }
                            }
                        },
                        Some('}') => {
                            self.consume_bytes("}".len())?;
                            self.context_stack.pop().expect("Must have object on stack to get here.");
                            self.parsed = Some(ParsedState::EndObject);
                        },
                        Some(c) => {
                            return Err(Error::UnexpectedChar(c));
                        },
                        None => {
                            return Err(Error::UnexpectedEOF);
                        }
                    };
                },
            }
        }
        Ok(())
    }

    pub fn get<'a>(&'a self) -> Option<JsonToken<'a>> {
        match self.parsed {
            Some(ParsedState::StartObject) =>
                Some(JsonToken::StartObject),
            Some(ParsedState::EndObject) =>
                Some(JsonToken::EndObject),
            Some(ParsedState::StartArray) =>
                Some(JsonToken::StartArray),
            Some(ParsedState::EndArray) =>
                Some(JsonToken::EndArray),
            Some(ParsedState::JsString(len)) =>
                Some(JsonToken::JsString(self.curr_str()[..len].into())),
            Some(ParsedState::JsKey(len)) =>
                Some(JsonToken::JsKey(self.curr_str()[..len].into())),
            Some(ParsedState::JsNumber(len)) =>
                Some(JsonToken::JsNumber(&self.curr_str()[..len])),
            Some(ParsedState::JsBoolean(b)) =>
                Some(JsonToken::JsBoolean(b)),
            Some(ParsedState::JsNull) =>
                Some(JsonToken::JsNull),
            None => None
        }
    }

    pub fn next<'a>(&'a mut self) -> Result<Option<JsonToken<'a>>> {
        self.advance()?;
        Ok(self.get())
    }
}

#[cfg(test)]
mod tests {
    use hamcrest2::prelude::*;
    use super::{JsonStream, JsonToken};
    use serde_json::{Value, Map, Number};
    use std::io::Read;
    use std::str::FromStr;

    #[derive(Debug)]
    enum ConsumedValue {
        Value(Value),
        EndArray,
    }

    fn consume_value_checked<R: Read>(stream: &mut JsonStream<R>) -> ConsumedValue {
        let tok = stream.next().unwrap().unwrap();
        match tok {
            JsonToken::JsNull => {ConsumedValue::Value(Value::Null)},
            JsonToken::JsBoolean(b) => {ConsumedValue::Value(Value::Bool(b))},
            JsonToken::JsNumber(s) => {
                ConsumedValue::Value(
                    Value::Number(
                        Number::from_str(s).expect("Should be able to read JSON number from string.")
                    )
                )
            },
            JsonToken::JsString(jsstr) => {ConsumedValue::Value(Value::String(jsstr.into()))},
            JsonToken::StartArray => {
                let mut res = vec![];
                loop {
                    match consume_value_checked(stream) {
                        ConsumedValue::Value(v) => {
                            res.push(v);
                        },
                        ConsumedValue::EndArray => {
                            break;
                        }
                    }
                }
                ConsumedValue::Value(Value::Array(res))
            },
            JsonToken::EndArray => { ConsumedValue::EndArray },
            JsonToken::StartObject => {
                let mut res = Map::new();
                loop {
                    match stream.next().unwrap() {
                        Some(JsonToken::JsKey(k)) => {
                            res.insert(k.into(), consume_value(stream));
                        },
                        Some(JsonToken::EndObject) => {
                            break;
                        },
                        t => { panic!("Unexpected token while parsing objects: {:?}", t); }
                    }
                }
                ConsumedValue::Value(Value::Object(res))
            },
            unexp => { panic!("Unexpected js token {:?}", unexp); },
        }
    }

    fn consume_value<R: Read>(stream: &mut JsonStream<R>) -> Value 
    {
        let res = consume_value_checked(stream);
        if let ConsumedValue::Value(v) = res {
            v
        } else {
            panic!("Expected to be able to read value, but got: {:?}", res);
        }
    }

    fn normalize_value(v: Value) -> Value {
        if v.as_f64() == Some(0.0) {
            json!(0)
        } else {
            v
        }
    }

    fn compare_serde_with_qjsonrs(input: &str) {
        println!("Running input {:?}", input);
        let mut stream = JsonStream::from_read(input.as_bytes()).unwrap();
        match Value::from_str(input).map(normalize_value) {
            Ok(serde) => {
                let qjsonrs = normalize_value(consume_value(&mut stream));
                assert_that!(qjsonrs, eq(serde));
                assert_that!(stream.next().unwrap(), none());
            },
            Err(_) => {
                match stream.next() {
                    Ok(_) => assert_that!(stream.next(), err()),
                    Err(_)  => {}
                }
            },
        }
    }

    #[test]
    fn simple_string() {
        let mut stream = JsonStream::from_read(&b"\"my string\""[..]).unwrap();
        assert_that!(stream.next().unwrap().unwrap(), eq(JsonToken::JsString("my string".into())));
        assert_that!(stream.next().unwrap(), none());
    }

    #[test]
    fn simple_string_serde() {
        compare_serde_with_qjsonrs("\"my string\"");
        compare_serde_with_qjsonrs(" \"my string\"");
        compare_serde_with_qjsonrs("\"my string\" ");
        compare_serde_with_qjsonrs("\"my \\\"string\"");
        compare_serde_with_qjsonrs("\"my \\\\string\"");
        compare_serde_with_qjsonrs("\"my \\/ string\"");
        compare_serde_with_qjsonrs("\"my \\b string\"");
        compare_serde_with_qjsonrs("\"my \\n string\"");
        compare_serde_with_qjsonrs("\"my \\r string\"");
        compare_serde_with_qjsonrs("\"my \\t string\"");
        compare_serde_with_qjsonrs("\"my \\u0022 string\"");
        compare_serde_with_qjsonrs("\"my \\u263A smiley\"");
    }

    #[test]
    fn string_spanning_buffers() {
        let size = {
            let stream = JsonStream::from_read(&b"\"my string\""[..]).unwrap();
            stream.buffer_size()
        };
        let s = (0..size-3).map(|_| ' ').collect::<String>();
        let input = s + "\"1234567890\"";
        compare_serde_with_qjsonrs(&input);
    }

    #[test]
    fn simple_bool() {
        compare_serde_with_qjsonrs("true");
        compare_serde_with_qjsonrs(" true");
        compare_serde_with_qjsonrs("false");
        compare_serde_with_qjsonrs("false ");
    }

    #[test]
    fn bad_num() {
        compare_serde_with_qjsonrs("1234.56ecat");
        compare_serde_with_qjsonrs("1234.56cat");
    }

    #[test]
    fn simple_number() {
        for sign in vec!["", "-"] {
            for number in vec!["0", "1", "14"] {
                for fraction in vec!["", ".1", ".14"] {
                    for e in vec!["e", "E", ""] {
                        for esign in vec!["+", "-", ""] {
                            for mag in vec!["0", "1", "14"] {
                                let exp = if e.len() == 0 {
                                    "".to_owned()
                                } else {
                                    e.to_owned() + esign + mag
                                };
                                let tc = sign.to_owned() + number + fraction + &exp;
                                compare_serde_with_qjsonrs(&tc);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn null() {
        compare_serde_with_qjsonrs(" null ");
    }

    #[test]
    fn arrays() {
        compare_serde_with_qjsonrs("[]");
        compare_serde_with_qjsonrs("[1]");
        compare_serde_with_qjsonrs(" [ 1 ] ");
        compare_serde_with_qjsonrs("[null, 1 , true]");
        compare_serde_with_qjsonrs("[[null], [], 1, [[[]], true]]");
        compare_serde_with_qjsonrs("[[null], [], 1, [ [ []], true]]");
    }

    #[test]
    fn objects() {
        compare_serde_with_qjsonrs("{}");
        compare_serde_with_qjsonrs("{\"one\": []}");
        compare_serde_with_qjsonrs("{ \"one\"  : {\"one\":{},\"two\":{\"12\":null}} }");
        compare_serde_with_qjsonrs("{\"a\": {} , \"one\": {\"[]\": [{}, null, {\"a\":[{}]}]}}");
    }
}
