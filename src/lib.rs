
#[cfg(test)] #[macro_use] extern crate hamcrest2;
#[cfg(test)]  extern crate serde_json;

pub mod iter;

/*
use std::io::Read;
use std::str;

enum Expecting {
    Value,
}

enum ParsedState {
    JsBoolean(bool),
    JsNumber(usize, usize),
    JsString(usize, usize),
}

pub struct JsonStream<R> where R: Read {
    buffer: Vec<u8>,

    input: R,

    cursor_start: usize,
    cursor_end: usize,
    // TODO: fragment bytes
    expected: Expecting,
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
}

impl From<std::io::Error> for Error {
    fn from(io_error: std::io::Error) -> Error {
        Error::Io(io_error)
    }
}

type Result<T> = std::result::Result<T, Error>;

impl<R> JsonStream<R> where R: Read {
    pub fn new(r: R) -> JsonStream<R> {
        JsonStream::<R> {
            buffer: Vec::with_capacity(4096),
            input: r,
            cursor_start: 0,
            cursor_end: 0,
            expected: Expecting::Value,
            parsed: None,
        }
    }

    fn curr_str(&self) -> &str {
        unsafe {
            str::from_utf8_unchecked(&self.buffer[self.cursor_start..self.cursor_end])
        }
    }

    fn advance_value(&mut self) -> Result<()> {
        let remaining = self.curr_str();
        let mut chars = remaining.char_indices();
        let (_, mut c) = chars.next().unwrap();
        while c.is_whitespace() {
            let (_, ch) = chars.next().unwrap();
            c = ch;
        }
        let parsed = match c {
            '"' => {
                let (string_start, mut c) = chars.next().unwrap();
                let string_end =  {
                    let mut pos = string_start;
                    loop {
                        match c {
                            '"' => {break;},
                            '\\' => {
                                chars.next().unwrap(); // consume the next escaped char.
                                let (p, nc) = chars.next().unwrap();
                                pos = p;
                                c = nc;
                            },
                            _ => {
                                let (p, nc) = chars.next().unwrap();
                                pos = p;
                                c = nc;
                            },
                        }
                    }
                    while c != '"' {
                    }
                    pos
                };
                ParsedState::JsString(string_start, string_end)
            },
            't' => {
                assert!(chars.next().map(|(_, c)| c) == Some('r'));
                assert!(chars.next().map(|(_, c)| c) == Some('u'));
                assert!(chars.next().map(|(_, c)| c) == Some('e'));
                ParsedState::JsBoolean(true)
            },
            'f' => {
                assert!(chars.next().map(|(_, c)| c) == Some('a'));
                assert!(chars.next().map(|(_, c)| c) == Some('l'));
                assert!(chars.next().map(|(_, c)| c) == Some('s'));
                assert!(chars.next().map(|(_, c)| c) == Some('e'));
                ParsedState::JsBoolean(false)
            },
            unk @ '0' ... '9' => {
                unimplemented!("Unhandled number parse error char {:?}", unk);
            },
            unk => unimplemented!("Unhandled parse error char {:?}", unk),
        };

        let consumed = {
            let mut idx;
            loop {
                if let Some((i, c)) = chars.next() {
                    idx = i;
                    if !c.is_whitespace() {
                        break;
                    }
                } else {
                    idx = self.cursor_end;
                    break;
                }
            }
            idx
        };
        self.parsed = Some(parsed);
        self.cursor_start += consumed;
        Ok(())
    }
}

impl<'a, R> iter::Iter<'a> for JsonStream<R> where R: Read {
    type Item = JsonToken<'a>;
    type Error = Error;

    fn advance(&mut self) -> Result<()> {
        if self.cursor_start >= self.cursor_end {
            self.buffer.resize(4096, 0);
            let len = self.buffer.len();
            self.cursor_start = 0;
            self.cursor_end = self.input.read(&mut self.buffer[0..len])?;
            str::from_utf8(&self.buffer[self.cursor_start..self.cursor_end]).or(
                Err(Error::Unimplemented("UTF-8 errors unhandled")))?;
        }
        if self.curr_str().is_empty() {
            self.parsed = None;
        } else {
            self.expected = match self.expected {
                Expecting::Value => {
                    self.advance_value()?;
                    Expecting::Value
                }
            };
        }
        Ok(())
    }

    fn get(&'a self) -> Option<JsonToken<'a>> {
        match self.parsed {
            Some(ParsedState::JsString(start, end)) => {
                Some(JsonToken::JsString(unsafe {
                    str::from_utf8_unchecked(&self.buffer[start..end])
                }.into()))
            },
            Some(ParsedState::JsNumber(start, end)) => {
                Some(JsonToken::JsNumber(unsafe {
                    str::from_utf8_unchecked(&self.buffer[start..end])
                }))
            },
            Some(ParsedState::JsBoolean(b)) => {
                Some(JsonToken::JsBoolean(b))
            },
            None => None
        }
    }
}

#[cfg(test)]
mod tests {
    use hamcrest2::prelude::*;
    use super::{JsonStream, JsonToken};
    use super::iter::Iter;
    use serde_json::Value;
    use std::io::Read;
    use std::str::FromStr;

    fn consume_value<R>(stream: &mut JsonStream<R>) -> serde_json::Value 
        where R: Read
    {
        let tok = stream.next().unwrap().unwrap();
        match tok {
            JsonToken::JsString(jsstr) => {Value::String(jsstr.into())},
            JsonToken::JsBoolean(b) => {Value::Bool(b)},
            unk => unimplemented!("still adding types to consume value: {:?}", unk),
        }
    }

    fn compare_serde_with_qjsonrs(input: &str) {
        let serde: Value = Value::from_str(input).unwrap();
        let mut stream = JsonStream::new(input.as_bytes());
        let qjsonrs = consume_value(&mut stream);
        assert_that!(qjsonrs, eq(serde));
        assert_that!(stream.next().unwrap(), none());
    }

    #[test]
    fn simple_string() {
        let mut stream = JsonStream::new(&b"\"my string\""[..]);
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
    fn simple_bool() {
        compare_serde_with_qjsonrs("true");
        compare_serde_with_qjsonrs(" true");
        compare_serde_with_qjsonrs("false");
        compare_serde_with_qjsonrs("false ");
    }

    #[test]
    fn simple_number() {
        compare_serde_with_qjsonrs("14");
    }
}
*/
