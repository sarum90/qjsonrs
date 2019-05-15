#![deny(missing_docs)]
//! # qjsonrs
//!
//! A quick JSON tokenizer.
//!
//! This crate is intended to be used to quickly tokenize a stream of JSON data. It merely emits
//! tokens, it does not parse the JSON into larger structures.
//!
//! This is useful for extracting data from massive arrays, or quick parsing of JSON objects where
//! you only care about certain keys.
//!
//! # Examples:
//! ## Simple usage:
//! ```
//! use qjsonrs::{
//!     sync::{
//!         Stream,
//!         TokenIterator,
//!         Error as JsonError,
//!     },
//!     JsonToken::{
//!         StartObject,
//!         EndObject,
//!         StartArray,
//!         EndArray,
//!         JsKey,
//!         JsNumber,
//!     },
//!     JsonString,
//! };
//!
//! # fn main() -> Result<(), JsonError> {
//! let mut stream = Stream::from_read(&b"{\"test\": 1, \"arr\": []}"[..])?;
//! assert_eq!(stream.next()?.unwrap(), StartObject);
//! assert_eq!(stream.next()?.unwrap(), JsKey(JsonString::from_str_ref("test").unwrap()));
//! assert_eq!(stream.next()?.unwrap(), JsNumber("1"));
//! assert_eq!(stream.next()?.unwrap(), JsKey(JsonString::from_str_ref("arr").unwrap()));
//! assert_eq!(stream.next()?.unwrap(), StartArray);
//! assert_eq!(stream.next()?.unwrap(), EndArray);
//! assert_eq!(stream.next()?.unwrap(), EndObject);
//! assert_eq!(stream.next()?, None);
//! # Ok(())
//! # }
//! ```
//! ## Count size of JSON array:
//! ```
//! # use qjsonrs::{
//! #     sync::{
//! #         Stream,
//! #         TokenIterator,
//! #         Error as JsonError,
//! #     },
//! #     JsonToken::{
//! #         StartObject,
//! #         EndObject,
//! #         StartArray,
//! #         EndArray,
//! #         JsKey,
//! #         JsNumber
//! #     },
//! # };
//! #
//! # use std::io::Read;
//! #
//! fn array_size(stream: &mut TokenIterator) -> Result<usize, JsonError> {
//!     assert_eq!(stream.next()?.unwrap(), StartArray);
//!     let mut size = 0;
//!     let mut depth = 0;
//!     loop {
//!         match stream.next()? {
//!             Some(StartObject) => { if depth == 0 {size += 1;} depth += 1; },
//!             Some(EndObject) => { assert!(depth > 0); depth -= 1; },
//!             Some(StartArray) => { if depth == 0 {size += 1;} depth += 1; },
//!             Some(EndArray) => { if depth == 0 {break;} else { depth -= 1; } },
//!             Some(_) => { if depth == 0 {size += 1; } },
//!             None => { panic!("Early termination"); },
//!         }
//!     }
//!     Ok(size)
//! }
//!
//! # fn main() -> Result<(), JsonError> {
//! let mut stream = Stream::from_read(&b"[1, [2], 3, {\"a\": [4]}, 5, 6]"[..])?;
//! assert_eq!(array_size(&mut stream)?, 6);
//! assert_eq!(stream.next()?, None);
//! # Ok(())
//! # }
//!

#[cfg(test)] #[macro_use] extern crate hamcrest2;
#[cfg(test)] #[macro_use] extern crate matches;
#[cfg(test)] #[macro_use] extern crate serde_json;
#[cfg(test)]  extern crate os_pipe;

mod decode;
mod token;

pub mod sync;
pub use crate::token::{JsonString, JsonToken};

#[cfg(test)]
mod tests {
    use hamcrest2::prelude::*;
    use super::sync::{Stream, TokenIterator};
    use super::{JsonToken, JsonString};
    use serde_json::{Value, Map, Number};
    use std::io::Read;
    use std::str::FromStr;

    #[derive(Debug)]
    enum ConsumedValue {
        Value(Value),
        EndArray,
    }

    fn consume_value_checked<R: Read>(stream: &mut Stream<R>) -> ConsumedValue {
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

    fn consume_value<R: Read>(stream: &mut Stream<R>) -> Value 
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
        let mut stream = Stream::from_read(input.as_bytes()).unwrap();
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
        let mut stream = Stream::from_read(&b"\"my string\""[..]).unwrap();
        assert_that!(stream.next().unwrap().unwrap(), eq(JsonToken::JsString(JsonString::from_str_ref("my string").unwrap())));
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
        compare_serde_with_qjsonrs("\"\\u0000\"");
    }

    #[test]
    fn bad_string() {
        compare_serde_with_qjsonrs("\"");
        compare_serde_with_qjsonrs("\"\\");
        compare_serde_with_qjsonrs("\"\\I\"");
        compare_serde_with_qjsonrs("\"\\u");
        compare_serde_with_qjsonrs("\"my\nstring\"");
        compare_serde_with_qjsonrs("\"my\\uaaaP\"");
    }

    #[test]
    fn string_spanning_buffers() {
        let size = 4096;
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
