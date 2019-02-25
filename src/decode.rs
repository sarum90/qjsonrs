
use crate::token::JsonToken;

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    NeedsMore,
    InvalidUtf8,
    UnexpectedChar(char),
    UnexpectedByte(u8),
}

pub type DecodeResult<'a> = Result<Option<JsonToken<'a>>, DecodeError>;

pub struct ConsumableBytes<'a> {
    bytes: &'a [u8]
}

fn is_whitespace(c: u8) -> bool {
    match c {
        0x09| 0x0a | 0x0d | 0x20 => true,
        _ => false,
    }
}

impl<'a> ConsumableBytes<'a> {
    pub fn new(bytes: &'a [u8]) -> ConsumableBytes<'a> {
        ConsumableBytes{bytes}
    }

    pub fn consume_bytes(&mut self, n: usize) {
        self.bytes = &self.bytes[n..];
    }

    fn expect_bytes(&mut self, bs: &[u8]) -> Result<(), DecodeError> {
        let len = bs.len();
        if self.bytes.len() >= len {
            if &self.bytes[..len] == bs {
                self.consume_bytes(len);
                Ok(())
            } else {
                Err(DecodeError::UnexpectedByte(
                    self.bytes.iter().zip(bs.iter())
                        .find(|(bc, ec)| *bc != *ec)
                        .map(|(bc, _)| *bc)
                        .unwrap()
                ))
            }
        } else {
            let sublen = self.bytes.len();
            if self.bytes == &bs[..sublen] {
                unimplemented!("Needs more unimplemented");
            } else {
                Err(DecodeError::UnexpectedByte(
                    self.bytes.iter().zip(bs.iter())
                        .find(|(bc, ec)| *bc != *ec)
                        .map(|(bc, _)| *bc)
                        .unwrap()
                ))
            }
        }
    }

    fn consume_ws(&mut self) {
        let skip = self.bytes.iter().take_while(|c| is_whitespace(**c)).count();
        self.consume_bytes(skip);
    }

    fn next(&self) -> Option<u8> {
        self.bytes.iter().next().map(|c| *c)
    }
}

#[derive(Clone, Copy, Debug)]
enum ParseContext {
    Base,
    Array,
    Object,
}

// Used to keep track of what 
#[derive(Clone, Copy, Debug)]
enum TokenCategory {
    Comma,
    Colon,
    Value,
    Key,
}

struct JsonDecoder {
    context_stack: Vec<ParseContext>,
    previous_token: TokenCategory,
}

impl JsonDecoder {
    pub fn new() -> JsonDecoder {
        JsonDecoder {
            context_stack: vec!{ParseContext::Base},
            previous_token: TokenCategory::Value,
        }
    }

    pub fn decode<'a>(&mut self, bytes: &mut ConsumableBytes<'a>) -> DecodeResult<'a> {
        bytes.consume_ws();
        match bytes.next() {
            Some(b'n') => {
                bytes.expect_bytes(b"null")?;
                Ok(Some(JsonToken::JsNull))
            },
            Some(b'f') => {
                bytes.expect_bytes(b"false")?;
                Ok(Some(JsonToken::JsBoolean(false)))
            },
            Some(b't') => {
                bytes.expect_bytes(b"true")?;
                Ok(Some(JsonToken::JsBoolean(true)))
            },
            Some(_) => unimplemented!("Decode is not implemented yet"),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use hamcrest2::prelude::*;
    use super::{JsonDecoder, ConsumableBytes, JsonToken, DecodeError};
    use serde_json::{Value, Map, Number};
    use std::str::FromStr;

    #[derive(Debug)]
    enum ConsumedValue {
        Value(Value),
        EndArray,
    }

    fn consume_value_impl<'a>(decoder: &mut JsonDecoder, bytes: &mut ConsumableBytes<'a>) -> Result<ConsumedValue, DecodeError> {
        let tok = decoder.decode(bytes)?.expect("Should not be at end of bytes.");
        Ok(match tok {
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
                    match consume_value_impl(decoder, bytes)? {
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
                    match decoder.decode(bytes).expect("No Error in middle of object") {
                        Some(JsonToken::JsKey(k)) => {
                            res.insert(k.into(), consume_value(decoder, bytes)?);
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
        })
    }

    fn consume_value<'a>(decoder: &mut JsonDecoder, bytes: &mut ConsumableBytes<'a>) -> Result<Value, DecodeError>
    {
        let res = consume_value_impl(decoder, bytes)?;
        if let ConsumedValue::Value(v) = res {
            Ok(v)
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

    // Validate that feeding the input in 1 byte at a time is the same as filling the input all at
    // once.
    fn validate_chunked(input: &str) {
        let mut fullbytes = ConsumableBytes::new(input.as_bytes());
        let mut fulldecoder = JsonDecoder::new();
        let qjsonrs = normalize_value(consume_value(&mut fulldecoder, &mut fullbytes).unwrap());
        let in_bytes = input.as_bytes();
        for idx in 0..in_bytes.len() {
            let mut bytes = ConsumableBytes::new(&in_bytes[..idx]);
            let mut decoder = JsonDecoder::new();
            let resp = consume_value_impl(&mut decoder, &mut bytes);
            if resp == Err(DecodeError::NeedsMore) {
                continue;
            }
            assert_that!(normalize_value(resp.expect("Should not get error")), eq(qjsonrs));
            return;
        }
        panic!("Should always get a error or value before end of byte stream.")
    }

    fn compare_serde_with_qjsonrs_impl(input: &str) -> Option<DecodeError> {
        println!("Running input {:?}", input);
        validate_chunked(input);
        let mut bytes = ConsumableBytes::new(input.as_bytes());
        let mut decoder = JsonDecoder::new();
        match Value::from_str(input).map(normalize_value) {
            Ok(serde) => {
                let qjsonrs = normalize_value(consume_value(&mut decoder, &mut bytes));
                assert_that!(qjsonrs, eq(serde));
                assert_that!(decoder.decode(&mut bytes).unwrap(), none());
                None
            },
            Err(_) => {
                Some(decoder.decode(&mut bytes).expect_err("Expected to hit an err case, given serde error in serde parsing."))
            },
        }
    }

    fn compare_serde_with_qjsonrs(input: &str) {
        compare_serde_with_qjsonrs_impl(input);
    }

    fn compare_serde_with_qjsonrs_err(input: &str, err: DecodeError) {
        assert_that!(
            compare_serde_with_qjsonrs_impl(input).expect("Error expected"),
            eq(err)
        );
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
    fn bool() {
        compare_serde_with_qjsonrs("true");
        compare_serde_with_qjsonrs(" true");
        compare_serde_with_qjsonrs("false");
        compare_serde_with_qjsonrs("false ");
        compare_serde_with_qjsonrs_err(" trout ", DecodeError::UnexpectedByte(b'o'));
        compare_serde_with_qjsonrs_err(" fal ", DecodeError::UnexpectedByte(b' '));
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
        compare_serde_with_qjsonrs("null");
        compare_serde_with_qjsonrs(" null ");
        compare_serde_with_qjsonrs_err("not_null", DecodeError::UnexpectedByte(b'o'));
        compare_serde_with_qjsonrs_err("nut", DecodeError::UnexpectedByte(b't'));
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
