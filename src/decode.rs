
use crate::token::{JsonToken, JsonString};
use std::str;
use std::str::Utf8Error;
use std::ops::Add;

#[derive(Clone, Copy, Debug)]
enum Context {
    Array,
    Object,
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum TokenType {
    ArrayStart,
    ArrayComma,
    ObjectStart,
    ObjectColon,
    ObjectComma,
    Key,
    Value,
}

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    NeedsMore,
    InvalidUtf8,
    UnexpectedByte(u8),
}

impl From<Utf8Error> for DecodeError {
    fn from (u: Utf8Error) -> DecodeError {
        match u.error_len() {
            None => DecodeError::NeedsMore,
            Some(_) => DecodeError::InvalidUtf8,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Token<'a> {
    Terminated(JsonToken<'a>),
    Unterminated(JsonToken<'a>),
    EndOfStream,
}

impl<'a> Token<'a> {
    pub fn unwrap_or<E>(self, e: E) -> Result<JsonToken<'a>, E> {
        match self {
            Token::Terminated(t) => Ok(t),
            Token::Unterminated(t) => Ok(t),
            _ => Err(e),
        }
    }

    pub fn terminated_or<E>(self, e: E) -> Result<JsonToken<'a>, E> {
        match self {
            Token::Terminated(t) => Ok(t),
            _ => Err(e),
        }
    }
}

enum NumberLength {
    Terminated(usize),
    Unterminated(usize),
}

impl Add<usize> for NumberLength {
    type Output = NumberLength;

    fn add(self, other: usize) -> NumberLength {
        match self {
            NumberLength::Terminated(i) => NumberLength::Terminated(i + other),
            NumberLength::Unterminated(i) => NumberLength::Unterminated(i + other),
        }
    }
}

impl NumberLength {
    fn len(&self) -> usize {
        match self {
            NumberLength::Terminated(n) => *n,
            NumberLength::Unterminated(n) => *n,
        }
    }
}

pub type DecodeResult<'a> = Result<Token<'a>, DecodeError>;

#[derive(Clone, Debug)]
pub struct ConsumableBytes<'a> {
    bytes: &'a [u8]
}

fn is_whitespace(c: u8) -> bool {
    match c {
        0x09| 0x0a | 0x0d | 0x20 => true,
        _ => false,
    }
}

fn validate_json_string(s: &str) -> Result<(), DecodeError> {
    let mut i = s.chars();
    while let Some(c) = i.next() {
        match (c, c.is_control()) {
            (_, true) | ('"', _) => {
                let mut bytes = [0, 0, 0, 0];
                c.encode_utf8(&mut bytes[..]);
                return Err(DecodeError::UnexpectedByte(bytes[0]));
            },
            ('\\', _) => {
                match i.next() {
                    None => {
                        return Err(DecodeError::NeedsMore);
                    },
                    Some('n') | Some('r') | Some('t') | Some('b') | Some('\\') | Some('"') | Some('/') => {},
                    Some('u') => {
                        let mut cnt = 0;
                        let mut b = i
                            .by_ref()
                            .take(4)
                            .inspect(|_| cnt += 1)
                            .skip_while(|c| c.is_digit(16));
                        match b.next() {
                            None => {},
                            Some(c2) => {
                                let mut bytes = [0, 0, 0, 0];
                                c2.encode_utf8(&mut bytes[..]);
                                return Err(DecodeError::UnexpectedByte(bytes[0]));
                            },
                        }
                        if cnt < 4 {
                            return Err(DecodeError::NeedsMore);
                        }
                    },
                    Some(c2) => {
                        let mut bytes = [0, 0, 0, 0];
                        c2.encode_utf8(&mut bytes[..]);
                        return Err(DecodeError::UnexpectedByte(bytes[0]));
                    },
                }
            },
            (_, _) => {},
        }
    }
    Ok(())
}

impl<'a> ConsumableBytes<'a> {
    pub fn new(bytes: &'a [u8]) -> ConsumableBytes<'a> {
        ConsumableBytes{bytes}
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
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
                Err(DecodeError::NeedsMore)
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

    fn consume_next(&mut self) -> Option<u8> {
        let r = self.next();
        if r.is_some() {
            self.consume_bytes(1);
        }
        r
    }

    fn unsigned_number(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            Some(b'1' ... b'9') => Ok(self.int_digits()? + 1),
            Some(b'0') => Ok(self.decimal_point()? + 1),
            Some(c) => Err(DecodeError::UnexpectedByte(c)),
            None => Err(DecodeError::NeedsMore),
        }
    }

    fn fraction_first_digit(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            Some(b'0' ... b'9') => Ok(self.fraction_digits()? + 1),
            Some(c) => Err(DecodeError::UnexpectedByte(c)),
            None => Err(DecodeError::NeedsMore),
        }
    }

    fn fraction_digits(&mut self) -> Result<NumberLength, DecodeError> {
        let mut i = 0;
        loop {
            match self.consume_next() {
                Some(b'0'...b'9') => { i += 1 },
                Some(b'e') | Some(b'E') => {return Ok(self.exp()? + i + 1)},
                Some(_) => {return Ok(NumberLength::Terminated(i))},
                None => {return Ok(NumberLength::Unterminated(i))},
            }
        }
    }

    fn exp_first_digit(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            Some(b'0' ... b'9') => Ok(self.exp_digits()? + 1),
            Some(c) => Err(DecodeError::UnexpectedByte(c)),
            None => Err(DecodeError::NeedsMore),
        }
    }

    fn exp_digits(&mut self) -> Result<NumberLength, DecodeError> {
        let mut i = 0;
        loop {
            match self.consume_next() {
                Some(b'0'... b'9') => { i += 1; },
                Some(_) => {return Ok(NumberLength::Terminated(i))},
                None => {return Ok(NumberLength::Unterminated(i))},
            }
        }
    }

    fn exp(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            Some(b'+') | Some(b'-') => Ok(self.exp_first_digit()? + 1),
            Some(b'0' ... b'9') => Ok(self.exp_digits()? + 1),
            Some(c) => Err(DecodeError::UnexpectedByte(c)),
            None => Err(DecodeError::NeedsMore),
        }
    }

    fn decimal_point(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            Some(b'.') => Ok(self.fraction_first_digit()? + 1),
            Some(b'e') | Some(b'E') => Ok(self.exp()? + 1),
            Some(_) => Ok(NumberLength::Terminated(0)),
            None => Ok(NumberLength::Unterminated(0)),
        }
    }

    fn int_digits(&mut self) -> Result<NumberLength, DecodeError> {
        let mut i = 0;
        loop {
            match self.consume_next() {
                Some(b'0'...b'9') => { i += 1 },
                Some(b'.') => {return Ok(self.fraction_first_digit()? + i + 1)},
                Some(b'e') | Some(b'E') => {return Ok(self.exp()? + i + 1)},
                Some(_) => {return Ok(NumberLength::Terminated(i))},
                None => {return Ok(NumberLength::Unterminated(i))},
            }
        }
    }
}

/// A decoder for translating a stream of bytes into Json Tokens.
pub struct JsonDecoder {
    stack: Vec<Context>,
    previous: TokenType,
}

impl JsonDecoder {
    /// Constructs a new JsonDecoder.
    pub fn new() -> JsonDecoder {
        JsonDecoder {
            stack: vec!{},
            previous: TokenType::Value,
        }
    }

    fn number_of_len<'a>(&self, bytes: &mut ConsumableBytes<'a>, nl: NumberLength) -> DecodeResult<'a> {
        let n = nl.len();
        // TODO: consider using from_utf8_unchecked, we will already have validated that the stream
        // is valid ascii at this point.
        let res = str::from_utf8(&bytes.bytes[..n])?;
        match nl {
            NumberLength::Terminated(_) => {
                bytes.consume_bytes(n);
                Ok(Token::Terminated(JsonToken::JsNumber(res)))
            },
            NumberLength::Unterminated(_) => {
                // Unterminted tokens should not be consumed. Caller should either use the value
                // and never call decode again, or call decode again with more data.
                Ok(Token::Unterminated(JsonToken::JsNumber(res)))
            },
        }
    }

    fn decode_str<'a>(&self, bytes: &mut ConsumableBytes<'a>) -> Result<JsonString<'a>, DecodeError> {
        let mut i = 1;
        let e;
        loop {
            let r = bytes.bytes[i..].iter().enumerate().find(|(_, x)| **x == b'"');
            match r {
                Some((q, _)) => {
                    let pref = &bytes.bytes[i..i+q];
                    let bs_count = if pref.len() > 0 {
                        let non_bs = pref.iter().enumerate().rfind(|(_, x)| **x != b'\\');
                        let (non_bs_idx, _) = non_bs.unwrap_or((0, &0));
                        pref.len() - non_bs_idx - 1
                    } else {
                        0
                    };
                    if bs_count % 2 == 1 {
                        i += pref.len() + 1;
                    } else {
                        e = Some(i + pref.len() - 1);
                        break;
                    }
                },
                None => {
                    e = None;
                    break;
                },
            }
        }

        match e {
            Some(l) => {
                let s = str::from_utf8(&bytes.bytes[1..l+1])?;
                bytes.consume_bytes(l+2);
                validate_json_string(s)?;
                Ok(unsafe { JsonString::from_str_unchecked(s) } )
            },
            None => Err(DecodeError::NeedsMore),
        }
    }

    fn decode_value<'a>(&self, bytes: &mut ConsumableBytes<'a>) -> DecodeResult<'a> {
        match bytes.next() {
            Some(b'n') => {
                bytes.expect_bytes(b"null")?;
                Ok(Token::Terminated(JsonToken::JsNull))
            },
            Some(b'f') => {
                bytes.expect_bytes(b"false")?;
                Ok(Token::Terminated(JsonToken::JsBoolean(false)))
            },
            Some(b't') => {
                bytes.expect_bytes(b"true")?;
                Ok(Token::Terminated(JsonToken::JsBoolean(true)))
            },
            Some(b'-') => {
                let mut bs = bytes.clone();
                bs.consume_bytes(1);
                self.number_of_len(bytes, bs.unsigned_number()? + 1)
            },
            Some(b'0') => {
                let mut bs = bytes.clone();
                bs.consume_bytes(1);
                self.number_of_len(bytes, bs.decimal_point()? + 1)
            },
            Some(b'1'...b'9') => {
                let mut bs = bytes.clone();
                bs.consume_bytes(1);
                self.number_of_len(bytes, bs.int_digits()? + 1)
            },
            Some(b'"') => {
                Ok(Token::Terminated(JsonToken::JsString(self.decode_str(bytes)?)))
            },
            Some(b'{') => {
                bytes.consume_bytes(1);
                Ok(Token::Terminated(JsonToken::StartObject))
            },
            Some(b'}') => {
                bytes.consume_bytes(1);
                Ok(Token::Terminated(JsonToken::EndObject))
            },
            Some(b'[') => {
                bytes.consume_bytes(1);
                Ok(Token::Terminated(JsonToken::StartArray))
            },
            Some(b']') => {
                bytes.consume_bytes(1);
                Ok(Token::Terminated(JsonToken::EndArray))
            },
            Some(c) => Err(DecodeError::UnexpectedByte(c)),
            None => {
                if self.stack.len() > 0 {
                    Err(DecodeError::NeedsMore)
                } else {
                    Ok(Token::EndOfStream)
                }
            },
        }
    }

    /// Decodes bytes into JsonTokens. N.B. the returned token can reference the input bytes.
    pub fn decode<'a>(&mut self, bytes: &mut ConsumableBytes<'a>) -> DecodeResult<'a> {
        bytes.consume_ws();
        match (self.stack.last(), &self.previous) {
            (Some(Context::Object), TokenType::ObjectComma) => {
                match bytes.next()  {
                    Some(b'"') => {
                        let res = Ok(Token::Terminated(JsonToken::JsKey(self.decode_str(bytes)?)));
                        self.previous = TokenType::Key;
                        return res;
                    },
                    Some(c) => {
                        return Err(DecodeError::UnexpectedByte(c));
                    },
                    None => {
                        return Err(DecodeError::NeedsMore);
                    },
                }
            },
            (Some(Context::Object), TokenType::Value) => {
                match bytes.next() {
                    Some(b',') => {
                        bytes.consume_bytes(1);
                        self.previous = TokenType::ObjectComma;
                        bytes.consume_ws();
                        match bytes.next()  {
                            Some(b'"') => {
                                let res = Ok(Token::Terminated(JsonToken::JsKey(self.decode_str(bytes)?)));
                                self.previous = TokenType::Key;
                                return res;
                            },
                            Some(c) => {
                                return Err(DecodeError::UnexpectedByte(c));
                            },
                            None => {
                                return Err(DecodeError::NeedsMore);
                            },
                        }
                    },
                    Some(b'}') => {
                        bytes.consume_bytes(1);
                        self.stack.pop();
                        self.previous = TokenType::Value;
                        return Ok(Token::Terminated(JsonToken::EndObject));
                    },
                    Some(c) => {
                        return Err(DecodeError::UnexpectedByte(c));
                    },
                    None => {
                        return Err(DecodeError::NeedsMore);
                    },
                }
            },
            (Some(Context::Object), TokenType::ObjectStart) => {
                match bytes.next() {
                    Some(b'"') => {
                        let res = Ok(Token::Terminated(JsonToken::JsKey(self.decode_str(bytes)?)));
                        self.previous = TokenType::Key;
                        return res;
                    },
                    Some(b'}') => {
                        bytes.consume_bytes(1);
                        self.stack.pop();
                        self.previous = TokenType::Value;
                        return Ok(Token::Terminated(JsonToken::EndObject));
                    },
                    Some(c) => {
                        return Err(DecodeError::UnexpectedByte(c));
                    },
                    None => {
                        return Err(DecodeError::NeedsMore);
                    },
                }
            },
            (Some(Context::Object), TokenType::Key) => {
                match bytes.next() {
                    Some(b':') => {
                        bytes.consume_bytes(1);
                        self.previous = TokenType::ObjectColon;
                    },
                    Some(c) => {
                        return Err(DecodeError::UnexpectedByte(c));
                    },
                    None => {
                        return Err(DecodeError::NeedsMore);
                    },
                }
                bytes.consume_ws();
            },
            (Some(Context::Array), TokenType::Value) => {
                match bytes.next() {
                    Some(b',') => {
                        bytes.consume_bytes(1);
                        self.previous = TokenType::ArrayComma;
                    },
                    Some(b']') => {
                        bytes.consume_bytes(1);
                        self.stack.pop();
                        self.previous = TokenType::Value;
                        return Ok(Token::Terminated(JsonToken::EndArray));
                    },
                    Some(c) => {
                        return Err(DecodeError::UnexpectedByte(c));
                    },
                    None => {
                        return Err(DecodeError::NeedsMore);
                    },
                }
                bytes.consume_ws();
            },
            (_, _) => {},
        }

        let res = self.decode_value(bytes)?;
        let prev = self.previous;
        self.previous = match res {
            Token::Terminated(JsonToken::StartObject) | Token::Unterminated(JsonToken::StartObject) => {
                self.stack.push(Context::Object);
                TokenType::ObjectStart
            },
            Token::Terminated(JsonToken::EndObject) | Token::Unterminated(JsonToken::EndObject) => {
                //if self.previous != TokenType::ObjectStart {
                //    return Err(DecodeError::UnexpectedByte(b'}'));
                //}
                self.stack.pop();
                TokenType::Value
            },
            Token::Terminated(JsonToken::StartArray) | Token::Unterminated(JsonToken::StartArray) => {
                self.stack.push(Context::Array);
                TokenType::ArrayStart
            },
            Token::Terminated(JsonToken::EndArray) | Token::Unterminated(JsonToken::EndArray) => {
                if self.previous != TokenType::ArrayStart {
                    return Err(DecodeError::UnexpectedByte(b']'));
                }
                self.stack.pop();
                TokenType::Value
            },
            Token::Terminated(_) => {
                TokenType::Value
            },
            Token::Unterminated(_) =>  {
                // Don't update after unterminated tokens
                prev
            },
            Token::EndOfStream =>  {
                TokenType::Value
            }
        };
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use hamcrest2::prelude::*;
    use super::{JsonDecoder, ConsumableBytes, JsonToken, DecodeError, Token, DecodeResult};
    use serde_json::{Value, Map, Number};
    use std::str::{FromStr};
    use std::str;

    #[derive(Debug)]
    enum ConsumedValue {
        Value(Value),
        EndArray,
    }

    impl ConsumedValue {
        fn unwrap(self) -> Value {
            match self {
                ConsumedValue::Value(v) => v,
                ConsumedValue::EndArray => panic!("Unexpected EndArray"),
            }
        }
    }

    #[derive(Debug)]
    struct SyncConsumableBytes<'a> {
        bytes: &'a [u8],
        start: usize,
        end: usize,
    }

    #[derive(Debug)]
    struct ConsumeableByteAdvance<'a, 'b> {
        source: &'b mut SyncConsumableBytes<'a>,
        bytes: ConsumableBytes<'a>,
        in_len: usize,
    }

    impl<'a, 'b> Drop for ConsumeableByteAdvance<'a, 'b> {
        fn drop(&mut self) {
            self.source.start += self.in_len - self.bytes.len();
        }
    }

    impl<'a, 'b> ConsumeableByteAdvance<'a, 'b> {
        fn new(source: &'b mut SyncConsumableBytes<'a>) -> ConsumeableByteAdvance<'a, 'b> {
            let in_len = source.end - source.start;
            let bytes = ConsumableBytes::new(&source.bytes[source.start..source.end]);
            ConsumeableByteAdvance{
                source,
                bytes,
                in_len,
            }
        }

        fn bytes(&mut self) -> &mut ConsumableBytes<'a> {
            &mut self.bytes
        }
    }

    impl<'a> SyncConsumableBytes<'a> {
        fn new(bytes: &'a [u8]) -> SyncConsumableBytes<'a> {
            SyncConsumableBytes{
                bytes,
                start: 0,
                end: 0,
            }
        }

        fn new_non_incremental(bytes: &'a [u8]) -> SyncConsumableBytes<'a> {
            let end = bytes.len();
            SyncConsumableBytes{
                bytes,
                start: 0,
                end,
            }
        }

        fn raw_next(&mut self, decoder: &mut JsonDecoder) -> DecodeResult<'a> {
            let mut bytes = ConsumeableByteAdvance::new(self);
            decoder.decode(bytes.bytes())
        }

        fn next_impl_end(&mut self, decoder: &mut JsonDecoder) -> Result<JsonToken<'a>, DecodeError> {
            self.raw_next(decoder)?.unwrap_or(DecodeError::NeedsMore)
        }

        fn next_impl(&mut self, decoder: &mut JsonDecoder) -> Result<JsonToken<'a>, DecodeError> {
            self.raw_next(decoder)?.terminated_or(DecodeError::NeedsMore)
        }

        fn next(&mut self, decoder: &mut JsonDecoder) -> Result<JsonToken<'a>, DecodeError> {
            while self.end < self.bytes.len() {
                match self.next_impl(decoder) {
                    Err(DecodeError::NeedsMore) => {
                        self.end += 1;
                    },
                    o => {
                        dbg!(&o);
                        return o;
                    },
                }
            }
            self.next_impl_end(decoder)
        }
    }

    fn consume_value_impl2<'a>(decoder: &mut JsonDecoder, scb: &mut SyncConsumableBytes<'a>) -> Result<ConsumedValue, DecodeError> {
        dbg!(&scb);
        let tok = scb.next(decoder)?;
        Ok(match tok {
            JsonToken::JsNull => {ConsumedValue::Value(Value::Null)},
            JsonToken::JsBoolean(b) => {ConsumedValue::Value(Value::Bool(b))},
            JsonToken::JsNumber(s) => {
                ConsumedValue::Value(
                    Value::Number({
                        println!("parsing: {:?}", s);
                        Number::from_str(s).expect("Should be able to read JSON number from string.")
                    })
                )
            },
            JsonToken::JsString(jsstr) => {ConsumedValue::Value(Value::String(jsstr.into()))},
            JsonToken::StartArray => {
                let mut res = vec![];
                loop {
                    match consume_value_impl2(decoder, scb)? {
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
                    {
                        match scb.next(decoder)? {
                            JsonToken::JsKey(k) => {
                                res.insert(k.into(), consume_value_impl2(decoder, scb)?.unwrap());
                            },
                            JsonToken::EndObject => {
                                break;
                            },
                            t => { panic!("Unexpected token while parsing objects: {:?}", t); }
                        }
                    }
                }
                ConsumedValue::Value(Value::Object(res))
            },
            unexp => { panic!("Unexpected js token {:?}", unexp); },
        })
    }

    fn consume_value2<'a>(decoder: &mut JsonDecoder, bytes: &'a [u8]) -> Result<Value, DecodeError>
    {
        let mut scb = SyncConsumableBytes::new_non_incremental(bytes);
        Ok(consume_value_impl2(decoder, &mut scb)?.unwrap())
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
        let mut fulldecoder = JsonDecoder::new();
        let qjsonrs = consume_value2(&mut fulldecoder, input.as_bytes()).map(normalize_value);
        let mut decoder = JsonDecoder::new();
        let mut scb = SyncConsumableBytes::new(input.as_bytes());
        let resp = consume_value_impl2(&mut decoder, &mut scb);
        match (resp, false) {
            (Err(e), _) => {
                assert_that!(e, eq(qjsonrs.unwrap_err()));
                return;
            }
            (Ok(v), _) => {
                assert_that!(normalize_value(v.unwrap()), eq(qjsonrs.unwrap()));
                return;
            }
        };
    }

    fn compare_serde_with_qjsonrs_impl(input: &str) -> Option<DecodeError> {
        validate_chunked(input);
        let mut decoder = JsonDecoder::new();
        let mut scb = SyncConsumableBytes::new_non_incremental(input.as_bytes());
        match Value::from_str(input).map(normalize_value) {
            Ok(serde) => {
                let qjsonrs = normalize_value(consume_value_impl2(&mut decoder, &mut scb).expect("Should be successful since serde was successful.").unwrap());
                assert_that!(qjsonrs, eq(serde));
                match scb.raw_next(&mut decoder) { // consume_value_impl2(&mut decoder, &mut scb) {
                    Ok(Token::Terminated(t)) => {panic!("Unexpected terminated token: {:?} after final parse.", t)}
                    _ => {}
                }
                None
            },
            Err(_) => {
                match consume_value_impl2(&mut decoder, &mut scb) {
                    Err(e) => {
                        Some(e)
                    },
                    _  => {
                        Some(consume_value_impl2(&mut decoder, &mut scb).expect_err("Expected to hit an err case, given serde error in serde parsing."))
                    }
                }
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
    fn string() {
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
        for c in b'\x00'..b'\x7f' {
            if c != b'"' && c != b'\\' {
                let bs = [b'"', c, b'"'];
                let st = str::from_utf8(&bs[..]).expect("ASCII should be valid UTF8");
                println!("Workin on {:?}", st);
                compare_serde_with_qjsonrs(st);
            }
        }
        compare_serde_with_qjsonrs("\"\x00\"");
        compare_serde_with_qjsonrs("\"\n\"");
        compare_serde_with_qjsonrs("\"\r\"");
        compare_serde_with_qjsonrs("\"\t\"");
        compare_serde_with_qjsonrs("\"");
        compare_serde_with_qjsonrs("\"\\");
        compare_serde_with_qjsonrs("\"\\I\"");
        compare_serde_with_qjsonrs("\"\\u");
        compare_serde_with_qjsonrs("\"\\udefg");
        compare_serde_with_qjsonrs("\"\\uDEFG");
        compare_serde_with_qjsonrs("\"\\u-012");
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
    fn number() {
        for sign in vec!["", "-"] {
            for number in vec!["0", "1", "94"] {
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
        compare_serde_with_qjsonrs_err("[,]", DecodeError::UnexpectedByte(b','));
        compare_serde_with_qjsonrs_err("[1,,2]", DecodeError::UnexpectedByte(b','));
        compare_serde_with_qjsonrs_err("[1,2,]", DecodeError::UnexpectedByte(b']'));
    }

    #[test]
    fn objects() {
        compare_serde_with_qjsonrs("{}");
        compare_serde_with_qjsonrs("{\"one\": []}");
        compare_serde_with_qjsonrs("{ \"one\"  : {\"one\":{},\"two\":{\"12\":null}} }");
        compare_serde_with_qjsonrs("{\"a\": {} , \"one\": {\"[]\": [{}, null, {\"a\":[{}]}]}}");
    }
}
