use crate::token::{JsonString, JsonStringParseError, JsonToken};
use std::ops::Add;
use std::str;
use std::str::Utf8Error;

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
/// Error type for decoding
pub enum DecodeError {
    /// Re-run decode with additional input.
    NeedsMore,
    /// More input needed to finish parse, but input bytes marked as end of stream.
    UnexpectedEndOfStream,
    /// Invalid UTF-8 character in input bytes.
    InvalidUtf8,
    /// String contains `\uXXXX` sequence where 0xXXXX is an invalid unicode code point.
    InvalidUnicodeEscape(u32),
    /// Generic error parsing found an invalid byte.
    UnexpectedByte(u8),
}

impl From<Utf8Error> for DecodeError {
    fn from(u: Utf8Error) -> DecodeError {
        match u.error_len() {
            None => DecodeError::NeedsMore,
            Some(_) => DecodeError::InvalidUtf8,
        }
    }
}

struct NumberLength(usize);

impl From<usize> for NumberLength {
    fn from(u: usize) -> NumberLength {
        NumberLength(u)
    }
}

impl Add<usize> for NumberLength {
    type Output = NumberLength;

    fn add(self, other: usize) -> NumberLength {
        NumberLength(self.0 + other)
    }
}

impl NumberLength {
    fn len(&self) -> usize {
        self.0
    }
}

/// Result from decode:
///  - Ok(None)    End of stream.
///  - Ok(Some(T)) Token T in JSON stream.
///  - Some() Token T in JSON stream.
pub type DecodeResult<'a> = Result<Option<JsonToken<'a>>, DecodeError>;

/// A set of bytes that can be consumed during decoding.
#[derive(Clone, Debug)]
pub struct ConsumableBytes<'a> {
    bytes: &'a [u8],
    end_of_stream: bool,
}

fn is_whitespace(c: u8) -> bool {
    match c {
        0x09 | 0x0a | 0x0d | 0x20 => true,
        _ => false,
    }
}

#[derive(Debug)]
enum ConsumeResult<T> {
    Consumed(T),
    EndOfStream,
    EndOfChunk,
}

impl<T: std::fmt::Debug> ConsumeResult<T> {
    fn unwrap(self) -> T {
        match self {
            ConsumeResult::Consumed(t) => t,
            c => panic!("Bad unwrap on ConsumeResult, found {:?}", c),
        }
    }
}

impl<'a> ConsumableBytes<'a> {
    /// Construct a chunk of consumable bytes.
    ///
    /// Constructing in this manner indicates that there are more bytes in the stream. Use
    /// new_end_of_stream if these are the final bytes in the stream.
    pub fn new(bytes: &'a [u8]) -> ConsumableBytes<'a> {
        ConsumableBytes {
            bytes,
            end_of_stream: false,
        }
    }

    /// Construct a chunk of consumable bytes.
    ///
    /// Constructing in this manner indicates that these are the final bytes in the stream.
    pub fn new_end_of_stream(bytes: &'a [u8]) -> ConsumableBytes<'a> {
        ConsumableBytes {
            bytes,
            end_of_stream: true,
        }
    }

    /// Length of the remaining bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Consume n bytes from the beginning of the bytes.
    ///
    /// Panics if `n` is larger than `len()`
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
                    self.bytes
                        .iter()
                        .zip(bs.iter())
                        .find(|(bc, ec)| *bc != *ec)
                        .map(|(bc, _)| *bc)
                        .unwrap(),
                ))
            }
        } else {
            let sublen = self.bytes.len();
            if self.bytes == &bs[..sublen] {
                Err(DecodeError::NeedsMore)
            } else {
                Err(DecodeError::UnexpectedByte(
                    self.bytes
                        .iter()
                        .zip(bs.iter())
                        .find(|(bc, ec)| *bc != *ec)
                        .map(|(bc, _)| *bc)
                        .unwrap(),
                ))
            }
        }
    }

    fn consume_ws(&mut self) {
        let skip = self.bytes.iter().take_while(|c| is_whitespace(**c)).count();
        self.consume_bytes(skip);
    }

    fn next(&self) -> Option<u8> {
        self.bytes.iter().next().cloned()
    }

    fn consume_next(&mut self) -> ConsumeResult<u8> {
        let r = self.next();
        if r.is_some() {
            self.consume_bytes(1);
            ConsumeResult::Consumed(r.unwrap())
        } else if self.end_of_stream {
            ConsumeResult::EndOfStream
        } else {
            ConsumeResult::EndOfChunk
        }
    }

    fn unsigned_number(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            ConsumeResult::Consumed(b'1'...b'9') => Ok(self.int_digits()? + 1),
            ConsumeResult::Consumed(b'0') => Ok(self.decimal_point()? + 1),
            ConsumeResult::Consumed(c) => Err(DecodeError::UnexpectedByte(c)),
            ConsumeResult::EndOfStream => Err(DecodeError::UnexpectedEndOfStream),
            ConsumeResult::EndOfChunk => Err(DecodeError::NeedsMore),
        }
    }

    fn fraction_first_digit(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            ConsumeResult::Consumed(b'0'...b'9') => Ok(self.fraction_digits()? + 1),
            ConsumeResult::Consumed(c) => Err(DecodeError::UnexpectedByte(c)),
            ConsumeResult::EndOfStream => Err(DecodeError::UnexpectedEndOfStream),
            ConsumeResult::EndOfChunk => Err(DecodeError::NeedsMore),
        }
    }

    fn fraction_digits(&mut self) -> Result<NumberLength, DecodeError> {
        let mut i = 0;
        loop {
            match self.consume_next() {
                ConsumeResult::Consumed(b'0'...b'9') => i += 1,
                ConsumeResult::Consumed(b'e') | ConsumeResult::Consumed(b'E') => {
                    return Ok(self.exp()? + i + 1)
                }
                ConsumeResult::Consumed(_) => return Ok(i.into()),
                ConsumeResult::EndOfStream => return Ok(i.into()),
                ConsumeResult::EndOfChunk => return Err(DecodeError::NeedsMore),
            }
        }
    }

    fn exp_first_digit(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            ConsumeResult::Consumed(b'0'...b'9') => Ok(self.exp_digits()? + 1),
            ConsumeResult::Consumed(c) => Err(DecodeError::UnexpectedByte(c)),
            ConsumeResult::EndOfStream => Err(DecodeError::UnexpectedEndOfStream),
            ConsumeResult::EndOfChunk => Err(DecodeError::NeedsMore),
        }
    }

    fn exp_digits(&mut self) -> Result<NumberLength, DecodeError> {
        let mut i = 0;
        loop {
            match self.consume_next() {
                ConsumeResult::Consumed(b'0'...b'9') => {
                    i += 1;
                }
                ConsumeResult::Consumed(_) => return Ok(i.into()),
                ConsumeResult::EndOfStream => return Ok(i.into()),
                ConsumeResult::EndOfChunk => return Err(DecodeError::NeedsMore),
            }
        }
    }

    fn exp(&mut self) -> Result<NumberLength, DecodeError> {
        match self.consume_next() {
            ConsumeResult::Consumed(b'+') | ConsumeResult::Consumed(b'-') => {
                Ok(self.exp_first_digit()? + 1)
            }
            ConsumeResult::Consumed(b'0'...b'9') => Ok(self.exp_digits()? + 1),
            ConsumeResult::Consumed(c) => Err(DecodeError::UnexpectedByte(c)),
            ConsumeResult::EndOfStream => Err(DecodeError::UnexpectedEndOfStream),
            ConsumeResult::EndOfChunk => Err(DecodeError::NeedsMore),
        }
    }

    fn decimal_point(&mut self) -> Result<NumberLength, DecodeError> {
        let c = self.consume_next();
        match c {
            ConsumeResult::Consumed(b'.') => Ok(self.fraction_first_digit()? + 1),
            ConsumeResult::Consumed(b'e') | ConsumeResult::Consumed(b'E') => Ok(self.exp()? + 1),
            ConsumeResult::Consumed(b'0'...b'9') => Err(DecodeError::UnexpectedByte(c.unwrap())),
            ConsumeResult::Consumed(_) => Ok(0.into()),
            ConsumeResult::EndOfStream => Ok(0.into()),
            ConsumeResult::EndOfChunk => Err(DecodeError::NeedsMore),
        }
    }

    fn int_digits(&mut self) -> Result<NumberLength, DecodeError> {
        let mut i = 0;
        loop {
            match self.consume_next() {
                ConsumeResult::Consumed(b'0'...b'9') => i += 1,
                ConsumeResult::Consumed(b'.') => return Ok(self.fraction_first_digit()? + i + 1),
                ConsumeResult::Consumed(b'e') | ConsumeResult::Consumed(b'E') => {
                    return Ok(self.exp()? + i + 1)
                }
                ConsumeResult::Consumed(_) => return Ok(i.into()),
                ConsumeResult::EndOfStream => return Ok(i.into()),
                ConsumeResult::EndOfChunk => return Err(DecodeError::NeedsMore),
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
            stack: vec![],
            previous: TokenType::Value,
        }
    }

    fn number_of_len<'a>(
        &self,
        bytes: &mut ConsumableBytes<'a>,
        nl: NumberLength,
    ) -> DecodeResult<'a> {
        // TODO: consider using from_utf8_unchecked, we will already have validated that the stream
        // is valid ascii at this point.
        let n = nl.len();
        let res = str::from_utf8(&bytes.bytes[..n])?;
        bytes.consume_bytes(n);
        Ok(Some(JsonToken::JsNumber(res)))
    }

    fn decode_str<'a>(
        &self,
        bytes: &mut ConsumableBytes<'a>,
    ) -> Result<JsonString<'a>, DecodeError> {
        let mut i = 1;
        let e;
        loop {
            let r = bytes.bytes[i..]
                .iter()
                .enumerate()
                .find(|(_, x)| **x == b'"');
            match r {
                Some((q, _)) => {
                    let pref = &bytes.bytes[i..i + q];
                    let bs_count = if !pref.is_empty() {
                        let non_bs = pref.iter().enumerate().rfind(|(_, x)| **x != b'\\');
                        let (non_bs_idx, _) = non_bs.map(|(x, c)| (x + 1, c)).unwrap_or((0, &0));
                        pref.len() - non_bs_idx
                    } else {
                        0
                    };
                    if bs_count % 2 == 1 {
                        i += pref.len() + 1;
                    } else {
                        e = Some(i + pref.len() - 1);
                        break;
                    }
                }
                None => {
                    e = None;
                    break;
                }
            }
        }

        match e {
            Some(length) => {
                let string = str::from_utf8(&bytes.bytes[1..=length])?;
                bytes.consume_bytes(length + 2);
                Ok(match JsonString::from_str_ref(string) {
                    Ok(t) => t,
                    Err(JsonStringParseError::UnexpectedByte(b)) => {
                        return Err(DecodeError::UnexpectedByte(b));
                    }
                    Err(JsonStringParseError::BadUnicodeEscape(u)) => {
                        return Err(DecodeError::InvalidUnicodeEscape(u));
                    }
                    Err(JsonStringParseError::EarlyTermination) => {
                        return Err(DecodeError::UnexpectedByte(b'\"'));
                    }
                })
            }
            None => Err(DecodeError::NeedsMore),
        }
    }

    fn decode_value<'a>(&self, bytes: &mut ConsumableBytes<'a>) -> DecodeResult<'a> {
        match bytes.next() {
            Some(b'n') => {
                bytes.expect_bytes(b"null")?;
                Ok(Some(JsonToken::JsNull))
            }
            Some(b'f') => {
                bytes.expect_bytes(b"false")?;
                Ok(Some(JsonToken::JsBoolean(false)))
            }
            Some(b't') => {
                bytes.expect_bytes(b"true")?;
                Ok(Some(JsonToken::JsBoolean(true)))
            }
            Some(b'-') => {
                let mut bs = bytes.clone();
                bs.consume_bytes(1);
                self.number_of_len(bytes, bs.unsigned_number()? + 1)
            }
            Some(b'0') => {
                let mut bs = bytes.clone();
                bs.consume_bytes(1);
                self.number_of_len(bytes, bs.decimal_point()? + 1)
            }
            Some(b'1'...b'9') => {
                let mut bs = bytes.clone();
                bs.consume_bytes(1);
                self.number_of_len(bytes, bs.int_digits()? + 1)
            }
            Some(b'"') => Ok(Some(JsonToken::JsString(self.decode_str(bytes)?))),
            Some(b'{') => {
                bytes.consume_bytes(1);
                Ok(Some(JsonToken::StartObject))
            }
            Some(b'}') => {
                bytes.consume_bytes(1);
                Ok(Some(JsonToken::EndObject))
            }
            Some(b'[') => {
                bytes.consume_bytes(1);
                Ok(Some(JsonToken::StartArray))
            }
            Some(b']') => {
                bytes.consume_bytes(1);
                Ok(Some(JsonToken::EndArray))
            }
            Some(c) => Err(DecodeError::UnexpectedByte(c)),
            None => {
                if self.stack.is_empty() {
                    Ok(None)
                } else {
                    Err(DecodeError::NeedsMore)
                }
            }
        }
    }

    /// Decodes bytes into JsonTokens. N.B. The returned token can reference the input bytes.
    ///
    /// Fully decoded bytes will be consumed from bytes, however, unconsumed bytes will remain.
    /// N.B.
    ///  If this function returns DecodeError::NeedsMore, in subsequent calls to decode, whatever
    ///  bytes are passed to decode must start with bytes.remaining() from the previous call.
    ///  
    ///  If this is not done, it is highly likely this function will panic on next invocation.
    pub fn decode<'a>(&mut self, bytes: &mut ConsumableBytes<'a>) -> DecodeResult<'a> {
        let r = self.decode_impl(bytes);
        if let (Err(DecodeError::NeedsMore), true) = (&r, bytes.end_of_stream) {
            Err(DecodeError::UnexpectedEndOfStream)
        } else if let (Ok(None), false) = (&r, bytes.end_of_stream) {
            Err(DecodeError::NeedsMore)
        } else {
            r
        }
    }

    fn decode_impl<'a>(&mut self, bytes: &mut ConsumableBytes<'a>) -> DecodeResult<'a> {
        bytes.consume_ws();
        match (self.stack.last(), &self.previous) {
            (Some(Context::Object), TokenType::ObjectComma) => match bytes.next() {
                Some(b'"') => {
                    let res = Ok(Some(JsonToken::JsKey(self.decode_str(bytes)?)));
                    self.previous = TokenType::Key;
                    return res;
                }
                Some(c) => {
                    return Err(DecodeError::UnexpectedByte(c));
                }
                None => {
                    return Err(DecodeError::NeedsMore);
                }
            },
            (Some(Context::Object), TokenType::Value) => match bytes.next() {
                Some(b',') => {
                    bytes.consume_bytes(1);
                    self.previous = TokenType::ObjectComma;
                    bytes.consume_ws();
                    match bytes.next() {
                        Some(b'"') => {
                            let res = Ok(Some(JsonToken::JsKey(self.decode_str(bytes)?)));
                            self.previous = TokenType::Key;
                            return res;
                        }
                        Some(c) => {
                            return Err(DecodeError::UnexpectedByte(c));
                        }
                        None => {
                            return Err(DecodeError::NeedsMore);
                        }
                    }
                }
                Some(b'}') => {
                    bytes.consume_bytes(1);
                    self.stack.pop();
                    self.previous = TokenType::Value;
                    return Ok(Some(JsonToken::EndObject));
                }
                Some(c) => {
                    return Err(DecodeError::UnexpectedByte(c));
                }
                None => {
                    return Err(DecodeError::NeedsMore);
                }
            },
            (Some(Context::Object), TokenType::ObjectStart) => match bytes.next() {
                Some(b'"') => {
                    let res = Ok(Some(JsonToken::JsKey(self.decode_str(bytes)?)));
                    self.previous = TokenType::Key;
                    return res;
                }
                Some(b'}') => {
                    bytes.consume_bytes(1);
                    self.stack.pop();
                    self.previous = TokenType::Value;
                    return Ok(Some(JsonToken::EndObject));
                }
                Some(c) => {
                    return Err(DecodeError::UnexpectedByte(c));
                }
                None => {
                    return Err(DecodeError::NeedsMore);
                }
            },
            (Some(Context::Object), TokenType::Key) => {
                match bytes.next() {
                    Some(b':') => {
                        bytes.consume_bytes(1);
                        self.previous = TokenType::ObjectColon;
                    }
                    Some(c) => {
                        return Err(DecodeError::UnexpectedByte(c));
                    }
                    None => {
                        return Err(DecodeError::NeedsMore);
                    }
                }
                bytes.consume_ws();
            }
            (Some(Context::Array), TokenType::Value) => {
                match bytes.next() {
                    Some(b',') => {
                        bytes.consume_bytes(1);
                        self.previous = TokenType::ArrayComma;
                    }
                    Some(b']') => {
                        bytes.consume_bytes(1);
                        self.stack.pop();
                        self.previous = TokenType::Value;
                        return Ok(Some(JsonToken::EndArray));
                    }
                    Some(c) => {
                        return Err(DecodeError::UnexpectedByte(c));
                    }
                    None => {
                        return Err(DecodeError::NeedsMore);
                    }
                }
                bytes.consume_ws();
            }
            (_, _) => {}
        }

        let res = self.decode_value(bytes)?;
        self.previous = match res {
            Some(JsonToken::StartObject) => {
                self.stack.push(Context::Object);
                TokenType::ObjectStart
            }
            Some(JsonToken::EndObject) => {
                if self.previous != TokenType::ObjectStart {
                    return Err(DecodeError::UnexpectedByte(b'}'));
                }
                self.stack.pop();
                TokenType::Value
            }
            Some(JsonToken::StartArray) => {
                self.stack.push(Context::Array);
                TokenType::ArrayStart
            }
            Some(JsonToken::EndArray) => {
                if self.previous != TokenType::ArrayStart {
                    return Err(DecodeError::UnexpectedByte(b']'));
                }
                self.stack.pop();
                TokenType::Value
            }
            Some(_) => TokenType::Value,
            None => TokenType::Value,
        };
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::{ConsumableBytes, DecodeError, DecodeResult, JsonDecoder, JsonToken};
    use hamcrest2::prelude::*;
    use serde_json::{from_reader, Map, Number, Value};
    use std::io::Cursor;
    use std::str;
    use std::str::FromStr;

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
        done: bool,
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
        fn new(
            source: &'b mut SyncConsumableBytes<'a>,
            end: bool,
        ) -> ConsumeableByteAdvance<'a, 'b> {
            let in_len = source.end - source.start;
            let bytes = if end {
                ConsumableBytes::new_end_of_stream(&source.bytes[source.start..source.end])
            } else {
                ConsumableBytes::new(&source.bytes[source.start..source.end])
            };
            ConsumeableByteAdvance {
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
            SyncConsumableBytes {
                bytes,
                start: 0,
                end: 0,
                done: false,
            }
        }

        fn new_non_incremental(bytes: &'a [u8]) -> SyncConsumableBytes<'a> {
            let end = bytes.len();
            SyncConsumableBytes {
                bytes,
                start: 0,
                end,
                done: false,
            }
        }

        fn raw_next(&mut self, decoder: &mut JsonDecoder, end: bool) -> DecodeResult<'a> {
            let mut bytes = ConsumeableByteAdvance::new(self, end);
            let n = decoder.decode(bytes.bytes());
            n
        }

        fn next_impl_end(
            &mut self,
            decoder: &mut JsonDecoder,
        ) -> Result<JsonToken<'a>, DecodeError> {
            if self.done {
                Err(DecodeError::NeedsMore)
            } else {
                match self.raw_next(decoder, true)? {
                    Some(t) => Ok(t),
                    _ => Err(DecodeError::NeedsMore),
                }
            }
        }

        fn next_impl(&mut self, decoder: &mut JsonDecoder) -> Result<JsonToken<'a>, DecodeError> {
            if self.done {
                Err(DecodeError::NeedsMore)
            } else {
                self.raw_next(decoder, false)?.ok_or(DecodeError::NeedsMore)
            }
        }

        fn next(&mut self, decoder: &mut JsonDecoder) -> Result<JsonToken<'a>, DecodeError> {
            while self.end < self.bytes.len() {
                match self.next_impl(decoder) {
                    Err(DecodeError::NeedsMore) => {
                        self.end += 1;
                    }
                    o => {
                        return o;
                    }
                }
            }
            let a = self.next_impl_end(decoder);
            a
        }
    }

    fn consume_value_impl2<'a>(
        decoder: &mut JsonDecoder,
        scb: &mut SyncConsumableBytes<'a>,
    ) -> Result<ConsumedValue, DecodeError> {
        let tok = scb.next(decoder)?;
        Ok(match tok {
            JsonToken::JsNull => ConsumedValue::Value(Value::Null),
            JsonToken::JsBoolean(b) => ConsumedValue::Value(Value::Bool(b)),
            JsonToken::JsNumber(s) => {
                ConsumedValue::Value(Value::Number({
                    // I want to do: .expect("Should be able to read JSON number from string.")
                    //
                    // But sadly... serde_json cannot handle super large number, fake a
                    // different error in that case for now.
                    match Number::from_str(s) {
                        Ok(o) => o,
                        Err(_) => {
                            return Err(DecodeError::UnexpectedByte(b'%'));
                        }
                    }
                }))
            }
            JsonToken::JsString(jsstr) => ConsumedValue::Value(Value::String(jsstr.into())),
            JsonToken::StartArray => {
                let mut res = vec![];
                loop {
                    match consume_value_impl2(decoder, scb)? {
                        ConsumedValue::Value(v) => {
                            res.push(v);
                        }
                        ConsumedValue::EndArray => {
                            break;
                        }
                    }
                }
                ConsumedValue::Value(Value::Array(res))
            }
            JsonToken::EndArray => ConsumedValue::EndArray,
            JsonToken::StartObject => {
                let mut res = Map::new();
                loop {
                    {
                        match scb.next(decoder)? {
                            JsonToken::JsKey(k) => {
                                res.insert(k.into(), consume_value_impl2(decoder, scb)?.unwrap());
                            }
                            JsonToken::EndObject => {
                                break;
                            }
                            t => {
                                panic!("Unexpected token while parsing objects: {:?}", t);
                            }
                        }
                    }
                }
                ConsumedValue::Value(Value::Object(res))
            }
            unexp => {
                panic!("Unexpected js token {:?}", unexp);
            }
        })
    }

    fn consume_value2<'a>(
        decoder: &mut JsonDecoder,
        bytes: &'a [u8],
    ) -> Result<Value, DecodeError> {
        let mut scb = SyncConsumableBytes::new_non_incremental(bytes);
        Ok(consume_value_impl2(decoder, &mut scb)?.unwrap())
    }

    fn normalize_value(v: Value) -> Value {
        match v {
            Value::Array(a) => Value::Array(a.iter().map(|v| normalize_value(v.clone())).collect()),
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, v)| (k.clone(), normalize_value(v.clone())))
                    .collect(),
            ),
            Value::Number(n) => {
                if n.as_f64() == Some(0.0) {
                    json!(0)
                } else {
                    Value::Number(n)
                }
            }
            d => d,
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
        let mut c = Cursor::new(input.as_bytes());
        let v: Result<Value, _> = from_reader(&mut c);
        match v.map(normalize_value) {
            Ok(serde) => {
                let qjsonrs = normalize_value(
                    consume_value_impl2(&mut decoder, &mut scb)
                        .expect("Should be successful since serde was successful.")
                        .unwrap(),
                );
                assert_that!(qjsonrs, eq(serde));
                match scb.raw_next(&mut decoder, true) {
                    Ok(Some(t)) => {
                        panic!("Unexpected terminated token: {:?} after final parse.", t)
                    }
                    _ => {}
                }
                None
            }
            Err(se) => {
                match consume_value_impl2(&mut decoder, &mut scb) {
                    Err(e) => Some(e),
                    _ => {
                        let trailing = format!("{}", se).contains("trailing characters");
                        if !trailing {
                            Some(consume_value_impl2(&mut decoder, &mut scb).expect_err(
                                "Expected to hit an err case, given serde error in serde parsing.",
                            ))
                        } else {
                            // In cases of trailing characters serde can report an error, but we
                            // don't have an error in qjsonrs where we want to be able to consume
                            // streams of json values.
                            None
                        }
                    }
                }
            }
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
        compare_serde_with_qjsonrs("\"my \\f string\"");
        compare_serde_with_qjsonrs("\"my \\t string\"");
        compare_serde_with_qjsonrs("\"my \\u0022 string\"");
        compare_serde_with_qjsonrs("\"my \\u263A smiley\"");
        compare_serde_with_qjsonrs("\"\\u0000\"");
    }

    #[test]
    fn bad_string() {
        compare_serde_with_qjsonrs("\" \"");
        for c in b'\x00'..b'\x7f' {
            if c != b'"' && c != b'\\' {
                let bs = [b'"', c, b'"'];
                let st = str::from_utf8(&bs[..]).expect("ASCII should be valid UTF8");
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
        compare_serde_with_qjsonrs("02");
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

    #[test]
    fn crashes() {
        compare_serde_with_qjsonrs("[1, 2, {\"cat\": null, \"bob\": true}, false, [}]");
        compare_serde_with_qjsonrs("[1, 2, {\"cat\": null, \"b\u{007f}b\": true}, false, []]");
        compare_serde_with_qjsonrs("[1, 2, {\"cat\": null, \"bob\": true}, false, []]6");
        compare_serde_with_qjsonrs("[1,-0, {\"cat\": null, \"bob\": true}, false, []]");
        compare_serde_with_qjsonrs("[1,-0, {\"cat\": -0, \"bob\": true}, false, []]");
        compare_serde_with_qjsonrs("[999E99999999\u{0018} nul , \"bob\": truc}, @alsz,\u{000b}[]]");
        compare_serde_with_qjsonrs("[[1");
        compare_serde_with_qjsonrs("[1, 2, {\"c\\u\": null, \"bob\": true}, false, []]");
        compare_serde_with_qjsonrs(r#""\\""#);
        compare_serde_with_qjsonrs("\"\u{001f}\" 2");
        compare_serde_with_qjsonrs("\"\\\\\\udEEEEEEEEE\"");
    }
}
