/// A raw JSON string (with escapes).
#[derive(Debug, PartialEq)]
pub struct JsonString<'a> {
    raw: &'a str,
}

#[derive(Debug)]
pub enum JsonStringParseError {
    UnexpectedByte(u8),
    BadUnicodeEscape(u32),
    EarlyTermination,
}

fn is_json_control(c: char) -> bool {
    c.is_ascii_control() && c != '\x7f'
}

impl<'a> JsonString<'a> {
    // TODO: expose a safe version that errors out if str is an invalid json string (bad escape
    // code, newlines, NULL).
    /// Unsafely construct a JsonString from a raw str.
    ///
    /// unsafe because it assumes `s` is a valid JSON string (all control chars escaped, no invalid
    /// escapes, no un-escaped '"')
    pub unsafe fn from_str_unchecked(s: &'a str) -> JsonString<'a> {
        JsonString { raw: s }
    }

    /// Get the raw underlying str for this JsonString (no escapes will have been applied).
    pub fn into_raw_str(self) -> &'a str {
        self.raw
    }

    /// Safely construct a JsonString from a raw string.
    pub fn from_str_ref(s: &'a str) -> Result<JsonString<'a>, JsonStringParseError> {
        let mut i = s.chars();
        while let Some(c) = i.next() {
            match (c, is_json_control(c)) {
                (_, true) | ('"', _) => {
                    let mut bytes = [0, 0, 0, 0];
                    c.encode_utf8(&mut bytes[..]);
                    return Err(JsonStringParseError::UnexpectedByte(bytes[0]));
                }
                ('\\', _) => match i.next() {
                    None => {
                        return Err(JsonStringParseError::EarlyTermination);
                    }
                    Some('n') | Some('f') | Some('r') | Some('t') | Some('b') | Some('\\')
                    | Some('"') | Some('/') => {}
                    Some('u') => {
                        let mut cnt = 0;
                        let mut ch: u32 = 0;
                        let mut b = i
                            .by_ref()
                            .take(4)
                            .inspect(|d| {
                                cnt += 1;
                                ch <<= 4;
                                ch += d.to_digit(16).unwrap_or(0);
                            })
                            .skip_while(|c| c.is_digit(16));
                        match b.next() {
                            None => {}
                            Some(c2) => {
                                let mut bytes = [0, 0, 0, 0];
                                c2.encode_utf8(&mut bytes[..]);
                                return Err(JsonStringParseError::UnexpectedByte(bytes[0]));
                            }
                        }
                        if cnt < 4 {
                            return Err(JsonStringParseError::EarlyTermination);
                        }
                        if std::char::from_u32(ch).is_none() {
                            return Err(JsonStringParseError::BadUnicodeEscape(ch));
                        }
                    }
                    Some(c2) => {
                        let mut bytes = [0, 0, 0, 0];
                        c2.encode_utf8(&mut bytes[..]);
                        return Err(JsonStringParseError::UnexpectedByte(bytes[0]));
                    }
                },
                (_, _) => {}
            }
        }
        // Above checks ensure this is safe.
        Ok(unsafe { JsonString::from_str_unchecked(s) })
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
                    let high_nibble = chs.next().expect("unescape unicode off end of string.");
                    let high_mid_nibble = chs.next().expect("unescape unicode off end of string.");
                    let low_mid_nibble = chs.next().expect("unescape unicode off end of string.");
                    let low_nibble = chs.next().expect("unescape unicode off end of string.");
                    let num = ((high_nibble
                        .to_digit(16)
                        .expect("Bad hex digit in \\u escape")
                        as u32)
                        << 12)
                        + ((high_mid_nibble
                            .to_digit(16)
                            .expect("Bad hex digit in \\u escape")
                            as u32)
                            << 8)
                        + ((low_mid_nibble
                            .to_digit(16)
                            .expect("Bad hex digit in \\u escape")
                            as u32)
                            << 4)
                        + (low_nibble
                            .to_digit(16)
                            .expect("Bad hex digit in \\u escape")
                            as u32);
                    std::char::from_u32(num).expect("Bad UTF-8 character in escape sequence")
                }
                '"' => '"',
                'n' => '\n',
                '\\' => '\\',
                '/' => '/',
                'b' => '\x08',
                'r' => '\r',
                'f' => '\x0c',
                't' => '\t',
                unk => panic!("Unhandled escape {:?}", unk),
            })
        } else {
            res.push(c);
        }
    }
    res
}

impl Into<String> for JsonString<'_> {
    fn into(self) -> String {
        // self.raw must be a valid set of escaped JSON string utf-8 bytes.
        unsafe { unescape(self.raw) }
    }
}

/// A token from a stream of JSON.
#[derive(Debug, PartialEq)]
pub enum JsonToken<'a> {
    /// The start of an object, a.k.a. '{'
    StartObject,
    /// The end of an object, a.k.a. '}'
    EndObject,
    /// The start of an array, a.k.a. '['
    StartArray,
    /// The end of an object, a.k.a. ']'
    EndArray,
    /// The token 'null'
    JsNull,
    /// Either 'true' or 'false'
    JsBoolean(bool),
    /// A number, unparsed. i.e. '-123.456e-789'
    JsNumber(&'a str),
    /// A JSON string in a value context.
    JsString(JsonString<'a>),
    /// A JSON string in the context of a key in a JSON object.
    JsKey(JsonString<'a>),
}
