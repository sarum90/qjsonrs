
/// A raw JSON string (with escapes).
#[derive(Debug, PartialEq)]
pub struct JsonString<'a> {
    raw: &'a str,
}

// TODO: kill this.
impl<'a> From<&'a str> for JsonString<'a> {
    fn from(s: &'a str) -> JsonString<'a> {
        JsonString{
            raw: s
        }
    }
}

impl<'a> JsonString<'a> {

    // TODO: expose a safe version that errors out if str is an invalid json string (bad escape
    // code, newlines, NULL).
    /// Unsafely construct a JsonString from a raw str.
    ///
    /// unsafe because it assumes `s` is a valid JSON string (all control chars escaped, no invalid
    /// escapes, no un-escaped '"')
    pub unsafe fn from_str_unchecked(s: &'a str) -> JsonString<'a> {
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
                    let num = ((a.to_digit(16).expect("Bad hex digit in \\u escape") as u32) << 12) +
                        ((b.to_digit(16).expect("Bad hex digit in \\u escape") as u32) << 8) +
                        ((c.to_digit(16).expect("Bad hex digit in \\u escape") as u32) << 4) +
                        (d.to_digit(16).expect("Bad hex digit in \\u escape") as u32);
                    std::char::from_u32(num).expect("Bad UTF-8 character in escape sequence")
                },
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
