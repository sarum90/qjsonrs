# qjsonrs

A Rust implementation of a JSON Tokenizer.

## Warning

This crate is still very unstable, and probably going to have many breaking
changes while in the 0.x.y versions.

## Motivation

Streaming tokenization for handling large JSON payloads which can be processed
without loading the whole JSON object into memory.

## Iterator interface.

The steam of JsonTokens emitted by this crate unfortunately cannot quite
provide the Iter interface. The reason is: the emitted JsonTokens refer to an
internal buffer of the stream, and thus maintain a reference to the stream.

Also, the iterator returns Results, to enable reporting of IO or JSON encoding errors.

## Example:

```rust
use qjsonrs::{
    JsonStream,
    JsonToken::JsBoolean
}

let mut stream = JsonStream::from_read(file)?;
while Some(t) = stream.next()? {
  match t {
    JsonToken::JsBoolean(b) => { println!("Got JSON boolean: {:?}", b) },
    o => { println!("Got other JSON token boolean: {:?}", o) },
  }
}
println!("Done reading stream.");
```
