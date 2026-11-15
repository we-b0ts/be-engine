//! Bounded RESP2 bulk/array copies; JSON changes only at declared scalar fields.
use super::*;
use redis_protocol::resp2::types::{OwnedFrame, Resp2Frame};

pub(super) const MAX_BYTES: usize = crate::value_limits::MAX_VALUE_BYTES;

pub(super) fn frame(bytes: &[u8]) -> Result<OwnedFrame> {
    ensure!(
        bytes.len() <= MAX_BYTES,
        "Redis read_back response exceeds 64 MiB"
    );
    let (frame, consumed) = redis_protocol::resp2::decode::decode(bytes)?
        .context("incomplete read_back RESP response")?;
    ensure!(
        consumed == bytes.len(),
        "read_back requires exactly one RESP response"
    );
    Ok(frame)
}

pub(super) fn encode(frame: &OwnedFrame) -> Result<Vec<u8>> {
    let size = frame.encode_len(false);
    ensure!(
        size <= MAX_BYTES,
        "derived read_back response exceeds 64 MiB"
    );
    let mut bytes = vec![0; size];
    let written = redis_protocol::resp2::encode::encode(&mut bytes, frame, false)?;
    bytes.truncate(written);
    Ok(bytes)
}

pub(super) fn value(bytes: &[u8], pointer: &str) -> Result<Value> {
    ensure!(
        bytes.len() <= MAX_BYTES,
        "read_back write argument exceeds 64 MiB"
    );
    if pointer.is_empty() {
        return Ok(Value::String(std::str::from_utf8(bytes)?.into()));
    }
    let json = crate::json_value::parse_with_limit(bytes, MAX_BYTES)
        .context("read_back requires complete unique-member JSON")?;
    let selected = json
        .pointer(pointer)
        .context("read_back JSON write field is missing")?;
    ensure!(
        !selected.is_array() && !selected.is_object() && !selected.is_null(),
        "read_back binds non-null JSON scalars only"
    );
    Ok(selected.clone())
}

pub(super) fn successful_write(command: &str, bytes: &[u8]) -> Result<bool> {
    Ok(match (command, frame(bytes)?) {
        ("SET" | "LSET", OwnedFrame::SimpleString(value)) => value == b"OK",
        ("RPUSH", OwnedFrame::Integer(value)) => value > 0,
        _ => false,
    })
}

pub(super) fn transform(
    command: &str,
    original: &[u8],
    mut transform: impl FnMut(&mut Vec<u8>) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut response = frame(original)?;
    match (command, &mut response) {
        (_, OwnedFrame::Null | OwnedFrame::Error(_)) => return Ok(original.to_vec()),
        ("GET", OwnedFrame::BulkString(value)) => transform(value)?,
        ("LRANGE", OwnedFrame::Array(values)) => {
            ensure!(
                values.len() <= 1024,
                "read_back LRANGE exceeds 1024 elements"
            );
            for value in values {
                let OwnedFrame::BulkString(value) = value else {
                    anyhow::bail!("read_back LRANGE requires bulk elements");
                };
                transform(value)?;
            }
        }
        _ => anyhow::bail!("read_back read has an unsupported RESP shape"),
    }
    encode(&response)
}
