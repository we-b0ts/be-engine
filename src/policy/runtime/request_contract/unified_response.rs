//! Compatibility access to the native bulk response projection.
use anyhow::{Context, Result, ensure};

pub(crate) fn redis_bulk_payload(raw: &[u8]) -> Result<Option<Vec<u8>>> {
    ensure!(
        raw.len() <= crate::value_limits::MAX_VALUE_BYTES,
        "Redis response value exceeds 64 MiB"
    );
    // RESP3 null has no value, and must retain its own protocol representation.
    if raw == b"_\r\n" {
        return Ok(None);
    }
    let bytes = bytes::Bytes::copy_from_slice(raw);
    let (frame, consumed) = redis_protocol::resp2::decode::decode_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid Redis response: {e}"))?
        .context("incomplete Redis response")?;
    ensure!(
        consumed == bytes.len(),
        "Redis value requires one complete response frame"
    );
    use redis_protocol::resp2::types::BytesFrame;
    match frame {
        BytesFrame::BulkString(value) => Ok(Some(value.to_vec())),
        BytesFrame::Null | BytesFrame::Error(_) => Ok(None),
        _ => anyhow::bail!("selected Redis response does not expose a bulk value"),
    }
}
