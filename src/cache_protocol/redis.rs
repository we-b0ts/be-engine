use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use redis_protocol::resp2::types::BytesFrame as Resp2Frame;
use redis_protocol::resp3::types::BytesFrame as Resp3Frame;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::BufferedReader;

#[derive(Debug, Clone)]
pub(crate) struct RedisCommand {
    pub(crate) name: String,
    pub(crate) args: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedisFrameKind {
    SimpleString,
    Error,
    Integer,
    BulkString,
    Array,
    Map,
    Set,
    Boolean,
    Double,
    BigNumber,
    VerbatimString,
    Null,
    Push,
    Other,
}

impl RedisFrameKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SimpleString => "simple_string",
            Self::Error => "error",
            Self::Integer => "integer",
            Self::BulkString => "bulk_string",
            Self::Array => "array",
            Self::Map => "map",
            Self::Set => "set",
            Self::Boolean => "boolean",
            Self::Double => "double",
            Self::BigNumber => "big_number",
            Self::VerbatimString => "verbatim_string",
            Self::Null => "null",
            Self::Push => "push",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RedisFrame {
    pub(crate) raw: Bytes,
    pub(crate) kind: RedisFrameKind,
}

pub(crate) async fn read_redis_frame<R>(
    reader: &mut BufferedReader<R>,
) -> Result<Option<RedisFrame>>
where
    R: AsyncRead + Unpin,
{
    loop {
        match redis_protocol::resp3::decode::complete::decode_bytes_mut(&mut reader.buffer) {
            Ok(Some((frame, _consumed, raw))) => {
                return Ok(Some(RedisFrame {
                    raw,
                    kind: resp3_kind(&frame),
                }));
            }
            Ok(None) => {}
            Err(err) => return Err(anyhow!(err)).context("invalid Redis RESP frame"),
        }
        if reader.buffer.len() > reader.max_frame_bytes {
            return Err(anyhow!(
                "Redis frame exceeds configured maximum of {} bytes",
                reader.max_frame_bytes
            ));
        }
        let read = reader.inner.read_buf(&mut reader.buffer).await?;
        if read == 0 {
            if reader.buffer.is_empty() {
                return Ok(None);
            }
            return Err(anyhow!(
                "Redis connection closed with an incomplete RESP frame"
            ));
        }
    }
}

pub(crate) fn redis_command(raw: &Bytes) -> Result<RedisCommand> {
    let Some((frame, consumed)) =
        redis_protocol::resp2::decode::decode_bytes(raw).map_err(|err| anyhow!(err))?
    else {
        return Err(anyhow!("incomplete Redis command frame"));
    };
    if consumed != raw.len() {
        return Err(anyhow!("Redis command parser left trailing bytes"));
    }
    let Resp2Frame::Array(values) = frame else {
        return Err(anyhow!("Redis command must be a RESP array"));
    };
    let mut values = values.into_iter();
    let Some(name) = values.next().and_then(resp2_bytes) else {
        return Err(anyhow!("Redis command array has no string command name"));
    };
    let name = std::str::from_utf8(&name)
        .context("Redis command name is not UTF-8")?
        .to_ascii_uppercase();
    let args = values
        .map(|value| {
            resp2_bytes(value).ok_or_else(|| anyhow!("Redis command argument is not a string"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RedisCommand { name, args })
}

fn resp2_bytes(frame: Resp2Frame) -> Option<Vec<u8>> {
    match frame {
        Resp2Frame::BulkString(value) | Resp2Frame::SimpleString(value) => Some(value.to_vec()),
        _ => None,
    }
}

fn resp3_kind(frame: &Resp3Frame) -> RedisFrameKind {
    match frame {
        Resp3Frame::SimpleString { .. } => RedisFrameKind::SimpleString,
        Resp3Frame::SimpleError { .. } | Resp3Frame::BlobError { .. } => RedisFrameKind::Error,
        Resp3Frame::Number { .. } => RedisFrameKind::Integer,
        Resp3Frame::BlobString { .. } | Resp3Frame::ChunkedString(_) => RedisFrameKind::BulkString,
        Resp3Frame::Array { .. } => RedisFrameKind::Array,
        Resp3Frame::Map { .. } => RedisFrameKind::Map,
        Resp3Frame::Set { .. } => RedisFrameKind::Set,
        Resp3Frame::Boolean { .. } => RedisFrameKind::Boolean,
        Resp3Frame::Double { .. } => RedisFrameKind::Double,
        Resp3Frame::BigNumber { .. } => RedisFrameKind::BigNumber,
        Resp3Frame::VerbatimString { .. } => RedisFrameKind::VerbatimString,
        Resp3Frame::Null => RedisFrameKind::Null,
        Resp3Frame::Push { .. } => RedisFrameKind::Push,
        Resp3Frame::Hello { .. } => RedisFrameKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_safe_redis_command() {
        let command = redis_command(&Bytes::from_static(
            b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$3\r\na\0b\r\n",
        ))
        .unwrap();
        assert_eq!(command.name, "SET");
        assert_eq!(command.args, vec![b"key".to_vec(), b"a\0b".to_vec()]);
    }
}
