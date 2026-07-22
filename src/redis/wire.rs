use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use redis_protocol::resp2::types::BytesFrame as Resp2Frame;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
pub(crate) struct BufferedReader<R> {
    pub(crate) inner: R,
    pub(crate) buffer: BytesMut,
    pub(crate) max_frame_bytes: usize,
}

impl<R> BufferedReader<R> {
    pub(crate) fn new(inner: R, max_frame_bytes: usize) -> Self {
        Self {
            inner,
            buffer: BytesMut::new(),
            max_frame_bytes,
        }
    }
}

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
    Null,
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
            Self::Null => "null",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RedisFrame {
    pub(crate) raw: Bytes,
    pub(crate) kind: RedisFrameKind,
}

pub(crate) async fn read_frame<R>(reader: &mut BufferedReader<R>) -> Result<Option<RedisFrame>>
where
    R: AsyncRead + Unpin,
{
    loop {
        match redis_protocol::resp2::decode::decode_bytes_mut(&mut reader.buffer) {
            Ok(Some((frame, _consumed, raw))) => {
                return Ok(Some(RedisFrame {
                    raw,
                    kind: resp2_kind(&frame),
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

fn resp2_kind(frame: &Resp2Frame) -> RedisFrameKind {
    match frame {
        Resp2Frame::SimpleString(_) => RedisFrameKind::SimpleString,
        Resp2Frame::Error(_) => RedisFrameKind::Error,
        Resp2Frame::Integer(_) => RedisFrameKind::Integer,
        Resp2Frame::BulkString(_) => RedisFrameKind::BulkString,
        Resp2Frame::Array(_) => RedisFrameKind::Array,
        Resp2Frame::Null => RedisFrameKind::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn parse_frame(raw: &'static [u8]) -> RedisFrame {
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(raw).await.unwrap();
        writer.shutdown().await.unwrap();
        read_frame(&mut BufferedReader::new(reader, 1024))
            .await
            .unwrap()
            .unwrap()
    }

    #[test]
    fn parses_binary_safe_redis_command() {
        let command = redis_command(&Bytes::from_static(
            b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$3\r\na\0b\r\n",
        ))
        .unwrap();
        assert_eq!(command.name, "SET");
        assert_eq!(command.args, vec![b"key".to_vec(), b"a\0b".to_vec()]);
    }

    #[tokio::test]
    async fn parses_resp2_null_bulk_string() {
        let frame = parse_frame(b"$-1\r\n").await;

        assert_eq!(frame.kind, RedisFrameKind::Null);
        assert_eq!(frame.raw, Bytes::from_static(b"$-1\r\n"));
    }

    #[tokio::test]
    async fn parses_resp2_null_array() {
        let frame = parse_frame(b"*-1\r\n").await;

        assert_eq!(frame.kind, RedisFrameKind::Null);
        assert_eq!(frame.raw, Bytes::from_static(b"*-1\r\n"));
    }

    #[tokio::test]
    async fn parses_resp2_array_containing_nulls() {
        let frame = parse_frame(b"*2\r\n$-1\r\n$-1\r\n").await;

        assert_eq!(frame.kind, RedisFrameKind::Array);
        assert_eq!(frame.raw, Bytes::from_static(b"*2\r\n$-1\r\n$-1\r\n"));
    }

    #[tokio::test]
    async fn rejects_resp3_null_frame() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(b"_\r\n").await.unwrap();
        writer.shutdown().await.unwrap();

        let error = read_frame(&mut BufferedReader::new(reader, 1024))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("invalid Redis RESP frame"));
    }
}
