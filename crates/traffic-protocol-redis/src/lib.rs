pub mod access;
pub mod builtins;
pub mod client_info;
pub mod expiration;
pub mod key_access;
pub mod key_selector;
pub mod key_slots;
pub mod keys;
pub mod message;
pub mod subject;
pub mod values;
use anyhow::{Context, Result, anyhow};
pub use client_info::is_client_library_info;

mod recognition;
use bytes::{Bytes, BytesMut};
pub use recognition::recognize;
use redis_protocol::resp2::types::BytesFrame as Resp2Frame;
use tokio::io::AsyncRead;
use traffic_protocol::FrameDecoder;
use traffic_protocol::io::BufferedReader as FrameBuffer;

#[derive(Debug, Clone)]
pub struct RedisCommand {
    pub name: String,
    pub args: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedisSubscriptionKind {
    Channel,
    Pattern,
    ShardChannel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisPubSubPush {
    pub subscription_kind: RedisSubscriptionKind,
    pub subject: Vec<u8>,
    pub channel: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisFrameKind {
    SimpleString,
    Error,
    Integer,
    BulkString,
    Array,
    Null,
    Other,
}

impl RedisFrameKind {
    pub fn as_str(self) -> &'static str {
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
pub struct RedisFrame {
    pub raw: Bytes,
    pub kind: RedisFrameKind,
}

#[derive(Default)]
pub struct RedisProvider;

#[derive(Default)]
pub struct RedisDecoder;

pub type RedisSession = Box<dyn FrameDecoder<Frame = RedisFrame>>;

impl traffic_protocol::DependencyProvider for RedisProvider {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn evidence(&self) -> Option<std::sync::Arc<dyn traffic_protocol::evidence::EvidenceAdapter>> {
        Some(std::sync::Arc::new(evidence::NativeEvidence))
    }

    fn recognize(&self, probe: traffic_protocol::Probe<'_>) -> traffic_protocol::Recognition {
        recognize(probe)
    }

    fn create_session(&self) -> Result<traffic_protocol::Session> {
        Ok(traffic_protocol::Session::new::<RedisSession>(Box::new(
            RedisDecoder,
        )))
    }
}

impl FrameDecoder for RedisDecoder {
    type Frame = RedisFrame;
    fn encode(&self, frame: &RedisFrame, output: &mut BytesMut) -> Result<()> {
        frame_kind(&frame.raw)?;
        output.extend_from_slice(&frame.raw);
        Ok(())
    }
    fn decode(&mut self, input: &mut BytesMut) -> Result<Option<RedisFrame>> {
        match redis_protocol::resp2::decode::decode_bytes_mut(input) {
            Ok(Some((frame, _, raw))) => Ok(Some(RedisFrame {
                raw,
                kind: resp2_kind(&frame),
            })),
            Ok(None) => Ok(None),
            Err(error) => Err(anyhow!(error)).context("invalid Redis RESP frame"),
        }
    }
}

/// The framework owns buffering while this connection retains its injected
/// native decoder across pipelined requests and server pushes.
pub struct BufferedReader<R> {
    reader: FrameBuffer<R>,
    session: RedisSession,
}

impl<R> BufferedReader<R> {
    pub fn new(inner: R, max_frame_bytes: usize) -> Self {
        Self::with_session(inner, max_frame_bytes, Box::new(RedisDecoder))
    }

    pub fn with_session(inner: R, max_frame_bytes: usize, session: RedisSession) -> Self {
        Self {
            reader: FrameBuffer::new(inner, max_frame_bytes),
            session,
        }
    }

    pub fn into_inner(self) -> R {
        self.reader.inner
    }
}

impl<R> std::ops::Deref for BufferedReader<R> {
    type Target = FrameBuffer<R>;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

impl<R> std::ops::DerefMut for BufferedReader<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reader
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut BufferedReader<R>,
) -> Result<Option<RedisFrame>> {
    traffic_protocol::io::read_frame(&mut reader.reader, reader.session.as_mut()).await
}

pub fn frame_kind(raw: &Bytes) -> Result<RedisFrameKind> {
    let Some((frame, consumed)) =
        redis_protocol::resp2::decode::decode_bytes(raw).map_err(|err| anyhow!(err))?
    else {
        return Err(anyhow!("incomplete Redis response frame"));
    };
    if consumed != raw.len() {
        return Err(anyhow!("Redis response parser left trailing bytes"));
    }
    Ok(resp2_kind(&frame))
}

pub fn redis_command(raw: &Bytes) -> Result<RedisCommand> {
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

pub fn is_pubsub_command(name: &str) -> bool {
    name.eq_ignore_ascii_case("SUBSCRIBE")
        || name.eq_ignore_ascii_case("PSUBSCRIBE")
        || name.eq_ignore_ascii_case("SSUBSCRIBE")
        || name.eq_ignore_ascii_case("UNSUBSCRIBE")
        || name.eq_ignore_ascii_case("PUNSUBSCRIBE")
        || name.eq_ignore_ascii_case("SUNSUBSCRIBE")
}

/// Replace only the subject of an already validated confirmation. Protocol kind
/// and the recorded integer subscription count retain their original values.
pub fn translate_subscription_confirmation(
    command: &RedisCommand,
    raw: &[u8],
    subject: &[u8],
) -> Result<Vec<u8>> {
    validate_subscription_confirmation(command, raw)?;
    let bytes = Bytes::copy_from_slice(raw);
    let (Resp2Frame::Array(values), _) = redis_protocol::resp2::decode::decode_bytes(&bytes)
        .map_err(|err| anyhow!(err))?
        .context("incomplete confirmation")?
    else {
        return Err(anyhow!("subscription confirmation is not an array"));
    };
    let kind = resp2_bytes_ref(&values[0]).context("confirmation kind is absent")?;
    let Resp2Frame::Integer(count) = values[2] else {
        return Err(anyhow!("confirmation count is not an integer"));
    };
    let mut output = format!("*3\r\n${}\r\n", kind.len()).into_bytes();
    output.extend_from_slice(kind);
    output.extend_from_slice(format!("\r\n${}\r\n", subject.len()).as_bytes());
    output.extend_from_slice(subject);
    output.extend_from_slice(format!("\r\n:{count}\r\n").as_bytes());
    Ok(output)
}

pub fn validate_subscription_confirmation(command: &RedisCommand, raw: &[u8]) -> Result<()> {
    if !is_pubsub_command(&command.name) {
        return Err(anyhow!(
            "Redis {} is not a supported subscription command",
            command.name
        ));
    }
    if command.args.len() != 1 {
        return Err(anyhow!(
            "Redis {} confirmation replay requires exactly one subscription argument",
            command.name
        ));
    }

    let raw = Bytes::copy_from_slice(raw);
    let Some((frame, consumed)) =
        redis_protocol::resp2::decode::decode_bytes(&raw).map_err(|err| anyhow!(err))?
    else {
        return Err(anyhow!("incomplete Redis subscription confirmation"));
    };
    if consumed != raw.len() {
        return Err(anyhow!(
            "Redis subscription confirmation contains trailing bytes"
        ));
    }
    let Resp2Frame::Array(values) = frame else {
        return Err(anyhow!(
            "Redis subscription confirmation must be a RESP2 array"
        ));
    };
    if values.len() != 3 {
        return Err(anyhow!(
            "Redis subscription confirmation must contain three elements"
        ));
    }
    let Some(kind) = resp2_bytes_ref(&values[0]) else {
        return Err(anyhow!(
            "Redis subscription confirmation command must be a string"
        ));
    };
    if !kind.eq_ignore_ascii_case(command.name.as_bytes()) {
        return Err(anyhow!(
            "Redis subscription confirmation command does not match {}",
            command.name
        ));
    }
    let Some(subject) = resp2_bytes_ref(&values[1]) else {
        return Err(anyhow!(
            "Redis subscription confirmation subject must be a string"
        ));
    };
    if subject != command.args[0] {
        return Err(anyhow!(
            "Redis subscription confirmation subject does not match the request"
        ));
    }
    let Resp2Frame::Integer(count) = values[2] else {
        return Err(anyhow!(
            "Redis subscription confirmation count must be an integer"
        ));
    };
    let unsubscribing = command.name.eq_ignore_ascii_case("UNSUBSCRIBE")
        || command.name.eq_ignore_ascii_case("PUNSUBSCRIBE")
        || command.name.eq_ignore_ascii_case("SUNSUBSCRIBE");
    if count < 0 || (!unsubscribing && count == 0) {
        return Err(anyhow!(
            "Redis subscription confirmation count must be {}",
            if unsubscribing {
                "nonnegative"
            } else {
                "positive"
            }
        ));
    }
    Ok(())
}

pub fn parse_pubsub_push(raw: &[u8]) -> Result<Option<RedisPubSubPush>> {
    let raw = Bytes::copy_from_slice(raw);
    let Some((frame, consumed)) =
        redis_protocol::resp2::decode::decode_bytes(&raw).map_err(|err| anyhow!(err))?
    else {
        return Err(anyhow!("incomplete Redis Pub/Sub push"));
    };
    if consumed != raw.len() {
        return Err(anyhow!("Redis Pub/Sub push contains trailing bytes"));
    }
    let Resp2Frame::Array(values) = frame else {
        return Ok(None);
    };
    let Some(kind) = values.first().and_then(resp2_bytes_ref) else {
        return Ok(None);
    };
    let (subscription_kind, subject_index, expected_len) = if kind.eq_ignore_ascii_case(b"message")
    {
        (RedisSubscriptionKind::Channel, 1, 3)
    } else if kind.eq_ignore_ascii_case(b"pmessage") {
        (RedisSubscriptionKind::Pattern, 1, 4)
    } else if kind.eq_ignore_ascii_case(b"smessage") {
        (RedisSubscriptionKind::ShardChannel, 1, 3)
    } else {
        return Ok(None);
    };
    if values.len() != expected_len {
        return Err(anyhow!(
            "Redis Pub/Sub push must contain {expected_len} elements"
        ));
    }
    let Some(subject) = values.get(subject_index).and_then(resp2_bytes_ref) else {
        return Err(anyhow!(
            "Redis Pub/Sub push subscription subject must be a string"
        ));
    };
    let channel_index = if subscription_kind == RedisSubscriptionKind::Pattern {
        2
    } else {
        1
    };
    if values
        .get(channel_index)
        .and_then(resp2_bytes_ref)
        .is_none()
        || values.last().and_then(resp2_bytes_ref).is_none()
    {
        return Err(anyhow!(
            "Redis Pub/Sub push channel and payload must be strings"
        ));
    }
    Ok(Some(RedisPubSubPush {
        subscription_kind,
        subject: subject.to_vec(),
        channel: resp2_bytes_ref(&values[channel_index])
            .expect("validated channel")
            .to_vec(),
        payload: resp2_bytes_ref(values.last().expect("validated length"))
            .expect("validated payload")
            .to_vec(),
    }))
}

fn resp2_bytes(frame: Resp2Frame) -> Option<Vec<u8>> {
    match frame {
        Resp2Frame::BulkString(value) | Resp2Frame::SimpleString(value) => Some(value.to_vec()),
        _ => None,
    }
}

fn resp2_bytes_ref(frame: &Resp2Frame) -> Option<&[u8]> {
    match frame {
        Resp2Frame::BulkString(value) | Resp2Frame::SimpleString(value) => Some(value.as_ref()),
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

pub fn encode_array(parts: &[&[u8]]) -> Vec<u8> {
    let mut raw = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        raw.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        raw.extend_from_slice(part);
        raw.extend_from_slice(b"\r\n");
    }
    raw
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

    #[test]
    fn classifies_complete_raw_response() {
        assert_eq!(
            frame_kind(&Bytes::from_static(b"$5\r\nvalue\r\n")).unwrap(),
            RedisFrameKind::BulkString
        );
    }

    #[test]
    fn validates_single_subscription_confirmation() {
        let command = RedisCommand {
            name: "PSUBSCRIBE".to_string(),
            args: vec![b"/0.celery.pidbox".to_vec()],
        };

        validate_subscription_confirmation(
            &command,
            b"*3\r\n$10\r\npsubscribe\r\n$16\r\n/0.celery.pidbox\r\n:1\r\n",
        )
        .unwrap();
    }

    #[test]
    fn rejects_mismatched_subscription_confirmation() {
        let command = RedisCommand {
            name: "SUBSCRIBE".to_string(),
            args: vec![b"events".to_vec()],
        };

        let error = validate_subscription_confirmation(
            &command,
            b"*3\r\n$9\r\nsubscribe\r\n$5\r\nother\r\n:1\r\n",
        )
        .unwrap_err();

        assert!(error.to_string().contains("subject does not match"));
    }

    #[test]
    fn rejects_multiple_subscription_arguments() {
        let command = RedisCommand {
            name: "SSUBSCRIBE".to_string(),
            args: vec![b"one".to_vec(), b"two".to_vec()],
        };

        let error = validate_subscription_confirmation(
            &command,
            b"*3\r\n$10\r\nssubscribe\r\n$3\r\none\r\n:1\r\n",
        )
        .unwrap_err();

        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn validates_single_unsubscription_confirmations_including_zero_count() {
        for name in ["UNSUBSCRIBE", "PUNSUBSCRIBE", "SUNSUBSCRIBE"] {
            let command = RedisCommand {
                name: name.to_string(),
                args: vec![b"a\0b".to_vec()],
            };
            for count in [0, 1, 2] {
                let response = format!(
                    "*3\r\n${}\r\n{}\r\n$3\r\na\0b\r\n:{count}\r\n",
                    name.len(),
                    name.to_ascii_lowercase()
                );
                validate_subscription_confirmation(&command, response.as_bytes()).unwrap();
            }
        }
    }

    #[test]
    fn rejects_unsafe_unsubscription_confirmations() {
        let command = RedisCommand {
            name: "UNSUBSCRIBE".to_string(),
            args: vec![b"events".to_vec()],
        };
        for response in [
            b"*3\r\n$11\r\nunsubscribe\r\n$5\r\nother\r\n:0\r\n".as_slice(),
            b"*3\r\n$12\r\npunsubscribe\r\n$6\r\nevents\r\n:0\r\n",
            b"*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n:-1\r\n",
            b"*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n$1\r\n0\r\n",
            b"*3\r\n$11\r\nunsubscribe\r\n$-1\r\n:0\r\n",
            b"*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n:0\r\n+OK\r\n",
            b"*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n",
            b">3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n:0\r\n",
        ] {
            assert!(validate_subscription_confirmation(&command, response).is_err());
        }
        for args in [vec![], vec![b"events".to_vec(), b"other".to_vec()]] {
            let command = RedisCommand {
                name: "UNSUBSCRIBE".to_string(),
                args,
            };
            assert!(
                validate_subscription_confirmation(
                    &command,
                    b"*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n:0\r\n"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn parses_resp2_pubsub_pushes() {
        let message =
            parse_pubsub_push(b"*3\r\n$7\r\nmessage\r\n$6\r\nevents\r\n$7\r\npayload\r\n")
                .unwrap()
                .unwrap();
        assert_eq!(message.subscription_kind, RedisSubscriptionKind::Channel);
        assert_eq!(message.subject, b"events");

        let pmessage = parse_pubsub_push(
            b"*4\r\n$8\r\npmessage\r\n$8\r\nevents.*\r\n$10\r\nevents.one\r\n$7\r\npayload\r\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(pmessage.subscription_kind, RedisSubscriptionKind::Pattern);
        assert_eq!(pmessage.subject, b"events.*");
    }

    #[test]
    fn distinguishes_non_push_arrays_and_rejects_malformed_pushes() {
        assert!(
            parse_pubsub_push(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
                .unwrap()
                .is_none()
        );
        let error = parse_pubsub_push(b"*2\r\n$7\r\nmessage\r\n$6\r\nevents\r\n").unwrap_err();
        assert!(error.to_string().contains("must contain 3 elements"));
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

pub mod events;

pub mod evidence;

pub mod capture;

pub mod process_summary;
