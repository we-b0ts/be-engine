use anyhow::{Context, Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemcachedWireProtocol {
    Text,
    Binary,
}

impl MemcachedWireProtocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Binary => "binary",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MemcachedRequest {
    pub(crate) raw: Bytes,
    pub(crate) command: String,
    pub(crate) opcode: Option<u8>,
    pub(crate) opaque: Option<u32>,
    pub(crate) key: Option<Vec<u8>>,
    pub(crate) args: Vec<Vec<u8>>,
    pub(crate) value: Option<Vec<u8>>,
    pub(crate) extras: Option<Vec<u8>>,
    pub(crate) cas: Option<u64>,
    pub(crate) noreply: bool,
    pub(crate) quiet: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct BinaryFrame {
    pub(crate) raw: Bytes,
    pub(crate) magic: u8,
    pub(crate) opcode: u8,
    pub(crate) opaque: u32,
    pub(crate) cas: u64,
    pub(crate) extras: Vec<u8>,
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

pub(crate) async fn read_binary_frame<R>(
    reader: &mut BufferedReader<R>,
) -> Result<Option<BinaryFrame>>
where
    R: AsyncRead + Unpin,
{
    loop {
        if reader.buffer.len() >= 24 {
            let body_len = u32::from_be_bytes([
                reader.buffer[8],
                reader.buffer[9],
                reader.buffer[10],
                reader.buffer[11],
            ]) as usize;
            let frame_len = 24usize
                .checked_add(body_len)
                .context("Memcached binary frame length overflow")?;
            if frame_len > reader.max_frame_bytes {
                return Err(anyhow!(
                    "Memcached binary frame exceeds configured maximum of {} bytes",
                    reader.max_frame_bytes
                ));
            }
            if reader.buffer.len() >= frame_len {
                let raw = Bytes::copy_from_slice(&reader.buffer[..frame_len]);
                let frame = parse_binary_frame(raw)?;
                reader.buffer.advance(frame_len);
                return Ok(Some(frame));
            }
        }
        let read = reader.inner.read_buf(&mut reader.buffer).await?;
        if read == 0 {
            if reader.buffer.is_empty() {
                return Ok(None);
            }
            return Err(anyhow!(
                "Memcached binary connection closed with an incomplete frame"
            ));
        }
    }
}

pub(crate) fn binary_access_denied_response(request: &BinaryFrame) -> Bytes {
    const STATUS_INVALID_ARGUMENTS: u16 = 0x0004;
    const MESSAGE: &[u8] = b"request blocked by recording access policy";

    let mut response = Vec::with_capacity(24 + MESSAGE.len());
    response.push(0x81);
    response.push(request.opcode);
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.push(0);
    response.push(0);
    response.extend_from_slice(&STATUS_INVALID_ARGUMENTS.to_be_bytes());
    response.extend_from_slice(&(MESSAGE.len() as u32).to_be_bytes());
    response.extend_from_slice(&request.opaque.to_be_bytes());
    response.extend_from_slice(&0_u64.to_be_bytes());
    response.extend_from_slice(MESSAGE);
    Bytes::from(response)
}

pub(crate) async fn read_text_request<R>(
    reader: &mut BufferedReader<R>,
) -> Result<Option<MemcachedRequest>>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(line_end) = crlf_position(&reader.buffer) {
            let line = std::str::from_utf8(&reader.buffer[..line_end])
                .context("Memcached text request line is not UTF-8")?;
            let tokens = line.split_ascii_whitespace().collect::<Vec<_>>();
            let command = tokens
                .first()
                .ok_or_else(|| anyhow!("empty Memcached text request"))?
                .to_ascii_lowercase();
            if !text_request_line_is_valid(&tokens, true) {
                return Err(anyhow!(
                    "invalid or unsupported Memcached text request line"
                ));
            }
            let value_len = storage_value_len(&command, &tokens)?;
            let frame_len = line_end + 2 + value_len.map_or(0, |len| len + 2);
            if frame_len > reader.max_frame_bytes {
                return Err(anyhow!(
                    "Memcached text request exceeds configured maximum of {} bytes",
                    reader.max_frame_bytes
                ));
            }
            if reader.buffer.len() >= frame_len {
                if value_len.is_some() && &reader.buffer[frame_len - 2..frame_len] != b"\r\n" {
                    return Err(anyhow!("Memcached storage value is not terminated by CRLF"));
                }
                let raw = reader.buffer.split_to(frame_len).freeze();
                return parse_text_request(raw).map(Some);
            }
        }
        let read = reader.inner.read_buf(&mut reader.buffer).await?;
        if read == 0 {
            if reader.buffer.is_empty() {
                return Ok(None);
            }
            return Err(anyhow!(
                "Memcached text connection closed with an incomplete request"
            ));
        }
    }
}

pub(crate) fn text_request_line_is_valid(tokens: &[&str], allow_meta: bool) -> bool {
    let Some(command) = tokens.first().map(|value| value.to_ascii_lowercase()) else {
        return false;
    };
    if tokens[0] != command {
        return false;
    }
    match command.as_str() {
        "set" | "add" | "replace" | "append" | "prepend" => {
            matches!(tokens.len(), 5 | 6)
                && (tokens.len() == 5 || tokens[5] == "noreply")
                && tokens[2].parse::<u32>().is_ok()
                && tokens[3].parse::<u64>().is_ok()
                && tokens[4].parse::<usize>().is_ok()
        }
        "cas" => {
            matches!(tokens.len(), 6 | 7)
                && (tokens.len() == 6 || tokens[6] == "noreply")
                && tokens[2].parse::<u32>().is_ok()
                && tokens[3].parse::<u64>().is_ok()
                && tokens[4].parse::<usize>().is_ok()
                && tokens[5].parse::<u64>().is_ok()
        }
        "get" | "gets" => tokens.len() >= 2,
        "delete" => matches!(tokens.len(), 2..=4),
        "incr" | "decr" | "touch" => {
            matches!(tokens.len(), 3 | 4)
                && tokens[2].parse::<u64>().is_ok()
                && (tokens.len() == 3 || tokens[3] == "noreply")
        }
        "gat" | "gats" => tokens.len() >= 3 && tokens[1].parse::<u64>().is_ok(),
        "stats" => true,
        "version" | "quit" => tokens.len() == 1,
        "flush_all" => matches!(tokens.len(), 1..=3),
        "verbosity" => matches!(tokens.len(), 2 | 3) && tokens[1].parse::<u32>().is_ok(),
        "mg" | "ms" | "md" | "ma" | "me" | "mn" => allow_meta,
        _ => false,
    }
}

pub(crate) async fn read_text_response<R>(
    reader: &mut BufferedReader<R>,
    command: &str,
) -> Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(frame_len) = text_response_len(&reader.buffer, command)? {
            if frame_len > reader.max_frame_bytes {
                return Err(anyhow!(
                    "Memcached text response exceeds configured maximum of {} bytes",
                    reader.max_frame_bytes
                ));
            }
            return Ok(Some(reader.buffer.split_to(frame_len).freeze()));
        }
        let read = reader.inner.read_buf(&mut reader.buffer).await?;
        if read == 0 {
            if reader.buffer.is_empty() {
                return Ok(None);
            }
            return Err(anyhow!(
                "Memcached text connection closed with an incomplete response"
            ));
        }
    }
}

pub(crate) fn binary_response_is_complete(request_opcode: u8, frame: &BinaryFrame) -> bool {
    request_opcode != 0x10 || (frame.key.is_empty() && frame.value.is_empty())
}

impl BinaryFrame {
    pub(crate) fn as_request(&self) -> Result<MemcachedRequest> {
        if self.magic != 0x80 {
            return Err(anyhow!("Memcached binary request has invalid magic"));
        }
        Ok(MemcachedRequest {
            raw: self.raw.clone(),
            command: binary_command_name(self.opcode).to_string(),
            opcode: Some(self.opcode),
            opaque: Some(self.opaque),
            key: (!self.key.is_empty()).then(|| self.key.clone()),
            args: Vec::new(),
            value: (!self.value.is_empty()).then(|| self.value.clone()),
            extras: (!self.extras.is_empty()).then(|| self.extras.clone()),
            cas: (self.cas != 0).then_some(self.cas),
            noreply: false,
            quiet: is_quiet_opcode(self.opcode),
        })
    }
}

fn parse_binary_frame(raw: Bytes) -> Result<BinaryFrame> {
    let magic = raw[0];
    if !matches!(magic, 0x80 | 0x81) {
        return Err(anyhow!("unknown Memcached binary magic 0x{magic:02x}"));
    }
    let opcode = raw[1];
    let key_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    let extras_len = raw[4] as usize;
    let body_len = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
    if extras_len + key_len > body_len {
        return Err(anyhow!("invalid Memcached binary extras/key lengths"));
    }
    let opaque = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let cas = u64::from_be_bytes(raw[16..24].try_into().expect("fixed binary header"));
    let extras_start = 24;
    let key_start = extras_start + extras_len;
    let value_start = key_start + key_len;
    Ok(BinaryFrame {
        raw: raw.clone(),
        magic,
        opcode,
        opaque,
        cas,
        extras: raw[extras_start..key_start].to_vec(),
        key: raw[key_start..value_start].to_vec(),
        value: raw[value_start..24 + body_len].to_vec(),
    })
}

fn parse_text_request(raw: Bytes) -> Result<MemcachedRequest> {
    let line_end = crlf_position(&raw).context("Memcached request line has no CRLF")?;
    let line = std::str::from_utf8(&raw[..line_end])?;
    let tokens = line.split_ascii_whitespace().collect::<Vec<_>>();
    let command = tokens[0].to_ascii_lowercase();
    let value_len = storage_value_len(&command, &tokens)?;
    let value = value_len.map(|len| raw[line_end + 2..line_end + 2 + len].to_vec());
    let key_position = if matches!(command.as_str(), "gat" | "gats") {
        2
    } else {
        1
    };
    let key = if command == "flush_all" {
        None
    } else {
        tokens
            .get(key_position)
            .map(|value| value.as_bytes().to_vec())
    };
    let noreply = command_supports_noreply(&command)
        && tokens
            .last()
            .is_some_and(|value| value.eq_ignore_ascii_case("noreply"));
    let args = tokens
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(position, value)| {
            (command == "flush_all" || *position != key_position)
                && !(noreply && value.eq_ignore_ascii_case("noreply"))
        })
        .map(|(_, value)| value.as_bytes().to_vec())
        .collect();
    let cas = (command == "cas")
        .then(|| tokens.get(5).and_then(|value| value.parse().ok()))
        .flatten();
    Ok(MemcachedRequest {
        raw,
        command,
        opcode: None,
        opaque: None,
        key,
        args,
        value,
        extras: None,
        cas,
        noreply,
        quiet: false,
    })
}

fn command_supports_noreply(command: &str) -> bool {
    matches!(
        command,
        "set"
            | "add"
            | "replace"
            | "append"
            | "prepend"
            | "cas"
            | "delete"
            | "incr"
            | "decr"
            | "touch"
            | "flush_all"
            | "verbosity"
    )
}

fn storage_value_len(command: &str, tokens: &[&str]) -> Result<Option<usize>> {
    if matches!(
        command,
        "set" | "add" | "replace" | "append" | "prepend" | "cas"
    ) {
        let value = tokens
            .get(4)
            .ok_or_else(|| anyhow!("Memcached storage command is missing byte length"))?;
        return value
            .parse::<usize>()
            .context("invalid Memcached storage byte length")
            .map(Some);
    }
    Ok(None)
}

fn text_response_len(buffer: &[u8], command: &str) -> Result<Option<usize>> {
    if !matches!(command, "get" | "gets" | "gat" | "gats" | "stats") {
        return Ok(crlf_position(buffer).map(|position| position + 2));
    }
    let mut cursor = 0;
    while cursor < buffer.len() {
        let Some(relative_end) = crlf_position(&buffer[cursor..]) else {
            return Ok(None);
        };
        let line_end = cursor + relative_end;
        let line = std::str::from_utf8(&buffer[cursor..line_end])
            .context("Memcached response line is not UTF-8")?;
        cursor = line_end + 2;
        if line == "END" {
            return Ok(Some(cursor));
        }
        if line == "ERROR" || line.starts_with("CLIENT_ERROR") || line.starts_with("SERVER_ERROR") {
            return Ok(Some(cursor));
        }
        if let Some(rest) = line.strip_prefix("VALUE ") {
            let tokens = rest.split_ascii_whitespace().collect::<Vec<_>>();
            let value_len = tokens
                .get(2)
                .ok_or_else(|| anyhow!("Memcached VALUE response is missing byte length"))?
                .parse::<usize>()
                .context("invalid Memcached VALUE byte length")?;
            let end = cursor
                .checked_add(value_len + 2)
                .context("Memcached response length overflow")?;
            if buffer.len() < end {
                return Ok(None);
            }
            if &buffer[end - 2..end] != b"\r\n" {
                return Err(anyhow!("Memcached VALUE body is not terminated by CRLF"));
            }
            cursor = end;
        }
    }
    Ok(None)
}

fn crlf_position(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn is_quiet_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x09 | 0x0d | 0x11..=0x1a | 0x1e | 0x32 | 0x34 | 0x36 | 0x39 | 0x3b
    )
}

fn binary_command_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 | 0x09 | 0x0c | 0x0d => "get",
        0x01 | 0x11 => "set",
        0x02 | 0x12 => "add",
        0x03 | 0x13 => "replace",
        0x04 | 0x14 => "delete",
        0x05 | 0x15 => "increment",
        0x06 | 0x16 => "decrement",
        0x07 | 0x17 => "quit",
        0x08 | 0x18 => "flush",
        0x0a => "noop",
        0x0b => "version",
        0x0e | 0x19 => "append",
        0x0f | 0x1a => "prepend",
        0x10 => "stat",
        0x1c => "touch",
        0x1d | 0x1e => "gat",
        0x20 => "sasl_list_mechs",
        0x21 => "sasl_auth",
        0x22 => "sasl_step",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn text_expiration_is_an_argument_for_get_and_touch_and_flush() {
        for command in ["gat", "gats"] {
            let raw = format!("{command} 1700000060 first second\r\n");
            let mut reader = BufferedReader::new(raw.as_bytes(), 1024);
            let request = read_text_request(&mut reader).await.unwrap().unwrap();
            assert_eq!(request.key.as_deref(), Some(b"first".as_slice()));
            assert_eq!(
                request.args,
                vec![b"1700000060".to_vec(), b"second".to_vec()]
            );
        }
        let mut reader = BufferedReader::new(b"flush_all 1700000060 noreply\r\n".as_slice(), 1024);
        let request = read_text_request(&mut reader).await.unwrap().unwrap();
        assert!(request.key.is_none());
        assert_eq!(request.args, vec![b"1700000060".to_vec()]);
        assert!(request.noreply);
    }

    #[tokio::test]
    async fn reads_text_storage_value_with_embedded_crlf() {
        let bytes = b"set key 7 60 4\r\na\r\nb\r\n".as_slice();
        let mut reader = BufferedReader::new(bytes, 1024);
        let request = read_text_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(request.command, "set");
        assert_eq!(request.value.as_deref(), Some(b"a\r\nb".as_slice()));
    }

    #[tokio::test]
    async fn reads_binary_frame_fields() {
        let mut raw = vec![0_u8; 24];
        raw[0] = 0x80;
        raw[1] = 0x00;
        raw[2..4].copy_from_slice(&3_u16.to_be_bytes());
        raw[8..12].copy_from_slice(&3_u32.to_be_bytes());
        raw[12..16].copy_from_slice(&42_u32.to_be_bytes());
        raw.extend_from_slice(b"key");
        let mut reader = BufferedReader::new(raw.as_slice(), 1024);
        let frame = read_binary_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(frame.key, b"key");
        assert_eq!(frame.opaque, 42);
    }

    #[test]
    fn builds_binary_access_denied_response_with_matching_correlation_fields() {
        let request = BinaryFrame {
            raw: Bytes::new(),
            magic: 0x80,
            opcode: 0x01,
            opaque: 0x1234_5678,
            cas: 0,
            extras: Vec::new(),
            key: Vec::new(),
            value: Vec::new(),
        };
        let response = binary_access_denied_response(&request);
        assert_eq!(response[0], 0x81);
        assert_eq!(response[1], 0x01);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0x0004);
        assert_eq!(
            u32::from_be_bytes(response[12..16].try_into().unwrap()),
            0x1234_5678
        );
    }

    #[tokio::test]
    async fn groups_multi_get_values_and_single_line_errors() {
        let bytes = b"VALUE a 0 1\r\n1\r\nVALUE b 0 1 9\r\n2\r\nEND\r\n".as_slice();
        let mut reader = BufferedReader::new(bytes, 1024);
        let response = read_text_response(&mut reader, "gets")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.as_ref(), bytes);

        let bytes = b"SERVER_ERROR backend failed\r\n".as_slice();
        let mut reader = BufferedReader::new(bytes, 1024);
        let response = read_text_response(&mut reader, "get")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.as_ref(), bytes);
    }
}
