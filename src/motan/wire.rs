use std::io::Read;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use flate2::read::GzDecoder;
use tokio::io::{AsyncRead, AsyncReadExt};

const OUTER_MAGIC: [u8; 2] = [0xF1, 0xF1];
const INNER_MAGIC: [u8; 2] = [0xF0, 0xF0];
const HEADER_LEN: usize = 16;
const MAX_DECOMPRESSED_IDENTITY_BYTES: u64 = 8 * 1024 * 1024;
const TC_BLOCKDATA: u8 = 0x77;
const TC_BLOCKDATALONG: u8 = 0x7A;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) raw: Bytes,
    pub(crate) request_id: u64,
    pub(crate) codec_version: u8,
    pub(crate) inner_flag: u8,
    pub(crate) request: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestIdentity {
    pub(crate) interface_name: Option<String>,
    pub(crate) method_name: Option<String>,
    pub(crate) parameter_desc: Option<String>,
    pub(crate) method_sign: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestMetadata {
    pub(crate) identity: RequestIdentity,
    pub(crate) group: Option<String>,
}

impl RequestIdentity {
    pub(crate) fn command(&self) -> String {
        match (&self.interface_name, &self.method_name, &self.method_sign) {
            (Some(interface), Some(method), _) => format!("{interface}#{method}"),
            (_, _, Some(sign)) => format!("method-sign:{sign}"),
            _ => "unknown".to_string(),
        }
    }

    pub(crate) fn is_heartbeat(&self) -> bool {
        self.interface_name.as_deref() == Some("com.weibo.api.motan.rpc.heartbeat")
            && self.method_name.as_deref() == Some("heartbeat")
            && self.parameter_desc.as_deref() == Some("void")
    }
}

pub(crate) async fn read_frame<R>(reader: &mut R, max_frame_bytes: usize) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; HEADER_LEN];
    let read = reader
        .read(&mut header[..1])
        .await
        .context("failed to read Motan frame")?;
    if read == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut header[1..])
        .await
        .context("truncated Motan outer header")?;
    if header[..2] != OUTER_MAGIC {
        bail!("invalid Motan outer magic");
    }
    let payload_len = read_u32(&header, 12)? as usize;
    if payload_len < HEADER_LEN {
        bail!("Motan outer payload is shorter than inner header");
    }
    let total_len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| anyhow!("Motan frame length overflow"))?;
    if total_len > max_frame_bytes {
        bail!("Motan frame length {total_len} exceeds configured limit {max_frame_bytes}");
    }
    let mut raw = vec![0_u8; total_len];
    raw[..HEADER_LEN].copy_from_slice(&header);
    reader
        .read_exact(&mut raw[HEADER_LEN..])
        .await
        .context("truncated Motan outer payload")?;
    parse_frame(raw).map(Some)
}

fn parse_frame(raw: Vec<u8>) -> Result<Frame> {
    let inner = raw
        .get(HEADER_LEN..)
        .ok_or_else(|| anyhow!("Motan frame has no inner payload"))?;
    if inner.get(..2) != Some(INNER_MAGIC.as_slice()) {
        bail!("Motan v1 outer frame does not contain F0F0 inner magic");
    }
    let codec_version = *inner
        .get(2)
        .ok_or_else(|| anyhow!("Motan inner header has no codec version"))?;
    if !matches!(codec_version, 1 | 2) {
        bail!("unsupported Motan inner codec version {codec_version}");
    }
    let inner_body_len = read_u32(inner, 12)? as usize;
    if HEADER_LEN + inner_body_len != inner.len() {
        bail!(
            "Motan inner length mismatch: header says {inner_body_len}, frame has {}",
            inner.len().saturating_sub(HEADER_LEN)
        );
    }
    let request_id = read_u64(&raw, 4)?;
    let inner_request_id = read_u64(inner, 4)?;
    if request_id != inner_request_id {
        bail!(
            "Motan outer request id {request_id} differs from inner request id {inner_request_id}"
        );
    }
    let outer_type = raw[3];
    let inner_flag = inner[3] & 0x07;
    let request = match outer_type {
        0 => true,
        1 => false,
        other => bail!("unsupported Motan outer message type {other}"),
    };
    if request && inner_flag != 0 || !request && !matches!(inner_flag, 1 | 3 | 5 | 7) {
        bail!("Motan outer and inner request/response flags disagree");
    }
    Ok(Frame {
        raw: Bytes::from(raw),
        request_id,
        codec_version,
        inner_flag,
        request,
    })
}

impl Frame {
    pub(crate) fn request_identity(&self) -> Result<RequestIdentity> {
        Ok(self.request_metadata()?.identity)
    }

    pub(crate) fn request_metadata(&self) -> Result<RequestMetadata> {
        if !self.request {
            bail!("cannot decode request identity from Motan response");
        }
        let body = self
            .raw
            .get(HEADER_LEN * 2..)
            .ok_or_else(|| anyhow!("Motan request has no inner body"))?;
        let decoded = if self.codec_version == 2 && body.starts_with(&[0x1f, 0x8b]) {
            decompress_identity(body)?
        } else {
            body.to_vec()
        };
        parse_java_request_metadata(&decoded, self.codec_version)
    }
}

pub(crate) fn response_status(frame: &Frame) -> &'static str {
    match frame.inner_flag {
        1 => "value",
        3 => "void",
        5 => "exception",
        7 => "attachment",
        _ => "unknown",
    }
}

pub(crate) fn patch_request_id(raw: &mut [u8], request_id: u64) -> Result<()> {
    if raw.len() < HEADER_LEN * 2
        || raw.get(..2) != Some(OUTER_MAGIC.as_slice())
        || raw.get(HEADER_LEN..HEADER_LEN + 2) != Some(INNER_MAGIC.as_slice())
    {
        bail!("recorded Motan response has invalid framing");
    }
    raw[4..12].copy_from_slice(&request_id.to_be_bytes());
    raw[HEADER_LEN + 4..HEADER_LEN + 12].copy_from_slice(&request_id.to_be_bytes());
    Ok(())
}

fn decompress_identity(body: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(body);
    let mut decoded = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_IDENTITY_BYTES + 1)
        .read_to_end(&mut decoded)
        .context("failed to decompress Motan request identity")?;
    if decoded.len() as u64 > MAX_DECOMPRESSED_IDENTITY_BYTES {
        bail!(
            "decompressed Motan identity exceeds {} bytes",
            MAX_DECOMPRESSED_IDENTITY_BYTES
        );
    }
    Ok(decoded)
}

fn parse_java_request_metadata(body: &[u8], codec_version: u8) -> Result<RequestMetadata> {
    if body.get(..4) != Some([0xAC, 0xED, 0x00, 0x05].as_slice()) {
        bail!("Motan body does not start with a Java serialization stream");
    }
    let block = first_block_data(body)?;
    let mut cursor = 0;
    let first = read_modified_utf(block, &mut cursor)?;
    if codec_version == 2 && first == "1" {
        let identity = RequestIdentity {
            interface_name: None,
            method_name: None,
            parameter_desc: None,
            method_sign: Some(read_modified_utf(block, &mut cursor)?),
        };
        return Ok(RequestMetadata {
            group: request_group(body, block.get(cursor..).unwrap_or_default()),
            identity,
        });
    }
    let identity = RequestIdentity {
        interface_name: Some(first),
        method_name: Some(read_modified_utf(block, &mut cursor)?),
        parameter_desc: Some(read_modified_utf(block, &mut cursor)?),
        method_sign: None,
    };
    Ok(RequestMetadata {
        group: request_group(body, block.get(cursor..).unwrap_or_default()),
        identity,
    })
}

fn request_group(body: &[u8], first_block_remainder: &[u8]) -> Option<String> {
    if let Some(group) = parse_attachment_group(first_block_remainder) {
        return group;
    }
    for block in terminal_block_data(body) {
        if let Some(group) = parse_attachment_group(block) {
            return group;
        }
    }
    None
}

fn terminal_block_data(body: &[u8]) -> Vec<&[u8]> {
    let mut candidates = Vec::new();
    for index in 4..body.len() {
        let Some(token) = body.get(index).copied() else {
            continue;
        };
        let (payload_start, payload_len) = match token {
            TC_BLOCKDATA => {
                let Some(len) = body.get(index + 1).copied() else {
                    continue;
                };
                (index + 2, usize::from(len))
            }
            TC_BLOCKDATALONG => {
                let Some(raw_len) = body.get(index + 1..index + 5) else {
                    continue;
                };
                let len =
                    u32::from_be_bytes([raw_len[0], raw_len[1], raw_len[2], raw_len[3]]) as usize;
                (index + 5, len)
            }
            _ => continue,
        };
        if payload_start.checked_add(payload_len) == Some(body.len()) {
            candidates.push(&body[payload_start..]);
        }
    }
    candidates
}

fn parse_attachment_group(block: &[u8]) -> Option<Option<String>> {
    let count = u32::from_be_bytes(block.get(..4)?.try_into().ok()?) as usize;
    if count > 1024 {
        return None;
    }
    let mut cursor = 4;
    let mut group = None;
    for _ in 0..count {
        let name = read_modified_utf(block, &mut cursor).ok()?;
        let value = read_modified_utf(block, &mut cursor).ok()?;
        if name == "group" {
            group = Some(value);
        }
    }
    (cursor == block.len()).then_some(group)
}

fn first_block_data(body: &[u8]) -> Result<&[u8]> {
    let token = *body
        .get(4)
        .ok_or_else(|| anyhow!("Java serialization stream has no block token"))?;
    let (offset, len) = match token {
        TC_BLOCKDATA => (
            6,
            usize::from(
                *body
                    .get(5)
                    .ok_or_else(|| anyhow!("Java block data has no length"))?,
            ),
        ),
        TC_BLOCKDATALONG => (
            9,
            usize::try_from(read_u32(body, 5)?).context("Java block length overflow")?,
        ),
        other => bail!("unsupported Java serialization token 0x{other:02x} before method data"),
    };
    body.get(offset..offset + len)
        .ok_or_else(|| anyhow!("Java block data is truncated"))
}

fn read_modified_utf(block: &[u8], cursor: &mut usize) -> Result<String> {
    let len = usize::from(read_u16(block, *cursor)?);
    *cursor += 2;
    let value = block
        .get(*cursor..*cursor + len)
        .ok_or_else(|| anyhow!("Java modified UTF value is truncated"))?;
    *cursor += len;
    String::from_utf8(value.to_vec()).context("Motan method metadata is not UTF-8")
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("u16 is out of bounds"))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("u32 is out of bounds"))?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow!("u64 is out of bounds"))?;
    Ok(u64::from_be_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    fn java_method_body(values: &[&str]) -> Vec<u8> {
        let mut block = Vec::new();
        for value in values {
            push_utf(&mut block, value);
        }
        let mut body = vec![0xAC, 0xED, 0x00, 0x05, TC_BLOCKDATA, block.len() as u8];
        body.extend_from_slice(&block);
        body
    }

    fn push_utf(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }

    fn attachment_block(values: &[(&str, &str)]) -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for (name, value) in values {
            push_utf(&mut block, name);
            push_utf(&mut block, value);
        }
        block
    }

    pub(crate) fn frame(
        request_id: u64,
        request: bool,
        codec_version: u8,
        inner_flag: u8,
        body: &[u8],
    ) -> Vec<u8> {
        let mut inner = vec![0_u8; HEADER_LEN];
        inner[..2].copy_from_slice(&INNER_MAGIC);
        inner[2] = codec_version;
        inner[3] = inner_flag;
        inner[4..12].copy_from_slice(&request_id.to_be_bytes());
        inner[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
        inner.extend_from_slice(body);

        let mut outer = vec![0_u8; HEADER_LEN];
        outer[..2].copy_from_slice(&OUTER_MAGIC);
        outer[3] = if request { 0 } else { 1 };
        outer[4..12].copy_from_slice(&request_id.to_be_bytes());
        outer[12..16].copy_from_slice(&(inner.len() as u32).to_be_bytes());
        outer.extend_from_slice(&inner);
        outer
    }

    #[tokio::test]
    async fn reads_legacy_frame_and_method_identity() {
        let raw = frame(
            42,
            true,
            1,
            0,
            &java_method_body(&["example.UserService", "getUser", "long"]),
        );
        let mut input = raw.as_slice();
        let parsed = read_frame(&mut input, 4096).await.unwrap().unwrap();
        assert_eq!(parsed.request_id, 42);
        assert_eq!(
            parsed.request_identity().unwrap(),
            RequestIdentity {
                interface_name: Some("example.UserService".to_string()),
                method_name: Some("getUser".to_string()),
                parameter_desc: Some("long".to_string()),
                method_sign: None,
            }
        );
    }

    #[test]
    fn extracts_group_from_inline_and_terminal_request_attachments() {
        let values = ["example.UserService", "refresh", "void"];
        let attachments =
            attachment_block(&[("application", "example-client"), ("group", "example-rpc")]);

        let mut inline = java_method_body(&values);
        let block_len = usize::from(inline[5]);
        inline.extend_from_slice(&attachments);
        inline[5] = u8::try_from(block_len + attachments.len()).unwrap();
        let inline_frame = parse_frame(frame(1, true, 1, 0, &inline)).unwrap();
        assert_eq!(
            inline_frame.request_metadata().unwrap().group.as_deref(),
            Some("example-rpc")
        );

        let mut terminal = java_method_body(&values);
        terminal.extend_from_slice(&[0x75, 0x70, 0x00, 0x00]);
        terminal.push(TC_BLOCKDATA);
        terminal.push(u8::try_from(attachments.len()).unwrap());
        terminal.extend_from_slice(&attachments);
        let terminal_frame = parse_frame(frame(2, true, 1, 0, &terminal)).unwrap();
        assert_eq!(
            terminal_frame.request_metadata().unwrap().group.as_deref(),
            Some("example-rpc")
        );
    }

    #[test]
    fn parses_compressed_codec_method_sign() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&java_method_body(&["1", "stable-method-sign"]))
            .unwrap();
        let body = encoder.finish().unwrap();
        let raw = frame(7, true, 2, 0, &body);
        let parsed = parse_frame(raw).unwrap();
        assert_eq!(
            parsed.request_identity().unwrap().method_sign.as_deref(),
            Some("stable-method-sign")
        );
    }

    #[test]
    fn patches_outer_and_inner_request_ids() {
        let mut raw = frame(1, false, 1, 1, b"response");
        patch_request_id(&mut raw, 99).unwrap();
        assert_eq!(read_u64(&raw, 4).unwrap(), 99);
        assert_eq!(read_u64(&raw, HEADER_LEN + 4).unwrap(), 99);
    }

    #[test]
    fn identifies_motan_heartbeat() {
        let raw = frame(
            3,
            true,
            1,
            0,
            &java_method_body(&["com.weibo.api.motan.rpc.heartbeat", "heartbeat", "void"]),
        );
        assert!(
            parse_frame(raw)
                .unwrap()
                .request_identity()
                .unwrap()
                .is_heartbeat()
        );
    }
}
