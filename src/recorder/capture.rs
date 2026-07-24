use std::collections::HashSet;
use std::io::Read;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use flate2::read::{GzDecoder, ZlibDecoder};
use hyper::HeaderMap;

use super::{BodyCapture, CaseBodyCapture, HeaderMapSnapshot};

pub fn capture_body(bytes: &[u8], max_body_bytes: usize) -> BodyCapture {
    let stored_len = bytes.len().min(max_body_bytes);
    capture_body_with_original_len(&bytes[..stored_len], bytes.len())
}

pub fn capture_body_with_original_len(bytes: &[u8], original_len: usize) -> BodyCapture {
    BodyCapture {
        encoding: "base64",
        original_len,
        stored_len: bytes.len(),
        truncated: original_len > bytes.len(),
        data: STANDARD.encode(bytes),
    }
}

pub fn capture_case_body(
    bytes: &[u8],
    max_body_bytes: usize,
    max_decoded_body_bytes: usize,
    headers: Option<&HeaderMap>,
) -> CaseBodyCapture {
    let content_encoding = headers.and_then(content_encoding);
    let (body, decoded, decode_truncated, limit_bytes, decode_error) = match content_encoding
        .as_deref()
    {
        Some(encoding) => match decode_content_encoding(bytes, encoding, max_decoded_body_bytes) {
            Ok(decoded) => (
                decoded.body,
                true,
                decoded.truncated,
                max_decoded_body_bytes,
                None,
            ),
            Err(err) => (
                bytes[..bytes.len().min(max_body_bytes)].to_vec(),
                false,
                bytes.len() > max_body_bytes,
                max_body_bytes,
                Some(err.to_string()),
            ),
        },
        None => (
            bytes[..bytes.len().min(max_body_bytes)].to_vec(),
            false,
            bytes.len() > max_body_bytes,
            max_body_bytes,
            None,
        ),
    };
    let stored_len = body.len();
    let stored = &body[..stored_len];
    match std::str::from_utf8(stored) {
        Ok(text) => CaseBodyCapture {
            encoding: "utf8",
            original_len: bytes.len(),
            stored_len,
            limit_bytes,
            truncated: decode_truncated,
            decoded,
            content_encoding,
            data: text.to_string(),
            decode_error,
        },
        Err(_) => CaseBodyCapture {
            encoding: "base64",
            original_len: bytes.len(),
            stored_len,
            limit_bytes,
            truncated: decode_truncated,
            decoded,
            content_encoding,
            data: STANDARD.encode(stored),
            decode_error,
        },
    }
}

pub fn redact_headers(headers: &HeaderMap, sensitive_names: &[String]) -> HeaderMapSnapshot {
    let sensitive = sensitive_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut out = HeaderMapSnapshot::new();

    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        let rendered = if sensitive.contains(&name) {
            "<redacted>".to_string()
        } else {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|_| STANDARD.encode(value.as_bytes()))
        };
        out.entry(name).or_default().push(rendered);
    }

    out
}

fn content_encoding(headers: &HeaderMap) -> Option<String> {
    headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

struct DecodedBody {
    body: Vec<u8>,
    truncated: bool,
}

fn decode_content_encoding(bytes: &[u8], encoding: &str, limit: usize) -> Result<DecodedBody> {
    let mut out = bytes.to_vec();
    let mut truncated = false;
    for coding in encoding
        .split(',')
        .map(str::trim)
        .filter(|coding| !coding.is_empty())
        .rev()
    {
        out = match coding {
            "gzip" | "x-gzip" => {
                let mut decoder = GzDecoder::new(out.as_slice());
                let mut decoded = Vec::new();
                decoder
                    .by_ref()
                    .take(limit.saturating_add(1) as u64)
                    .read_to_end(&mut decoded)
                    .context("failed to decode gzip body")?;
                truncated = decoded.len() > limit;
                decoded.truncate(limit);
                decoded
            }
            "deflate" => {
                let mut decoder = ZlibDecoder::new(out.as_slice());
                let mut decoded = Vec::new();
                decoder
                    .by_ref()
                    .take(limit.saturating_add(1) as u64)
                    .read_to_end(&mut decoded)
                    .context("failed to decode deflate body")?;
                truncated = decoded.len() > limit;
                decoded.truncate(limit);
                decoded
            }
            "identity" => out,
            other => anyhow::bail!("unsupported content-encoding {other}"),
        };
        if truncated {
            break;
        }
    }
    Ok(DecodedBody {
        body: out,
        truncated,
    })
}

impl From<Bytes> for BodyCapture {
    fn from(value: Bytes) -> Self {
        capture_body(&value, value.len())
    }
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};
    use std::io::Write;

    use super::*;

    #[test]
    fn captures_body_with_truncation() {
        let capture = capture_body(b"abcdef", 3);
        assert_eq!(capture.original_len, 6);
        assert_eq!(capture.stored_len, 3);
        assert!(capture.truncated);
        assert_eq!(capture.data, "YWJj");
    }

    #[test]
    fn captures_case_body_with_gzip_decoding() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(br#"{"ok":true}"#).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());

        let capture = capture_case_body(&compressed, 1024, 1024, Some(&headers));
        assert_eq!(capture.encoding, "utf8");
        assert!(capture.decoded);
        assert_eq!(capture.data, r#"{"ok":true}"#);
    }

    #[test]
    fn bounds_decoded_gzip_body_independently_from_wire_body() {
        let decoded = vec![b'a'; 4096];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&decoded).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 1024);
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());

        let complete = capture_case_body(&compressed, 1024, 4096, Some(&headers));
        assert!(!complete.truncated);
        assert_eq!(complete.stored_len, 4096);
        assert_eq!(complete.limit_bytes, 4096);

        let truncated = capture_case_body(&compressed, 1024, 2048, Some(&headers));
        assert!(truncated.truncated);
        assert_eq!(truncated.stored_len, 2048);
        assert_eq!(truncated.limit_bytes, 2048);
    }

    #[test]
    fn captures_observed_pluto_large_decoded_response_with_32_mib_limit() {
        const OBSERVED_DECODED_BYTES: usize = 28_964_825;
        const DECODED_LIMIT: usize = 32 * 1024 * 1024;

        let decoded = vec![b'a'; OBSERVED_DECODED_BYTES];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&decoded).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 10 * 1024 * 1024);
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());

        let capture =
            capture_case_body(&compressed, 10 * 1024 * 1024, DECODED_LIMIT, Some(&headers));
        assert!(!capture.truncated);
        assert!(capture.decoded);
        assert_eq!(capture.stored_len, OBSERVED_DECODED_BYTES);
        assert_eq!(capture.limit_bytes, DECODED_LIMIT);
    }

    #[test]
    fn redacts_sensitive_headers_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        headers.insert(COOKIE, HeaderValue::from_static("a=b"));

        let snapshot = redact_headers(&headers, &["authorization".into(), "cookie".into()]);
        assert_eq!(snapshot["authorization"], vec!["<redacted>".to_string()]);
        assert_eq!(snapshot["cookie"], vec!["<redacted>".to_string()]);
    }
}
