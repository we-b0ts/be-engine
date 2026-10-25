//! Bounded multipart comparison: delimiter bytes are transport, parts remain exact.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type Headers = BTreeMap<String, Vec<String>>;
const MAX_BODY: usize = 16 * 1024 * 1024;

struct Document<'a> {
    parameters: Vec<(String, String)>,
    parts: Vec<&'a [u8]>,
}

impl<'a> Document<'a> {
    fn parse(body: &'a [u8], headers: &Headers) -> Result<Self> {
        let (parameters, boundary) = content_type(headers)?;
        Ok(Self {
            parameters,
            parts: parts(body, &boundary)?,
        })
    }

    fn compare(&self, actual: &Self) -> Result<()> {
        ensure!(
            self.parameters == actual.parameters,
            "multipart content-type parameters differ"
        );
        ensure!(self.parts == actual.parts, "multipart parts differ");
        Ok(())
    }
}

/// Check the same bounded Content-Type grammar before materializing body bytes.
/// A supported header alone never selects multipart without a complete body.
pub(super) fn supports_headers(headers: &Headers) -> bool {
    content_type(headers).is_ok()
}

/// A complete supported Source selects this protocol comparison. Unknown or
/// incomplete Source encodings retain the ordinary exact-byte matcher; a
/// selected Target can never fall back after a malformed body or header.
pub(super) fn preview(
    source: &[u8],
    source_headers: &Headers,
    actual: &[u8],
    actual_headers: &Headers,
) -> Option<Result<()>> {
    let source = Document::parse(source, source_headers).ok()?;
    Some((|| {
        let mut source_identity = source_headers.clone();
        let mut actual_identity = actual_headers.clone();
        source_identity.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
        actual_identity.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
        ensure!(
            super::request_headers::exact_contract_match(&source_identity, &actual_identity),
            "multipart identity headers differ"
        );
        source.compare(&Document::parse(actual, actual_headers)?)
    })())
}

pub(in crate::replay) fn compare(
    source: &[u8],
    source_headers: &Headers,
    actual: &[u8],
    actual_headers: &Headers,
) -> Result<()> {
    Document::parse(source, source_headers)?.compare(&Document::parse(actual, actual_headers)?)
}

/// Protected planning witness: exact part bytes are represented by SHA-256 digests.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::replay) struct MultipartContract {
    parameters: Vec<(String, String)>,
    part_fingerprints: Vec<String>,
}
pub(in crate::replay) fn contract(body: &[u8], headers: &Headers) -> Result<MultipartContract> {
    let document = Document::parse(body, headers)?;
    let part_fingerprints = document
        .parts
        .into_iter()
        .map(|part| format!("{:x}", Sha256::digest(part)))
        .collect();
    Ok(MultipartContract {
        parameters: document.parameters,
        part_fingerprints,
    })
}

fn content_type(headers: &Headers) -> Result<(Vec<(String, String)>, String)> {
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .flat_map(|(_, values)| values)
        .collect();
    ensure!(
        values.len() == 1,
        "multipart requires exactly one Content-Type"
    );
    let (kind, mut parameters) = parameters(values[0])?;
    ensure!(
        kind.eq_ignore_ascii_case("multipart/form-data"),
        "expected multipart/form-data"
    );
    let boundary = parameters.remove("boundary");
    let boundary = boundary.context("multipart boundary is missing")?;
    ensure!(
        !boundary.is_empty()
            && boundary.len() <= 70
            && !boundary.ends_with(' ')
            && boundary
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b)),
        "invalid multipart boundary"
    );
    Ok((parameters.into_iter().collect(), boundary))
}

fn parameters(value: &str) -> Result<(&str, BTreeMap<String, String>)> {
    ensure!(
        !value.contains(['\r', '\n', '\0']),
        "invalid multipart header value"
    );
    let mut pieces = Vec::new();
    let (mut quoted, mut escaped, mut start) = (false, false, 0);
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                pieces.push(&value[start..index]);
                start = index + 1;
            }
            _ => (),
        }
    }
    ensure!(!quoted && !escaped, "malformed multipart header parameter");
    pieces.push(&value[start..]);
    let kind = pieces[0].trim();
    let mut parameters = BTreeMap::new();
    let token = |text: &str| {
        !text.is_empty()
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    for piece in pieces.into_iter().skip(1) {
        let (name, value) = piece
            .trim()
            .split_once('=')
            .context("invalid multipart parameter")?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        ensure!(token(&name), "invalid multipart parameter name");
        let value = if value.starts_with('"') {
            let text = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .context("invalid quoted multipart parameter")?;
            let mut out = String::new();
            let mut chars = text.chars();
            while let Some(character) = chars.next() {
                if character == '\\' {
                    out.push(chars.next().context("incomplete quoted escape")?);
                } else {
                    ensure!(character != '"', "unexpected quote in multipart parameter");
                    out.push(character);
                }
            }
            out
        } else {
            ensure!(token(value), "invalid unquoted multipart parameter");
            value.into()
        };
        ensure!(
            parameters.insert(name, value).is_none(),
            "duplicate multipart parameter"
        );
    }
    Ok((kind, parameters))
}

fn parts<'a>(body: &'a [u8], boundary: &str) -> Result<Vec<&'a [u8]>> {
    ensure!(body.len() <= MAX_BODY, "multipart body exceeds 16 MiB");
    let first = format!("--{boundary}\r\n");
    ensure!(
        body.starts_with(first.as_bytes()),
        "multipart opening delimiter differs from Content-Type"
    );
    let delimiter = format!("\r\n--{boundary}");
    let mut start = first.len();
    let mut parts = Vec::new();
    loop {
        ensure!(parts.len() < 128, "multipart exceeds 128 parts");
        let mut search = start;
        let end = loop {
            let offset = body[search..]
                .windows(delimiter.len())
                .position(|bytes| bytes == delimiter.as_bytes())
                .context("multipart closing delimiter is missing")?;
            let end = search + offset;
            let tail = &body[end + delimiter.len()..];
            if tail.starts_with(b"\r\n") || tail.starts_with(b"--") {
                break end;
            }
            search = end + delimiter.len();
        };
        let part = &body[start..end];
        let header_end = part
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .context("multipart part headers are incomplete")?;
        ensure!(
            header_end <= 16 * 1024,
            "multipart part headers exceed 16 KiB"
        );
        let headers = std::str::from_utf8(&part[..header_end])?;
        let mut disposition = 0;
        for line in headers.split("\r\n") {
            let (name, value) = line
                .split_once(':')
                .context("invalid multipart part header")?;
            ensure!(
                !name.is_empty()
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !value.contains(['\r', '\n', '\0']),
                "invalid multipart part header"
            );
            if name.eq_ignore_ascii_case("content-disposition") {
                disposition += 1;
                let (kind, parameters) = parameters(value)?;
                ensure!(
                    kind.eq_ignore_ascii_case("form-data")
                        && parameters.get("name").is_some_and(|name| !name.is_empty()),
                    "multipart disposition requires form-data and a field name"
                );
            }
        }
        ensure!(
            disposition == 1,
            "multipart requires one Content-Disposition per part"
        );
        parts.push(part);
        let tail = &body[end + delimiter.len()..];
        if tail.starts_with(b"--") {
            ensure!(
                tail == b"--\r\n" || tail == b"--",
                "multipart has trailing bytes"
            );
            return Ok(parts);
        }
        start = end + delimiter.len() + 2;
    }
}

#[cfg(test)]
mod tests;
