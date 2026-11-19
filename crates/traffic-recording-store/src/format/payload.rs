//! Lossless body tokens and direct segment references in the payload cells.
use std::{io::Write, ops::Range};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use traffic_protocol::capture::RecordingLayout;

use super::{
    INLINE_BYTES, Payload, PayloadRef,
    row::{ExternalKind, PayloadCell},
};

const BODY: &str = "$body";
const JSON: &str = "$json";
const LITERAL: &str = "$literal";

/// A serialized protocol cell with slots for offsets assigned by the segment writer.
pub(super) struct SerializedCell {
    bytes: Vec<u8>,
    links: Vec<PendingLink>,
}

struct PendingLink {
    range: Range<usize>,
    index: usize,
    text: bool,
}

impl SerializedCell {
    pub(super) fn prepare(
        singleton: &str,
        fields: &Map<String, Value>,
        has_external_fields: bool,
    ) -> Result<Self> {
        let bytes = encode_cell(singleton, fields)?;
        let mut links = Vec::new();
        if has_external_fields {
            let encoded = std::str::from_utf8(&bytes)?;
            for (start, _) in encoded.match_indices("pending") {
                let (prefix, suffix) = encoded.split_at(start);
                let (number, text, tag_size) = match suffix {
                    suffix if suffix.starts_with("pending:") => (&suffix[8..], false, 8),
                    suffix if suffix.starts_with("pending-text:") => (&suffix[13..], true, 13),
                    _ => continue,
                };
                let digits = number.bytes().take_while(u8::is_ascii_digit).count();
                // Structured cells escape input objects with reserved single-field
                // shapes. Only an entire generated token can become a link.
                let nested = encoded.starts_with("json:")
                    && (prefix.ends_with("{\"$body\":\"") || prefix.ends_with("{\"$json\":\""))
                    && number[digits..].starts_with("\"}");
                let standalone = matches!(prefix, "" | "json-") && digits == number.len();
                if nested || standalone {
                    links.push(PendingLink {
                        range: start..start + tag_size + digits,
                        index: number[..digits].parse()?,
                        text,
                    });
                }
            }
        }
        Ok(Self { bytes, links })
    }

    pub(super) fn finish(self, refs: &[Option<PayloadRef>]) -> Result<Vec<u8>> {
        if self.links.is_empty() {
            return Ok(self.bytes);
        }
        let mut bytes = Vec::with_capacity(self.bytes.len());
        let mut previous = 0;
        for link in self.links {
            bytes.extend_from_slice(&self.bytes[previous..link.range.start]);
            let reference = refs
                .get(link.index)
                .and_then(Option::as_ref)
                .context("unlinked protocol payload")?;
            let kind = if link.text { "path-text" } else { "path" };
            write!(
                bytes,
                "{kind}:{}:{}:{}",
                reference.segment, reference.offset, reference.length
            )?;
            previous = link.range.end;
        }
        bytes.extend_from_slice(&self.bytes[previous..]);
        Ok(bytes)
    }
}

pub(super) fn take_fields(
    native: &mut Map<String, Value>,
    layout: Option<RecordingLayout>,
) -> (Map<String, Value>, Map<String, Value>) {
    let mut request = Map::new();
    let mut response = Map::new();
    native.retain(|key, value| {
        let response_field = layout.map_or_else(
            || key == "response" || key.starts_with("response_") && key != "response_kind",
            |layout| layout.response_fields.contains(&key.as_str()),
        );
        let request_field = layout.map_or_else(
            || {
                key == "request"
                    || key.starts_with("request_") && key != "request_started_at"
                    || matches!(
                        key.as_str(),
                        "command" | "args" | "sql" | "params" | "method" | "uri" | "authority"
                    )
            },
            |layout| layout.request_fields.contains(&key.as_str()),
        );
        if response_field {
            response.insert(key.clone(), std::mem::take(value));
            false
        } else if request_field {
            request.insert(key.clone(), std::mem::take(value));
            false
        } else {
            true
        }
    });
    (request, response)
}

pub(super) fn shrink_fields(
    fields: &mut Map<String, Value>,
    payloads: &mut Vec<Payload>,
    offload_json: bool,
) -> Result<()> {
    for value in fields.values_mut() {
        let before = payloads.len();
        let capture = shrink(value, payloads)?;
        if offload_json
            && !capture
            && payloads.len() == before
            && matches!(value, Value::Object(_) | Value::Array(_) | Value::String(_))
        {
            let bytes = serde_json::to_vec(value)?;
            if bytes.len() > INLINE_BYTES {
                let index = add_payload(payloads, bytes);
                *value = json!({JSON:format!("pending:{index}")});
            }
        }
    }
    Ok(())
}

fn shrink(value: &mut Value, payloads: &mut Vec<Payload>) -> Result<bool> {
    match value {
        Value::Array(items) => {
            for item in items {
                shrink(item, payloads)?;
            }
        }
        Value::Object(fields) => {
            if let Some(token) = pack_body(fields, payloads)? {
                *value = json!({BODY:token});
                return Ok(true);
            }
            for item in fields.values_mut() {
                shrink(item, payloads)?;
            }
            if fields.len() == 1 && fields.keys().any(|key| is_token(key)) {
                let (key, inner) = std::mem::take(fields)
                    .into_iter()
                    .next()
                    .expect("one field");
                *value = json!({LITERAL:[key, inner]});
            }
        }
        _ => {}
    }
    Ok(false)
}

fn is_token(key: &str) -> bool {
    matches!(key, BODY | JSON | LITERAL)
}

fn pack_body(fields: &Map<String, Value>, payloads: &mut Vec<Payload>) -> Result<Option<String>> {
    if fields.len() != 5 {
        return Ok(None);
    }
    let (
        Some(encoding @ ("base64" | "utf8")),
        Some(original),
        Some(stored),
        Some(truncated),
        Some(data),
    ) = (
        fields.get("encoding").and_then(Value::as_str),
        fields.get("original_len").and_then(Value::as_u64),
        fields.get("stored_len").and_then(Value::as_u64),
        fields.get("truncated").and_then(Value::as_bool),
        fields.get("data").and_then(Value::as_str),
    )
    else {
        return Ok(None);
    };
    ensure!(
        !truncated && original == stored,
        "truncated payload cannot enter the dependency ledger"
    );
    let len = if encoding == "base64" {
        b64_len(data)?
    } else {
        data.len()
    };
    ensure!(
        len as u64 == stored,
        "captured payload length disagrees with its data"
    );
    if len <= INLINE_BYTES {
        let tag = if encoding == "base64" { "b64" } else { "text" };
        return Ok(Some(format!("{tag}:{data}")));
    }
    let (tag, bytes) = if encoding == "base64" {
        ("pending", STANDARD.decode(data)?)
    } else {
        ("pending-text", data.as_bytes().to_vec())
    };
    let index = add_payload(payloads, bytes);
    Ok(Some(format!("{tag}:{index}")))
}

fn add_payload(payloads: &mut Vec<Payload>, bytes: Vec<u8>) -> usize {
    let index = payloads.len();
    payloads.push(Payload { index, bytes });
    index
}

fn b64_len(data: &str) -> Result<usize> {
    ensure!(data.len().is_multiple_of(4), "invalid encoded payload size");
    let pad = if data.ends_with("==") {
        2
    } else {
        usize::from(data.ends_with('='))
    };
    (data.len() / 4 * 3)
        .checked_sub(pad)
        .context("invalid encoded payload padding")
}

pub(super) fn link(
    fields: &mut Map<String, Value>,
    references: &[Option<PayloadRef>],
) -> Result<()> {
    for value in fields.values_mut() {
        link_value(value, references)?;
    }
    Ok(())
}

fn link_value(value: &mut Value, references: &[Option<PayloadRef>]) -> Result<()> {
    match value {
        Value::Object(fields) => {
            if fields.len() == 1 {
                for key in [BODY, JSON] {
                    if let Some(Value::String(token)) = fields.get_mut(key) {
                        let pending = token
                            .strip_prefix("pending:")
                            .map(|index| (index, "path"))
                            .or_else(|| {
                                token
                                    .strip_prefix("pending-text:")
                                    .map(|index| (index, "path-text"))
                            });
                        if let Some((index, tag)) = pending {
                            let index: usize = index.parse()?;
                            let reference = references
                                .get(index)
                                .and_then(Option::as_ref)
                                .context("unlinked dependency payload")?;
                            *token = format!(
                                "{tag}:{}:{}:{}",
                                reference.segment, reference.offset, reference.length
                            );
                        }
                        return Ok(());
                    }
                }
            }
            for value in fields.values_mut() {
                link_value(value, references)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                link_value(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn encode_cell(singleton: &str, fields: &Map<String, Value>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if fields.is_empty() {
        out.push(b'-');
        return Ok(out);
    }
    if fields.len() == 1
        && let Some(wrapper) = fields.get(singleton).and_then(Value::as_object)
        && wrapper.len() == 1
    {
        if let Some(token) = wrapper.get(BODY).and_then(Value::as_str)
            && !token.contains(['\t', '\r', '\n'])
        {
            out.extend_from_slice(token.as_bytes());
            return Ok(out);
        }
        if let Some(token) = wrapper.get(JSON).and_then(Value::as_str) {
            out.extend_from_slice(b"json-");
            out.extend_from_slice(token.as_bytes());
            return Ok(out);
        }
    }
    out.extend_from_slice(b"json:");
    serde_json::to_writer(&mut out, fields)?;
    Ok(out)
}

pub(super) fn decode_cell(
    singleton: &str,
    cell: PayloadCell<'_>,
    read: &mut impl FnMut(&PayloadRef) -> Result<Vec<u8>>,
) -> Result<Map<String, Value>> {
    let field = match cell {
        PayloadCell::Absent => return Ok(Map::new()),
        PayloadCell::Text(value) => capture("utf8", value.to_owned(), value.len()),
        PayloadCell::Base64(value) => capture("base64", value.to_owned(), b64_len(value)?),
        PayloadCell::Json(data) => {
            let mut fields = serde_json::from_str(data)?;
            restore_fields(&mut fields, read)?;
            return Ok(fields);
        }
        PayloadCell::External { kind, reference } => unpack_external(kind, &reference, read)?,
    };
    Ok(Map::from_iter([(singleton.into(), field)]))
}

pub(super) fn restore_fields(
    fields: &mut Map<String, Value>,
    read: &mut impl FnMut(&PayloadRef) -> Result<Vec<u8>>,
) -> Result<()> {
    for value in fields.values_mut() {
        restore(value, read)?;
    }
    Ok(())
}

fn restore(value: &mut Value, read: &mut impl FnMut(&PayloadRef) -> Result<Vec<u8>>) -> Result<()> {
    match value {
        Value::Object(fields) => {
            if fields.len() == 1 {
                if let Some(token) = fields.get(BODY).and_then(Value::as_str) {
                    *value = unpack_body(token, read)?;
                    return Ok(());
                }
                if let Some(token) = fields.get(JSON).and_then(Value::as_str) {
                    let address = token
                        .strip_prefix("path:")
                        .context("invalid external JSON reference")?;
                    *value = unpack_external(ExternalKind::Json, &address.parse()?, read)?;
                    return Ok(());
                }
                if let Some(Value::Array(literal)) = fields.get_mut(LITERAL) {
                    ensure!(literal.len() == 2, "invalid escaped dependency object");
                    let mut inner = literal.pop().expect("escaped dependency value");
                    let key = literal
                        .pop()
                        .and_then(|key| key.as_str().map(str::to_owned))
                        .context("invalid escaped dependency key")?;
                    restore(&mut inner, read)?;
                    *value = Value::Object(Map::from_iter([(key, inner)]));
                    return Ok(());
                }
            }
            restore_fields(fields, read)?;
        }
        Value::Array(values) => {
            for value in values {
                restore(value, read)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn capture(encoding: &str, data: String, length: usize) -> Value {
    json!({"encoding":encoding,"data":data,"original_len":length,"stored_len":length,"truncated":false})
}

fn unpack_external(
    kind: ExternalKind,
    reference: &PayloadRef,
    read: &mut impl FnMut(&PayloadRef) -> Result<Vec<u8>>,
) -> Result<Value> {
    let bytes = read(reference)?;
    let length = bytes.len();
    ensure!(
        length as u64 == reference.length,
        "incomplete dependency payload"
    );
    Ok(match kind {
        ExternalKind::Bytes => capture("base64", STANDARD.encode(bytes), length),
        ExternalKind::Text => capture("utf8", String::from_utf8(bytes)?, length),
        ExternalKind::Json => {
            let mut value = serde_json::from_slice(&bytes)?;
            restore(&mut value, read)?;
            value
        }
    })
}

fn unpack_body(
    token: &str,
    read: &mut impl FnMut(&PayloadRef) -> Result<Vec<u8>>,
) -> Result<Value> {
    match PayloadCell::parse(token)? {
        PayloadCell::Text(data) => Ok(capture("utf8", data.to_owned(), data.len())),
        PayloadCell::Base64(data) => Ok(capture("base64", data.to_owned(), b64_len(data)?)),
        PayloadCell::External {
            kind: kind @ (ExternalKind::Bytes | ExternalKind::Text),
            reference,
        } => unpack_external(kind, &reference, read),
        _ => anyhow::bail!("unknown dependency body kind"),
    }
}
