//! The storage envelope shared by the Recorder and immutable Source readers.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const DEPENDENCIES: &str = "dependencies.tsv";
pub const EVENTS: &str = "events.tsv";
pub const INLINE_BYTES: usize = 4 * 1024;
pub const SEGMENT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct PayloadRef {
    pub segment: u64,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

impl PayloadRef {
    pub fn path(segment: u64) -> String {
        format!("payload/{segment:08}.bin")
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Encoding {
    Json,
    Base64Capture,
    Base64Array,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExternalField(String, Encoding, PayloadRef);

pub struct Payload {
    field: String,
    encoding: Encoding,
    bytes: Vec<u8>,
}

impl Payload {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct DependencyRow {
    recording_id: uuid::Uuid,
    capture: Value,
    outcome: Value,
    complete: bool,
    native: Map<String, Value>,
    external: Vec<ExternalField>,
}

fn captured_len(value: &Value) -> Option<usize> {
    (value["encoding"] == "base64" && value["data"].is_string())
        .then(|| usize::try_from(value["stored_len"].as_u64()?).ok())
        .flatten()
}

fn captured_bytes(value: &mut Value, size: usize) -> Result<Vec<u8>> {
    let data = value.get_mut("data").context("missing captured data")?;
    let bytes = STANDARD.decode(data.as_str().context("invalid captured data")?)?;
    ensure!(bytes.len() == size, "captured data length changed");
    *data = Value::Null;
    Ok(bytes)
}

fn restore_capture(value: &mut Value, bytes: &[u8]) -> Result<()> {
    let data = value
        .get_mut("data")
        .context("missing external capture data")?;
    ensure!(data.is_null(), "external capture already has a value");
    *data = Value::String(STANDARD.encode(bytes));
    Ok(())
}

fn offload(value: &mut Value) -> Result<Option<(Encoding, Vec<u8>)>> {
    if let Some(size) = captured_len(value) {
        return if size > INLINE_BYTES {
            Ok(Some((
                Encoding::Base64Capture,
                captured_bytes(value, size)?,
            )))
        } else {
            Ok(None)
        };
    }
    if let Some(values) = value.as_array_mut()
        && let Some(size) = values
            .iter()
            .try_fold(0_usize, |size, part| size.checked_add(captured_len(part)?))
    {
        if size <= INLINE_BYTES {
            return Ok(None);
        }
        let mut bytes = Vec::with_capacity(size);
        for part in values {
            let size = captured_len(part).context("missing capture array element")?;
            bytes.extend_from_slice(&captured_bytes(part, size)?);
        }
        return Ok(Some((Encoding::Base64Array, bytes)));
    }
    if value.is_array() || value.is_object() || value.is_string() {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > INLINE_BYTES {
            *value = Value::Null;
            return Ok(Some((Encoding::Json, bytes)));
        }
    }
    Ok(None)
}

fn restore_array(value: &mut Value, mut bytes: &[u8]) -> Result<()> {
    for part in value
        .as_array_mut()
        .context("missing external capture array")?
    {
        let length = usize::try_from(
            part["stored_len"]
                .as_u64()
                .context("missing external capture length")?,
        )?;
        let (capture, rest) = bytes
            .split_at_checked(length)
            .context("incomplete external capture array")?;
        restore_capture(part, capture)?;
        bytes = rest;
    }
    ensure!(
        bytes.is_empty(),
        "external capture array has trailing bytes"
    );
    Ok(())
}

impl DependencyRow {
    pub fn split(mut event: Map<String, Value>) -> Result<(Self, Vec<Payload>)> {
        let recording_id = serde_json::from_value(
            event
                .remove("recording_id")
                .context("missing recording ID")?,
        )?;
        let capture = event
            .remove("capture")
            .context("missing capture metadata")?;
        let outcome = event
            .remove("outcome")
            .context("missing dependency outcome")?;
        let complete = event
            .remove("capture_complete")
            .and_then(|value| value.as_bool())
            .context("missing capture completeness")?;
        let mut payloads = Vec::new();
        for (field, value) in &mut event {
            if let Some((encoding, bytes)) = offload(value)? {
                payloads.push(Payload {
                    field: field.clone(),
                    encoding,
                    bytes,
                });
            }
        }
        Ok((
            Self {
                recording_id,
                capture,
                outcome,
                complete,
                native: event,
                external: Vec::new(),
            },
            payloads,
        ))
    }

    pub fn link(&mut self, payload: Payload, reference: PayloadRef) {
        self.external
            .push(ExternalField(payload.field, payload.encoding, reference));
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut row = Vec::new();
        row.extend_from_slice(self.recording_id.as_hyphenated().to_string().as_bytes());
        row.push(b'\t');
        serde_json::to_writer(&mut row, &self.capture)?;
        row.push(b'\t');
        serde_json::to_writer(&mut row, &self.outcome)?;
        row.extend_from_slice(if self.complete { b"\t1\t" } else { b"\t0\t" });
        serde_json::to_writer(&mut row, &self.native)?;
        row.push(b'\t');
        serde_json::to_writer(&mut row, &self.external)?;
        row.push(b'\n');
        Ok(row)
    }

    pub fn decode(
        row: &[u8],
        mut read: impl FnMut(&PayloadRef) -> Result<Vec<u8>>,
    ) -> Result<Value> {
        let columns: [&[u8]; 6] = row
            .split(|byte| *byte == b'\t')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid compact dependency row"))?;
        let [id, capture, outcome, complete, native, external] = columns;
        let mut native: Map<String, Value> = serde_json::from_slice(native)?;
        for ExternalField(field, encoding, reference) in
            serde_json::from_slice::<Vec<ExternalField>>(external)?
        {
            let value = native
                .get_mut(&field)
                .context("missing external dependency field")?;
            let bytes = read(&reference)?;
            match encoding {
                Encoding::Json => {
                    ensure!(
                        value.is_null(),
                        "external dependency field already has a value"
                    );
                    *value = serde_json::from_slice(&bytes)?;
                }
                Encoding::Base64Capture => restore_capture(value, &bytes)?,
                Encoding::Base64Array => restore_array(value, &bytes)?,
            }
        }
        native.insert(
            "recording_id".into(),
            Value::String(std::str::from_utf8(id)?.parse::<uuid::Uuid>()?.to_string()),
        );
        native.insert("capture".into(), serde_json::from_slice(capture)?);
        native.insert("outcome".into(), serde_json::from_slice(outcome)?);
        native.insert(
            "capture_complete".into(),
            Value::Bool(match complete {
                b"0" => false,
                b"1" => true,
                _ => anyhow::bail!("invalid compact capture completeness"),
            }),
        );
        Ok(Value::Object(native))
    }
}

pub fn encode_event(
    event: &crate::trace::RecordedEvent<crate::trace::CaptureEvent>,
) -> Result<Vec<u8>> {
    let mut row = format!("{}\t{}\t", event.sequence, event.offset_micros).into_bytes();
    serde_json::to_writer(&mut row, &event.event)?;
    row.push(b'\n');
    Ok(row)
}

pub fn decode_event(row: &str) -> Result<crate::trace::RecordedEvent<crate::trace::CaptureEvent>> {
    let mut columns = row.splitn(3, '\t');
    Ok(crate::trace::RecordedEvent {
        sequence: columns.next().context("missing event sequence")?.parse()?,
        offset_micros: columns.next().context("missing event offset")?.parse()?,
        event: serde_json::from_str(columns.next().context("missing event body")?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::capture_body;

    #[test]
    fn compact_rows_preserve_inline_threshold_and_external_binary_fields() {
        let inline = vec![0xFC; INLINE_BYTES];
        let large = vec![0xFD; INLINE_BYTES + 1];
        let event = serde_json::json!({
            "recording_id": uuid::Uuid::new_v4(),
            "capture": {"sequence":3},
            "outcome": {"kind":"response"},
            "capture_complete": true,
            "args": [capture_body(&inline, inline.len()), capture_body(&[0xFE], 1)],
            "response": capture_body(&large, large.len()),
            "inline": capture_body(&inline, inline.len()),
        });
        let (mut row, fields) = DependencyRow::split(event.as_object().unwrap().clone()).unwrap();
        assert_eq!(fields.len(), 2);
        let mut parts = Vec::new();
        for field in fields {
            let bytes = field.bytes().to_vec();
            assert_eq!(bytes.len(), INLINE_BYTES + 1);
            let reference = PayloadRef {
                segment: parts.len() as u64,
                offset: 0,
                length: bytes.len() as u64,
                sha256: String::new(),
            };
            row.link(field, reference);
            parts.push(bytes);
        }
        let encoded = row.encode().unwrap();
        assert_eq!(encoded.split(|byte| *byte == b'\n').count(), 2);
        let actual = DependencyRow::decode(&encoded, |reference| {
            Ok(parts[reference.segment as usize].clone())
        })
        .unwrap();
        assert_eq!(actual, event);
    }
}
