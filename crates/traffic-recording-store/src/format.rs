//! The storage envelope shared by Recorder and immutable Source readers.
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value};
use std::str::FromStr;
use uuid::Uuid;

use crate::dependency_columns::{ReadTerms, WriteTerms};

mod atoms;
mod header;
mod payload;
mod reference;
mod row;

use header::RecordProjection;
pub use header::RowLayout;
#[cfg(test)]
pub(crate) use row::COLUMN_COUNT;
use row::{DependencyRow, PayloadCell, ProtocolExtension};

pub const DEPENDENCIES: &str = "dependencies.tsv";
pub const EVENTS: &str = "events.tsv";
pub const PUSH_EVENTS: &str = "events-push.tsv";
pub const INLINE_BYTES: usize = 4 * 1024;
pub const SEGMENT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug)]
pub struct PayloadRef {
    pub segment: u64,
    pub offset: u64,
    pub length: u64,
}

impl PayloadRef {
    pub fn path(segment: u64) -> String {
        format!("payload/{segment:08}.bin")
    }
}

impl FromStr for PayloadRef {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (segment, rest) = value.split_once(':').context("missing payload offset")?;
        let (offset, length) = rest.split_once(':').context("missing payload length")?;
        Ok(Self {
            segment: segment.parse()?,
            offset: offset.parse()?,
            length: length.parse()?,
        })
    }
}

pub struct Payload {
    index: usize,
    bytes: Vec<u8>,
}

impl Payload {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) struct PendingDependency {
    header: RecordProjection,
    request: payload::SerializedCell,
    response: payload::SerializedCell,
    references: Vec<Option<PayloadRef>>,
}

impl PendingDependency {
    pub fn split(
        mut event: Map<String, Value>,
        recording_id: Uuid,
        layout: &RowLayout,
    ) -> Result<(Self, Vec<Payload>)> {
        let recorded_id: Uuid = serde_json::from_value(
            event
                .remove("recording_id")
                .context("missing recording ID")?,
        )?;
        ensure!(
            recorded_id == recording_id,
            "dependency belongs to a different recording"
        );
        let Some(Value::Object(capture)) = event.remove("capture") else {
            anyhow::bail!("missing or invalid capture metadata");
        };
        let outcome = event
            .remove("outcome")
            .context("missing dependency outcome")?;
        let complete = event
            .remove("capture_complete")
            .and_then(|value| value.as_bool())
            .context("missing capture completeness")?;
        let (mut request, mut response) = payload::take_fields(&mut event, layout.declaration);
        let mut payloads = Vec::new();
        payload::shrink_fields(&mut request, &mut payloads, true)?;
        let request = payload::SerializedCell::prepare("request", &request, !payloads.is_empty())?;
        let request_payloads = payloads.len();
        payload::shrink_fields(&mut response, &mut payloads, true)?;
        let response = payload::SerializedCell::prepare(
            "response",
            &response,
            payloads.len() != request_payloads,
        )?;
        payload::shrink_fields(&mut event, &mut payloads, false)?;
        let references = (0..payloads.len()).map(|_| None).collect();
        Ok((
            Self {
                header: RecordProjection {
                    capture,
                    outcome,
                    complete,
                    native: event,
                },
                request,
                response,
                references,
            },
            payloads,
        ))
    }

    pub fn link(&mut self, payload: Payload, reference: PayloadRef) {
        self.references[payload.index] = Some(reference);
    }

    pub(crate) fn encode(mut self, terms: &mut WriteTerms, layout: &RowLayout) -> Result<Vec<u8>> {
        payload::link(&mut self.header.native, &self.references)?;
        let (prefix, extension) = self.header.project(terms, layout)?;
        let request = self.request.finish(&self.references)?;
        let response = self.response.finish(&self.references)?;
        DependencyRow::write(
            &prefix,
            ProtocolExtension::parse(std::str::from_utf8(&extension)?)?,
            PayloadCell::parse(std::str::from_utf8(&request)?)?,
            PayloadCell::parse(std::str::from_utf8(&response)?)?,
            terms.recording_id(),
        )
    }

    pub(crate) fn materialize(
        row: &[u8],
        recording_id: Uuid,
        terms: &ReadTerms,
        mut read: impl FnMut(&PayloadRef) -> Result<Vec<u8>>,
    ) -> Result<Value> {
        let DependencyRow {
            prefix,
            extension,
            request,
            response,
        } = DependencyRow::parse(row, recording_id)?;
        let RecordProjection {
            capture,
            outcome,
            complete,
            mut native,
        } = RecordProjection::materialize(prefix, extension, recording_id, terms)?;
        payload::restore_fields(&mut native, &mut read)?;
        for (key, value) in payload::decode_cell("request", request, &mut read)?
            .into_iter()
            .chain(payload::decode_cell("response", response, &mut read)?)
        {
            ensure!(
                native.insert(key, value).is_none(),
                "duplicate dependency payload field"
            );
        }
        native.insert("recording_id".into(), Value::from(recording_id.to_string()));
        native.insert("capture".into(), Value::Object(capture));
        native.insert("outcome".into(), outcome);
        native.insert("capture_complete".into(), Value::Bool(complete));
        Ok(Value::Object(native))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_model::{capture::capture_body, recording::identity::IdentityKind};

    #[test]
    fn declared_dependency_uses_one_case_and_direct_body_location() {
        use traffic_protocol::capture::{RecordingLayout, RecordingScalar};

        let epoch = Uuid::from_u128(43);
        let case = IdentityKind::Case.bridge(epoch, 7);
        let dependency = IdentityKind::Dependency.bridge(epoch, 9);
        let original = dependency;
        let body = vec![0xFB; INLINE_BYTES + 1];
        let event = serde_json::json!({
            "recording_id": epoch,
            "capture": {
                "sequence":9, "exchange_id":dependency,
                "observed_case":case, "admitted_case":case,
                "attribution":{"kind":"case","origin_case_id":case},
                "protocol_ref":{"protocol":"http","exchange_id":original},
            },
            "outcome":"response", "capture_complete":true,
            "event_type":"http_exchange", "id":original,
            "scheme":"http", "duration_ms":2, "method":"POST", "authority":"example.test",
            "request_body":capture_body(b"", 0),
            "response_headers":{"content-type":["application/octet-stream"]},
            "response_body":capture_body(&body, body.len()),
        });
        let layout = RowLayout {
            declaration: Some(RecordingLayout {
                protocol: "http",
                variant: "",
                event_type: "http_exchange",
                use_dependency_id: true,
                fields: &[("scheme", RecordingScalar::Text)],
                request_fields: &["method", "authority", "request_body"],
                response_fields: &["response_headers", "response_body"],
            }),
            target: Some("example.test:80".into()),
            upstream: Some("192.0.2.32:80".into()),
        };
        let (mut pending, mut payloads) =
            PendingDependency::split(event.as_object().unwrap().clone(), epoch, &layout).unwrap();
        assert_eq!(payloads.len(), 1);
        let payload = payloads.pop().unwrap();
        assert_eq!(payload.bytes(), body);
        pending.link(
            payload,
            PayloadRef {
                segment: 4,
                offset: 32,
                length: body.len() as u64,
            },
        );
        let mut terms = WriteTerms::new("2026-11-19T06:43:37Z".parse().unwrap(), epoch);
        let encoded = pending.encode(&mut terms, &layout).unwrap();
        let row = std::str::from_utf8(&encoded).unwrap();
        assert!(
            row.starts_with("9\thttp\tcase-7\texample.test:80\t-\t192.0.2.32:80\t-\t2\text:[http]")
        );
        assert_eq!(row.matches("case-7").count(), 1);
        assert!(row.contains("path:4:32:4097"));
        for redundant in [
            "original_len",
            "stored_len",
            "truncated",
            "sha256",
            "http_exchange",
            "exchange_id",
        ] {
            assert!(!row.contains(redundant), "{redundant} appears in {row}");
        }
        let compiled = ReadTerms::decode(&terms.take_pending()).unwrap();
        let actual = PendingDependency::materialize(&encoded, epoch, &compiled, |reference| {
            assert_eq!(
                (reference.segment, reference.offset, reference.length),
                (4, 32, 4097)
            );
            Ok(body.clone())
        })
        .unwrap();
        let mut expected = event;
        expected["id"] = Value::from(dependency.to_string());
        expected["capture"]["protocol_ref"]["exchange_id"] = Value::from(dependency.to_string());
        assert_eq!(actual, expected);
    }

    #[test]
    fn dependency_rejects_a_truncated_capture() {
        let epoch = Uuid::from_u128(50);
        let event = serde_json::json!({
            "recording_id":epoch,
            "capture":{"sequence":1},
            "capture_complete":false,
            "outcome":"response",
            "response":capture_body(b"abcd", 3),
        });
        let error = PendingDependency::split(
            event.as_object().unwrap().clone(),
            epoch,
            &RowLayout::default(),
        );
        assert!(error.is_err());
    }

    #[test]
    fn compact_rows_preserve_inline_threshold_and_external_binary_fields() {
        let inline = vec![0xFC; INLINE_BYTES];
        let large = vec![0xFD; INLINE_BYTES + 1];
        let recording_id = Uuid::new_v4();
        let event = serde_json::json!({
            "recording_id": recording_id,
            "capture": {"sequence":3, "exchange_id":IdentityKind::Dependency.bridge(recording_id,3), "started_at":"2026-11-19T06:43:36.999999999Z"},
            "outcome": {"kind":"response"},
            "capture_complete": true,
            "target_host": "example.test",
            "target_port": 48958,
            "client_addr": null,
            "timestamp": "2026-11-19T06:43:37.015651230Z",
            "request_started_at": "2026-11-19T14:43:36.5+08:00",
            "args": [capture_body(&inline, inline.len()), capture_body(&[0xFE], 1)],
            "response": capture_body(&large, large.len()),
            "inline": capture_body(&inline, inline.len()),
        });
        let (mut row, fields) = PendingDependency::split(
            event.as_object().unwrap().clone(),
            recording_id,
            &RowLayout::default(),
        )
        .unwrap();
        assert_eq!(fields.len(), 2);
        let mut parts = Vec::new();
        for field in fields {
            let bytes = field.bytes().to_vec();
            assert!(bytes.len() > INLINE_BYTES);
            let reference = PayloadRef {
                segment: parts.len() as u64,
                offset: 0,
                length: bytes.len() as u64,
            };
            row.link(field, reference);
            parts.push(bytes);
        }
        let mut terms = WriteTerms::new("2026-11-19T06:43:37Z".parse().unwrap(), recording_id);
        let encoded = row.encode(&mut terms, &RowLayout::default()).unwrap();
        assert_eq!(encoded.split(|byte| *byte == b'\n').count(), 2);
        assert_eq!(encoded.split(|byte| *byte == b'\t').count(), COLUMN_COUNT);
        assert!(encoded.starts_with(b"3\t"));
        assert!(
            encoded
                .windows(b"example.test".len())
                .any(|part| part == b"example.test")
        );
        assert!(encoded.windows(b"path:".len()).any(|part| part == b"path:"));
        let terms = ReadTerms::decode(&terms.take_pending()).unwrap();
        let actual = PendingDependency::materialize(&encoded, recording_id, &terms, |reference| {
            Ok(parts[reference.segment as usize].clone())
        })
        .unwrap();
        assert_eq!(actual, event);
    }
}
