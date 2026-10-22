//! On-demand private SSE evidence; decrypted payloads never enter saved reports.
use std::path::Path;

use serde_json::{Value, json};

use super::E2eCaseResponseDifference;

const MAX_FRAMES: usize = 128;
const MAX_DIFFERENCES: usize = 20;
const MAX_NODES: usize = 4096;
const MAX_VALUE_BYTES: usize = 4096;

pub(super) fn diagnose_page(
    differences: &mut [E2eCaseResponseDifference],
    expected: &Path,
    actual: &Path,
) {
    if !differences
        .iter()
        .any(|d| d.pointer.starts_with("$interaction/events/"))
    {
        return;
    }
    // Authenticate and read each channel once per page, rather than once per frame.
    let expected = OutputEvidence::read(expected);
    let actual = OutputEvidence::read(actual);
    for difference in differences {
        let Some(suffix) = difference.pointer.strip_prefix("$interaction/events/") else {
            continue;
        };
        if suffix == "length" {
            difference.interaction_diagnosis = Some(json!({
                "expected": expected.inventory(), "actual": actual.inventory(),
            }));
        } else if let Some(index) = suffix.split('/').next().and_then(|s| s.parse().ok()) {
            let (source_summary, source) = expected.event(index);
            let (target_summary, target) = actual.event(index);
            let mut raw = RawDifferences::default();
            if let (Some(source), Some(target)) = (&source, &target) {
                raw.compare("", Some(source), Some(target), 0);
            }
            difference.interaction_diagnosis = Some(json!({
                "expected": source_summary, "actual": target_summary,
                "raw_json_differences": raw.values,
                "raw_json_differences_truncated": raw.truncated,
                "comparison": "raw_json_before_contracts",
            }));
        }
    }
}

struct OutputEvidence(Option<Value>);

impl OutputEvidence {
    fn read(path: &Path) -> Self {
        let response = (|| {
            let mut response: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
            crate::interaction::private::decrypt_output(&mut response, path).ok()?;
            Some(response)
        })();
        Self(response)
    }

    fn events(&self) -> Option<impl Iterator<Item = &Value>> {
        let interaction = self.0.as_ref()?.get("interaction")?;
        if interaction["protocol"] != "sse" {
            return None;
        }
        Some(
            interaction["events"]
                .as_array()?
                .iter()
                .filter(|e| e["heartbeat"] != true),
        )
    }

    fn event(&self, index: usize) -> (Value, Option<Value>) {
        let Some(mut events) = self.events() else {
            return (unavailable(), None);
        };
        let Some(event) = events.nth(index) else {
            return (json!({"presence":"missing"}), None);
        };
        summarize_event(event)
    }

    fn inventory(&self) -> Value {
        let Some(events) = self.events() else {
            return unavailable();
        };
        let mut frames = Vec::new();
        let mut count: usize = 0;
        for event in events {
            if frames.len() < MAX_FRAMES {
                let (mut summary, _) = summarize_event(event);
                summary
                    .as_object_mut()
                    .expect("event summary")
                    .remove("data");
                frames.push(summary);
            }
            count += 1;
        }
        json!({"presence":"present", "frames":frames, "omitted_frames":count.saturating_sub(MAX_FRAMES)})
    }
}

fn unavailable() -> Value {
    // Never treat unreadable evidence as missing data.
    json!({"presence":"unavailable", "reason":"private_sse_evidence_unavailable"})
}

fn summarize_event(event: &Value) -> (Value, Option<Value>) {
    let decoded = (|| {
        let message = serde_json::from_value(event.get("message")?.clone()).ok()?;
        crate::replay::decode_sse(&message).ok()
    })();
    let Some(sse) = decoded else {
        return (unavailable(), None);
    };
    let data = crate::json_value::parse(sse.data.as_bytes());
    let summary = json!({
        "presence":"present", "private":true, "sequence":event.get("sequence"),
        "event":bounded(&json!(sse.event.as_deref().unwrap_or("message"))),
        "id":sse.id.as_ref().map(|id| bounded(&json!(id))), "retry":sse.retry,
        "json_type":data.as_ref().and_then(|v| v.get("type")).map(bounded),
        "data":bounded(data.as_ref().unwrap_or(&Value::String(sse.data))),
    });
    (summary, data)
}

fn bounded(value: &Value) -> Value {
    let text = serde_json::to_string(value).expect("JSON value");
    if text.len() <= MAX_VALUE_BYTES {
        return value.clone();
    }
    let mut end = MAX_VALUE_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    json!({"truncated":true, "bytes":text.len(), "preview":&text[..end]})
}

fn observed(value: Option<&Value>) -> Value {
    let Some(value) = value else {
        return json!({"presence":"missing"});
    };
    let kind = match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    json!({"presence":"present", "type":kind, "value":bounded(value)})
}

#[derive(Default)]
struct RawDifferences {
    values: Vec<Value>,
    nodes: usize,
    truncated: bool,
}

impl RawDifferences {
    fn compare(
        &mut self,
        pointer: &str,
        source: Option<&Value>,
        target: Option<&Value>,
        depth: usize,
    ) {
        self.nodes += 1;
        if self.values.len() >= MAX_DIFFERENCES || self.nodes > MAX_NODES || pointer.len() > 1024 {
            self.truncated = true;
            return;
        }
        if source == target {
            return;
        }
        match (source, target) {
            (Some(Value::Object(source)), Some(Value::Object(target))) if depth < 16 => {
                let keys = source
                    .keys()
                    .chain(target.keys().filter(|key| !source.contains_key(*key)));
                for key in keys {
                    let escaped = key.replace('~', "~0").replace('/', "~1");
                    self.compare(
                        &format!("{pointer}/{escaped}"),
                        source.get(key),
                        target.get(key),
                        depth + 1,
                    );
                    if self.truncated {
                        break;
                    }
                }
            }
            (Some(Value::Array(source)), Some(Value::Array(target))) if depth < 16 => {
                for index in 0..source.len().max(target.len()) {
                    self.compare(
                        &format!("{pointer}/{index}"),
                        source.get(index),
                        target.get(index),
                        depth + 1,
                    );
                    if self.truncated {
                        break;
                    }
                }
            }
            _ => self.values.push(json!({
                "pointer": pointer, "expected":observed(source), "actual":observed(target),
            })),
        }
    }
}

#[cfg(test)]
mod tests;
