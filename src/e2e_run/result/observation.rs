use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{E2eValueObservation, E2eValuePresence};

pub(in crate::e2e_run) fn response_observation(path: &Path, pointer: &str) -> E2eValueObservation {
    response_observation_with_status(path, pointer, None)
}

pub(in crate::e2e_run) fn response_observation_with_status(
    path: &Path,
    pointer: &str,
    status: Option<u16>,
) -> E2eValueObservation {
    let Ok(bytes) = std::fs::read(path) else {
        return observation(E2eValuePresence::Unavailable, None);
    };
    let Ok(response) = serde_json::from_slice::<Value>(&bytes) else {
        return observation(E2eValuePresence::Unavailable, None);
    };
    if pointer == "$status" {
        if let Some(status) = status {
            return observation(E2eValuePresence::Present, Some(Value::from(status)));
        }
        return match response.get("status") {
            Some(value) => observation(E2eValuePresence::Present, Some(bounded(value, pointer))),
            None => observation(E2eValuePresence::Missing, None),
        };
    }
    if let Some(name) = pointer.strip_prefix("$headers/") {
        let Some(headers) = response.get("headers").and_then(Value::as_object) else {
            return observation(E2eValuePresence::Unavailable, None);
        };
        return match headers.get(name) {
            Some(value) => observation(E2eValuePresence::Present, Some(bounded(value, pointer))),
            None => observation(E2eValuePresence::Missing, None),
        };
    }
    let Some(body) = response.get("body").or_else(|| response.get("frame")) else {
        return observation(E2eValuePresence::Missing, None);
    };
    let Some(data) = body.get("data").and_then(Value::as_str) else {
        return observation(E2eValuePresence::Missing, None);
    };
    let decoded = match body.get("encoding").and_then(Value::as_str) {
        Some("utf8") => data.as_bytes().to_vec(),
        Some("base64") => match STANDARD.decode(data) {
            Ok(value) => value,
            Err(_) => return observation(E2eValuePresence::Unavailable, None),
        },
        _ => return observation(E2eValuePresence::Unavailable, None),
    };
    if pointer == "$body" {
        let value = String::from_utf8(decoded)
            .map(Value::String)
            .unwrap_or_else(|error| {
                Value::String(format!("<binary bytes={}>", error.as_bytes().len()))
            });
        return observation(E2eValuePresence::Present, Some(bounded(&value, pointer)));
    }
    let Ok(json) = serde_json::from_slice::<Value>(&decoded) else {
        return observation(E2eValuePresence::NotApplicable, None);
    };
    match json.pointer(pointer) {
        Some(value) => observation(E2eValuePresence::Present, Some(bounded(value, pointer))),
        None => observation(E2eValuePresence::Missing, None),
    }
}

fn observation(presence: E2eValuePresence, value: Option<Value>) -> E2eValueObservation {
    E2eValueObservation { presence, value }
}

pub(super) fn bounded(value: &Value, pointer: &str) -> Value {
    if sensitive_pointer(pointer) {
        return Value::String(match value {
            Value::String(value) => format!("<redacted string bytes={}>", value.len()),
            _ => "<redacted>".to_string(),
        });
    }
    match value {
        Value::String(value) if value.len() > 256 => {
            Value::String(format!("<string bytes={}>", value.len()))
        }
        Value::Array(values) => {
            let bytes = serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len());
            if bytes > 1_024 {
                Value::String(format!("<array items={} bytes={bytes}>", values.len()))
            } else {
                value.clone()
            }
        }
        Value::Object(values) => {
            let bytes = serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len());
            if bytes > 1_024 {
                Value::String(format!("<object keys={} bytes={bytes}>", values.len()))
            } else {
                value.clone()
            }
        }
        _ => value.clone(),
    }
}

fn sensitive_pointer(pointer: &str) -> bool {
    pointer.split('/').any(|token| {
        let token = token.to_ascii_lowercase();
        [
            "authorization",
            "cookie",
            "password",
            "passwd",
            "secret",
            "token",
            "ticket",
            "credential",
        ]
        .iter()
        .any(|sensitive| token.contains(sensitive))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_response_header_presence_and_values_for_api_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let response = temp.path().join("response.json");
        std::fs::write(
            &response,
            serde_json::to_vec(&serde_json::json!({
                "status": 200,
                "headers": {"vary": ["Origin"]},
                "body": {"encoding": "utf8", "data": "{}", "truncated": false}
            }))
            .unwrap(),
        )
        .unwrap();

        let present = response_observation(&response, "$headers/vary");
        assert_eq!(present.presence, E2eValuePresence::Present);
        assert_eq!(present.value, Some(serde_json::json!(["Origin"])));
        let missing = response_observation(&response, "$headers/location");
        assert_eq!(missing.presence, E2eValuePresence::Missing);
        assert_eq!(missing.value, None);
    }
}
