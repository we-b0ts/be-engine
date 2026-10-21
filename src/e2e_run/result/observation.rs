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
            Some(value) => observed_value(value, pointer),
            None => observation(E2eValuePresence::Missing, None),
        };
    }
    if pointer == "$interaction" || pointer.starts_with("$interaction/") {
        let suffix = pointer.trim_start_matches("$interaction");
        let Some(interaction) = response.get("interaction") else {
            return observation(E2eValuePresence::Missing, None);
        };
        if suffix == "/events/length" {
            return interaction
                .get("events")
                .and_then(Value::as_array)
                .map_or_else(
                    || observation(E2eValuePresence::Missing, None),
                    |events| {
                        observation(E2eValuePresence::Present, Some(Value::from(events.len())))
                    },
                );
        }
        if let Some((index, _)) = suffix
            .strip_prefix("/events/")
            .and_then(|s| s.split_once("/sse/"))
        {
            let event = index.parse::<usize>().ok().and_then(|index| {
                interaction["events"]
                    .as_array()
                    .and_then(|events| events.iter().filter(|e| e["heartbeat"] != true).nth(index))
            });
            return observation(
                if event.is_some() {
                    E2eValuePresence::Unavailable
                } else {
                    E2eValuePresence::Missing
                },
                None,
            );
        }
        let Some(value) = interaction.pointer(suffix) else {
            return observation(E2eValuePresence::Missing, None);
        };
        if suffix == "/end/close" || suffix == "/end/close/reason" {
            return observation(
                E2eValuePresence::Present,
                Some(serde_json::json!({"private": true, "code": value.get("code")})),
            );
        }
        if suffix.starts_with("/events") || suffix.is_empty() {
            // Events carry authenticated private payloads. Public diagnostics
            // describe the observation without expanding decrypted messages.
            return observation(
                E2eValuePresence::Present,
                Some(
                    serde_json::json!({"private": true, "sequence": value.get("sequence"), "heartbeat": value.get("heartbeat")}),
                ),
            );
        }
        return observed_value(value, pointer);
    }
    if pointer == "$sse_observation" || pointer.starts_with("$sse_observation/") {
        let json_pointer = format!("/{}", pointer.trim_start_matches('$'));
        return match response.pointer(&json_pointer) {
            Some(value) => observed_value(value, pointer),
            None => observation(E2eValuePresence::Missing, None),
        };
    }
    if let Some(name) = pointer.strip_prefix("$headers/") {
        if response.get("private_interaction_output_headers").is_some() {
            return observation(E2eValuePresence::Unavailable, None);
        }
        let Some(headers) = response.get("headers").and_then(Value::as_object) else {
            return observation(E2eValuePresence::Unavailable, None);
        };
        return match headers.get(name) {
            Some(value) => observed_value(value, pointer),
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
        return observed_value(&value, pointer);
    }
    let Ok(json) = serde_json::from_slice::<Value>(&decoded) else {
        return observation(E2eValuePresence::NotApplicable, None);
    };
    match json.pointer(pointer) {
        Some(value) => observed_value(value, pointer),
        None => observation(E2eValuePresence::Missing, None),
    }
}

pub(in crate::e2e_run) fn request_correlated_header_observation(
    response_path: &Path,
    request_context_path: &Path,
    request_headers_field: &str,
    name: &str,
) -> E2eValueObservation {
    let pointer = format!("$headers/{name}");
    let mut response = response_observation(response_path, &pointer);
    if response.presence != E2eValuePresence::Present {
        return response;
    }
    let request = header_observation(request_context_path, request_headers_field, name, &pointer);
    response.value = Some(serde_json::json!({
        "response": response.value,
        "request": request,
    }));
    response
}

fn header_observation(
    path: &Path,
    headers_field: &str,
    name: &str,
    pointer: &str,
) -> E2eValueObservation {
    let Ok(bytes) = std::fs::read(path) else {
        return observation(E2eValuePresence::Unavailable, None);
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return observation(E2eValuePresence::Unavailable, None);
    };
    if value.get("private_headers").is_some()
        || value.get("private_interaction_output_headers").is_some()
    {
        return observation(E2eValuePresence::Unavailable, None);
    }
    let Some(headers) = value.get(headers_field).and_then(Value::as_object) else {
        return observation(E2eValuePresence::Unavailable, None);
    };
    match headers.get(name) {
        Some(value) if protected_header_value(value) => {
            observation(E2eValuePresence::Unavailable, None)
        }
        Some(value) => observed_value(value, pointer),
        None => observation(E2eValuePresence::Missing, None),
    }
}

fn protected_header_value(value: &Value) -> bool {
    value.as_array().is_some_and(|values| {
        values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value == "<redacted>" || value.starts_with("traffic-e2e:enc:"))
        })
    })
}

fn observation(presence: E2eValuePresence, value: Option<Value>) -> E2eValueObservation {
    E2eValueObservation {
        presence,
        value,
        jwt_candidate: false,
    }
}

fn observed_value(value: &Value, pointer: &str) -> E2eValueObservation {
    E2eValueObservation {
        presence: E2eValuePresence::Present,
        jwt_candidate: jwt_candidate(value, 0),
        value: Some(bounded(value, pointer)),
    }
}

fn jwt_candidate(value: &Value, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }
    match value {
        Value::String(raw) => crate::ResponseJwtRule::is_candidate(raw),
        Value::Array(values) => values.iter().take(64).any(|v| jwt_candidate(v, depth + 1)),
        Value::Object(values) => values
            .values()
            .take(64)
            .any(|v| jwt_candidate(v, depth + 1)),
        _ => false,
    }
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
    fn sse_virtual_data_diagnostics_retain_private_availability() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("response.json");
        std::fs::write(
            &path,
            serde_json::json!({"interaction":{"events":[
                {"heartbeat":true,"message":{"data":"private-heartbeat"}},
                {"heartbeat":false,"message":{"data":"encrypted-private-event"}}
            ]}})
            .to_string(),
        )
        .unwrap();
        let observed = response_observation(&path, "$interaction/events/0/sse/data/item/id");
        assert_eq!(observed.presence, E2eValuePresence::Unavailable);
        assert!(observed.value.is_none());
        let missing = response_observation(&path, "$interaction/events/1/sse/data/item/id");
        assert_eq!(missing.presence, E2eValuePresence::Missing);
    }

    #[test]
    fn jwt_hint_survives_redaction_and_long_url_bounding_without_exposing_tokens() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let token = format!(
            "{}.{}.AA",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#),
            URL_SAFE_NO_PAD.encode(r#"{"sub":"private-user","exp":2000}"#)
        );
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("response.json");
        let url = format!("/download?padding={}&token={token}", "x".repeat(300));
        std::fs::write(&path, serde_json::json!({"body":{"encoding":"utf8","data":serde_json::json!({"access_token":token,"downloadUrl":url,"opaque_token":"secret-value"}).to_string()}}).to_string()).unwrap();
        for pointer in ["/access_token", "/downloadUrl"] {
            let value = response_observation(&path, pointer);
            assert!(value.jwt_candidate);
            let rendered = serde_json::to_string(&value).unwrap();
            assert!(!rendered.contains(&token));
            assert!(!rendered.contains("private-user"));
        }
        let opaque = response_observation(&path, "/opaque_token");
        assert!(!opaque.jwt_candidate);
        assert!(
            !serde_json::to_string(&opaque)
                .unwrap()
                .contains("secret-value")
        );
        assert!(!response_observation(&path, "/missing").jwt_candidate);
    }

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

    #[test]
    fn projects_request_context_with_x_request_id_response_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let request = temp.path().join("request.json");
        let response = temp.path().join("response.json");
        std::fs::write(
            &request,
            serde_json::to_vec(&serde_json::json!({
                "headers": {"x-request-id": ["incoming-id"]}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &response,
            serde_json::to_vec(&serde_json::json!({
                "headers": {"x-request-id": ["response-id"]}
            }))
            .unwrap(),
        )
        .unwrap();

        let observation =
            request_correlated_header_observation(&response, &request, "headers", "x-request-id");

        assert_eq!(observation.presence, E2eValuePresence::Present);
        assert_eq!(
            observation.value,
            Some(serde_json::json!({
                "response": ["response-id"],
                "request": {"presence": "present", "value": ["incoming-id"]}
            }))
        );
    }
}
