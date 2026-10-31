use super::*;
use serde_json::json;

#[test]
fn ordinary_response_clock_uses_only_its_independent_completion_observation() {
    let response: ExpectedResponse = serde_json::from_value(json!({
        "timestamp": "1970-01-01T00:19:20Z", "duration_ms": 160000
    }))
    .unwrap();
    assert_eq!(
        response.response_completed_at(),
        chrono::DateTime::from_timestamp(1160, 0)
    );
    for timestamp in [json!(null), json!("invalid-clock"), json!(1160)] {
        let response: ExpectedResponse = serde_json::from_value(json!({
            "timestamp": timestamp, "duration_ms": 160000
        }))
        .unwrap();
        assert!(response.response_completed_at().is_none());
    }
}

#[test]
fn stream_clock_recovers_capture_start_without_request_fallback() {
    let mut value = json!({"timestamp":"1970-01-01T00:19:20Z","duration_ms":160000,
        "interaction":{"version":1,"protocol":"sse","events":[],"end":{"reason":"server_eof","offset_ms":160000,"clean":true}}});
    let response: ExpectedResponse = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        response.interaction_started_at(),
        chrono::DateTime::from_timestamp(1000, 0)
    );
    for duration in [
        json!(-1),
        json!("160000"),
        json!(u64::MAX),
        serde_json::Value::Null,
    ] {
        value["duration_ms"] = duration;
        let response: ExpectedResponse = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(response.interaction_started_at(), None);
    }
    value["duration_ms"] = json!(160000);
    value["timestamp"] = json!("invalid-clock");
    let response: ExpectedResponse = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(response.interaction_started_at(), None);
    value["interaction"] = serde_json::Value::Null;
    let response: ExpectedResponse = serde_json::from_value(value).unwrap();
    assert_eq!(response.interaction_started_at(), None);
}
