use super::*;
use serde_json::json;

#[test]
fn stream_clock_recovers_capture_start_and_keeps_legacy_fallback_strict() {
    let fallback = chrono::DateTime::from_timestamp(1002, 500_000_000);
    let mut value = json!({"timestamp":"1970-01-01T00:19:20Z","duration_ms":160000,
        "interaction":{"version":1,"protocol":"sse","events":[],"end":{"reason":"server_eof","offset_ms":160000,"clean":true}}});
    let response: ExpectedResponse = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        response.clock_start(fallback),
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
        assert_eq!(response.clock_start(fallback), fallback);
    }
    value["duration_ms"] = json!(160000);
    value["timestamp"] = json!("invalid-clock");
    let response: ExpectedResponse = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(response.clock_start(fallback), fallback);
    value["interaction"] = serde_json::Value::Null;
    let response: ExpectedResponse = serde_json::from_value(value).unwrap();
    assert_eq!(response.clock_start(fallback), fallback);
}
