use super::*;
use chrono::Duration;
use serde_json::{Value, json};

fn record() -> RecordedHttpExchange {
    serde_json::from_value(json!({
        "scheme":"http", "method":"GET", "uri":"/object",
        "request_body":{"encoding":"utf8","truncated":false,"data":""},
        "timestamp":"2026-10-03T16:00:31Z", "duration_ms":30000,
        "response_status":200
    }))
    .unwrap()
}

#[test]
fn legacy_completion_and_duration_resolve_the_dependency_clock() {
    let record = record();
    let reference = source(&record).unwrap();
    let expected: DateTime<Utc> = "2026-10-03T16:00:01Z".parse().unwrap();
    assert_eq!(reference, expected);
    let mut record = record;
    record.native.duration_ms = Some(json!(0));
    assert_eq!(source(&record).unwrap(), record.native.timestamp.unwrap());
}

#[test]
fn explicit_start_always_wins_over_inferred_or_unusable_metadata() {
    let mut record = record();
    let explicit = record.native.timestamp.unwrap() - Duration::days(1);
    record.native.request_started_at = Some(explicit);
    for duration in [json!(30000), json!(-1), json!("invalid"), Value::Null] {
        record.native.duration_ms = Some(duration);
        assert_eq!(source(&record), Some(explicit));
    }
    record.native.timestamp = None;
    assert_eq!(source(&record).unwrap(), explicit);
}

#[test]
fn incomplete_invalid_and_overflowing_timing_has_no_fallback() {
    for duration in [
        Value::Null,
        json!(-1),
        json!(1.5),
        json!("1000"),
        json!(true),
        json!(u64::MAX),
        json!(i64::MAX),
    ] {
        let mut record = record();
        record.native.duration_ms = Some(duration);
        assert!(source(&record).is_none());
    }
    let mut record = record();
    record.native.duration_ms = None;
    assert!(source(&record).is_none());
    record.native.duration_ms = Some(json!(30000));
    record.native.timestamp = None;
    assert!(source(&record).is_none());
    record.native.timestamp = Some(DateTime::<Utc>::MIN_UTC);
    assert!(source(&record).is_none());
}
