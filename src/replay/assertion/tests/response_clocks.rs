use super::*;

fn response_case(target_time: i64) -> (tempfile::TempDir, ResponseAssertionOptions) {
    let (temp, options) = write_raw_case(
        "",
        &json!({"created_at":1100,"stable":true}).to_string(),
        &json!({"created_at":target_time,"stable":true}).to_string(),
    );
    fs::write(
        &options.policy,
        "format: traffic-policy/v3\njson:\n  fields:\n    /created_at: {kind: time, formats: [unix_seconds]}\n",
    )
    .unwrap();
    for (path, field, seconds) in [
        (&options.request, "timestamp", 1000),
        (&options.expected_response, "timestamp", 1100),
        (&options.actual_response, "request_sent_at", 2000),
        (&options.actual_response, "response_completed_at", 2300),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        value[field] =
            serde_json::to_value(chrono::DateTime::from_timestamp(seconds, 0).unwrap()).unwrap();
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
    (temp, options)
}

#[test]
fn ordinary_response_time_uses_completion_when_api_durations_differ() {
    let (_temp, options) = response_case(2300);
    let expected_path = options.expected_response.clone();
    let before = fs::read(&expected_path).unwrap();
    let report = assert_recorded_response(options).unwrap();
    assert!(report.passed, "{:?}", report.differences);
    assert_eq!(fs::read(expected_path).unwrap(), before);

    // A timestamp sampled earlier in the request may be reused at completion.
    let (_temp, options) = response_case(2100);
    let report = assert_recorded_response(options).unwrap();
    assert!(report.passed, "{:?}", report.differences);

    // The 303-second error exceeds the 300-second elapsed budget plus 2 seconds.
    let (_temp, options) = response_case(1997);
    let report = assert_recorded_response(options).unwrap();
    assert!(!report.passed);
    assert!(report.differences.iter().any(|difference| {
        difference.pointer == "/created_at"
            && difference.kind == ResponseDifferenceKind::DurationDeltaMismatch
    }));
}

#[test]
fn missing_response_clock_never_uses_available_request_clocks() {
    for source_missing in [true, false] {
        let (_temp, options) = response_case(2300);
        let (path, field) = if source_missing {
            (&options.expected_response, "timestamp")
        } else {
            (&options.actual_response, "response_completed_at")
        };
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        value.as_object_mut().unwrap().remove(field);
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed);
        assert!(report.differences.iter().any(|difference| {
            difference.pointer == "/created_at"
                && difference.kind == ResponseDifferenceKind::TimeReferenceMissing
        }));
    }
}

#[test]
fn response_observation_does_not_require_an_unrelated_request_time_contract() {
    let (_temp, options) = response_case(2300);
    for (path, field) in [
        (&options.request, "timestamp"),
        (&options.actual_response, "request_sent_at"),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        value.as_object_mut().unwrap().remove(field);
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
    let report = assert_recorded_response(options).unwrap();
    assert!(report.passed, "{:?}", report.differences);
}
