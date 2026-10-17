use super::*;
use serde_json::Value;

fn rule(format: &str, pointer: &str, mode: &str) -> String {
    format!(
        "response_rules:\n  json:\n    'GET /api/resource/token':\n      timestamp:\n        - pointer: {pointer}\n          format: {format}\n          time: {mode}\n          source_evidence: SessionService:create sets expiry from current time plus TTL\n          source_example: '2023-11-14T23:13:20Z'\n          target_example: '2023-11-14T23:14:20Z'\n"
    )
}

#[test]
fn relative_timestamp_accepts_expiry_offsets_formats_and_timezone_equivalence() {
    for (format, source, target) in [
        (
            "rfc3339",
            json!("2023-11-14T23:13:20Z"),
            json!("2023-11-14T23:14:20Z"),
        ),
        (
            "rfc3339",
            json!("2023-11-15T07:13:20+08:00"),
            json!("2023-11-14T23:14:20Z"),
        ),
        (
            "rfc3339",
            json!("2023-11-14T23:13:20.118135Z"),
            json!("2023-11-14T23:14:20.118135Z"),
        ),
        ("unix_seconds", json!(1700003600), json!(1700003660)),
        (
            "unix_milliseconds",
            json!(1700003600000_i64),
            json!(1700003660000_i64),
        ),
    ] {
        let (_temp, options) = write_raw_case(
            &rule(format, "/expires_at", "preserve_relative"),
            &json!({"expires_at":source,"stable":"checked"}).to_string(),
            &json!({"expires_at":target,"stable":"checked"}).to_string(),
        );
        let report = assert_recorded_response(options).unwrap();
        assert!(report.passed, "{format}: {report:?}");
        assert_eq!(report.applied_body_rule_ids.len(), 1);
    }
}

#[test]
fn relative_timestamp_preserves_ttl_and_uses_inclusive_five_second_tolerance() {
    for (target, valid) in [
        ("2023-11-14T23:14:15Z", true),
        ("2023-11-14T23:14:25Z", true),
        ("2023-11-14T23:14:14.999999Z", false),
        ("2023-11-14T23:14:25.000001Z", false),
        ("2023-11-14T22:14:20Z", false), // Dropped TTL.
        ("2023-11-14T23:44:20Z", false), // Wrong TTL.
        ("2023-11-14T23:13:20Z", false), // Same literal despite later request.
    ] {
        let (_temp, options) = write_raw_case(
            &rule("rfc3339", "/expires_at", "preserve_relative"),
            r#"{"expires_at":"2023-11-14T23:13:20Z"}"#,
            &json!({"expires_at":target}).to_string(),
        );
        let report = assert_recorded_response(options).unwrap();
        assert_eq!(report.passed, valid, "{target}: {report:?}");
        if !valid {
            assert_eq!(
                report.differences[0].kind,
                ResponseDifferenceKind::DurationDeltaMismatch
            );
        }
    }
}

#[test]
fn relative_timestamp_rejects_invalid_types_missing_fields_and_other_field_changes() {
    for (source, target, kind, pointer) in [
        (
            json!("2023-11-14T23:13:20Z"),
            json!("invalid"),
            ResponseDifferenceKind::TimeFieldInvalid,
            "/expires_at",
        ),
        (
            json!("invalid"),
            json!("2023-11-14T23:14:20Z"),
            ResponseDifferenceKind::TimeFieldInvalid,
            "/expires_at",
        ),
        (
            json!("2023-11-14T23:13:20Z"),
            json!(1700003660),
            ResponseDifferenceKind::TimeFieldInvalid,
            "/expires_at",
        ),
        (
            json!("2023-11-14T23:13:20Z"),
            Value::Null,
            ResponseDifferenceKind::TimeFieldInvalid,
            "/expires_at",
        ),
    ] {
        let (_temp, options) = write_raw_case(
            &rule("rfc3339", "/expires_at", "preserve_relative"),
            &json!({"expires_at":source}).to_string(),
            &json!({"expires_at":target}).to_string(),
        );
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed);
        assert!(
            report
                .differences
                .iter()
                .any(|d| d.kind == kind && d.pointer == pointer)
        );
    }
    for (target, pointer, kind) in [
        (
            json!({"stable":1}),
            "/expires_at",
            ResponseDifferenceKind::MissingActual,
        ),
        (
            json!({"expires_at":"2023-11-14T23:14:20Z","stable":2}),
            "/stable",
            ResponseDifferenceKind::ValueMismatch,
        ),
    ] {
        let (_temp, options) = write_raw_case(
            &rule("rfc3339", "/expires_at", "preserve_relative"),
            r#"{"expires_at":"2023-11-14T23:13:20Z","stable":1}"#,
            &target.to_string(),
        );
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed);
        assert!(
            report
                .differences
                .iter()
                .any(|d| d.pointer == pointer && d.kind == kind)
        );
    }
}

#[test]
fn relative_timestamp_requires_both_captured_request_clocks() {
    for source_missing in [true, false] {
        let (_temp, options) = write_raw_case(
            &rule("rfc3339", "/expires_at", "preserve_relative"),
            r#"{"expires_at":"2023-11-14T23:13:20Z"}"#,
            r#"{"expires_at":"2023-11-14T23:14:20Z"}"#,
        );
        let (path, key) = if source_missing {
            (&options.request, "timestamp")
        } else {
            (&options.actual_response, "request_sent_at")
        };
        let mut document: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        document.as_object_mut().unwrap().remove(key);
        fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed);
        assert_eq!(
            report.differences[0].kind,
            ResponseDifferenceKind::TimeReferenceMissing
        );
    }
}

#[test]
fn relative_timestamp_array_expansion_checks_each_item_and_keeps_default_semantics() {
    let (_temp, options) = write_raw_case(
        &rule("rfc3339", "/items/*/expires_at", "preserve_relative"),
        r#"{"items":[{"expires_at":"2023-11-14T23:13:20Z"},{"expires_at":"2023-11-14T23:13:20Z"}]}"#,
        r#"{"items":[{"expires_at":"2023-11-14T23:14:20Z"},{"expires_at":"2023-11-14T23:44:20Z"}]}"#,
    );
    let report = assert_recorded_response(options).unwrap();
    assert!(!report.passed);
    assert_eq!(report.differences[0].pointer, "/items/1/expires_at");
    let (_temp, options) = write_raw_case(
        &rule("rfc3339", "/expires_at", "request_window")
            .replace("          time: request_window\n", ""),
        r#"{"expires_at":"2023-11-14T23:13:20Z"}"#,
        r#"{"expires_at":"2023-11-14T23:14:20Z"}"#,
    );
    let report = assert_recorded_response(options).unwrap();
    assert!(!report.passed);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::TimestampOutsideRequestWindow
    );
}
