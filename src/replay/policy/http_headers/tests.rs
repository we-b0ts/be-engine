use super::*;
use crate::replay::policy::config::{ReplayPolicyDocument, validate_document};

fn document(headers: &str, path: &str) -> ReplayPolicyDocument {
    serde_yaml::from_str(&format!(
        r#"version: 3
expected_response: assertions_only
dependency_rules:
- id: signing-time
  protocol: http
  target: {{host: storage.example.test, port: 9100}}
  http:
    method: GET
    path: {path}
    headers:
{headers}
"#
    ))
    .unwrap()
}

const FIELD: &str = "      x-amz-date: {kind: timestamp, format: amz_date, source_evidence: 'sdk.py:build_headers uses UTC time'}";

#[test]
fn dependency_header_timestamp_schema_is_bounded_and_requires_source_proof() {
    assert!(validate_document(&document(FIELD, "/bucket/objects/*")).is_ok());
    for header in [
        "authorization",
        "cookie",
        "user-agent",
        "connection",
        "host",
        "x-request-id",
        "x-api-token",
        "x-recorder-clock",
    ] {
        assert!(
            validate_document(&document(
                &FIELD.replace("x-amz-date:", &format!("{header}:")),
                "/bucket"
            ))
            .is_err()
        );
    }
    for path in ["/bucket/**", "/bucket/object*", "/bucket?secret=1"] {
        assert!(validate_document(&document(FIELD, path)).is_err());
    }
    let no_proof = FIELD.replace("'sdk.py:build_headers uses UTC time'", "''");
    assert!(validate_document(&document(&no_proof, "/bucket")).is_err());
    let mut old = document(FIELD, "/bucket");
    old.version = 1;
    assert!(validate_document(&old).is_err());
    let duplicate = format!("{FIELD}\n{}", FIELD.replace("x-amz-date", "X-Amz-Date"));
    assert!(validate_document(&document(&duplicate, "/bucket")).is_err());
    let mut scoped = document(FIELD, "/bucket");
    scoped.dependency_rules[0].replay_scope = ReplayScope::RecordingRun;
    assert!(validate_document(&scoped).is_err());
}

#[test]
fn dependency_header_timestamp_rejects_configurable_tolerance_and_unknown_formats() {
    for text in [
        FIELD.replace("format: amz_date", "format: amz_date, tolerance: 5s"),
        FIELD.replace("kind: timestamp", "kind: ignore"),
        FIELD.replace("format: amz_date", "format: arbitrary"),
    ] {
        // Parse the field directly so deny_unknown_fields is exercised before validation.
        let field = text.split_once(": ").unwrap().1;
        assert!(
            serde_yaml::from_str::<HttpHeaderRule>(field).is_err(),
            "{text}"
        );
    }
}

#[test]
fn dependency_header_timestamp_rejects_overlapping_path_patterns() {
    let mut doc = document(FIELD, "/bucket/*");
    let mut overlapping = doc.dependency_rules[0].clone();
    overlapping.id = "other".into();
    overlapping.http.as_mut().unwrap().path = "/bucket/object".into();
    doc.dependency_rules.push(overlapping);
    assert!(validate_document(&doc).is_err());
    doc.dependency_rules[1].http.as_mut().unwrap().path = "/other/object".into();
    assert!(validate_document(&doc).is_ok());
}
