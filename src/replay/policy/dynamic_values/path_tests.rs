//! Path capture shape, clocks, atomic decisions and SQL/JSON correlation.
use super::*;
use crate::replay::assertion::time::RequestTimes;
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;

fn rule() -> DynamicValueRule {
    serde_json::from_value(json!({
        "id":"object-key", "api":"/upload",
        "targets":[{"host":"s3.example.test","port":80},{"host":"db.example.test","port":3306}],
        "capture":{"protocol":"http","target":{"host":"s3.example.test","port":80},"method":"PUT","path":"/bucket/attachments/*",
            "path_segment":{"index":2,"template":"{nonce}_{created_at}_{user_id}_{attachment_id}","fields":{
                "nonce":{"kind":"random","format":"hex","length":12},
                "created_at":{"kind":"timestamp","format":"%Y%m%d%H%M%S","timezone":"UTC"},
                "user_id":{"kind":"exact"},"attachment_id":{"kind":"exact"}}}},
        "source_evidence":"Storage:key uses UUID hex[:12], UTC now, owner and inserted attachment ID"
    })).unwrap()
}

fn segment(rule: &DynamicValueRule) -> &PathSegmentCapture {
    let DynamicValueCapture::Http {
        path_segment: Some(value),
        ..
    } = &rule.capture
    else {
        panic!("path capture")
    };
    value
}
fn clock(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

#[test]
fn path_capture_schema_rejects_ambiguous_or_unbounded_declarations() {
    let base = serde_json::to_value(rule()).unwrap();
    rule().validate().unwrap();
    let original = rule();
    assert_eq!(
        serde_yaml::from_str::<DynamicValueRule>(&serde_yaml::to_string(&original).unwrap())
            .unwrap(),
        original
    );
    let mut overlap = original.clone();
    overlap.id = "overlap".into();
    if let DynamicValueCapture::Http {
        path_segment: Some(segment),
        ..
    } = &mut overlap.capture
    {
        segment.fields.insert(
            "nonce".into(),
            PathSegmentField::Random {
                format: "hex".into(),
                length: 10,
            },
        );
    }
    assert!(config::validate(&[original, overlap]).is_err());
    for (pointer, replacement) in [
        ("/capture/json_pointer", json!("/name")),
        ("/capture/path_segment/index", json!(1)),
        (
            "/capture/path_segment/template",
            json!("{nonce}{created_at}_{user_id}_{attachment_id}"),
        ),
        (
            "/capture/path_segment/template",
            json!("{nonce}_{nonce}_{user_id}_{attachment_id}"),
        ),
        (
            "/capture/path_segment/fields/created_at/timezone",
            json!("local"),
        ),
        (
            "/capture/path_segment/fields/created_at/format",
            json!("%s"),
        ),
        ("/capture/path_segment/fields/nonce/length", json!(0)),
        (
            "/capture/path_segment/fields/nonce/format",
            json!("anything"),
        ),
        ("/value_type", json!("integer")),
    ] {
        let mut value = base.clone();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), replacement);
        let invalid: DynamicValueRule = serde_json::from_value(value).unwrap();
        assert!(invalid.validate().is_err(), "{pointer}");
    }
}

#[test]
fn path_capture_cannot_rebind_a_source_or_collapse_two_source_names() {
    let runtime = DynamicValues::new(
        vec![rule()],
        BTreeMap::from([("case".into(), "/upload".into())]),
    );
    let endpoint = TargetKey {
        host: "s3.example.test".into(),
        port: 80,
    };
    let preview = |source_nonce: &str, target_nonce: &str| {
        let a = format!("/bucket/attachments/{source_nonce}_20200101000000_7_100");
        let b = format!("/bucket/attachments/{target_nonce}_20261010000000_7_100");
        runtime
            .http(
                Some("case"),
                &endpoint,
                "PUT",
                HttpInput {
                    uri: &a,
                    body: b"file bytes",
                    request_started_at: Some(clock("2020-01-01T00:00:00Z")),
                },
                HttpInput {
                    uri: &b,
                    body: b"file bytes",
                    request_started_at: Some(clock("2026-10-10T00:00:00Z")),
                },
            )
            .unwrap()
    };
    runtime.commit(
        "case",
        preview("aabbccddeeff", "112233445566").unwrap().decision,
    );
    assert!(preview("aabbccddeeff", "665544332211").is_err());
    assert!(preview("ffeeddccbbaa", "112233445566").is_err());
    assert!(preview("aabbccddeeff", "112233445566").is_ok());
}

#[test]
fn path_timestamps_use_independent_clocks_and_inclusive_five_second_window() {
    let rule = rule();
    let capture = segment(&rule);
    let source = "aabbccddeeff_20200101000000_7_100";
    let target = "112233445566_20261010000000_7_100";
    let a = clock("2020-01-01T00:00:00Z");
    let b = clock("2026-10-10T00:00:00Z");
    for delta in [-5, 0, 5] {
        capture
            .compare(
                source,
                target,
                RequestTimes {
                    source: Some(a + TimeDelta::seconds(delta)),
                    target: Some(b - TimeDelta::seconds(delta)),
                },
            )
            .unwrap();
    }
    for times in [
        RequestTimes {
            source: Some(a + TimeDelta::milliseconds(5001)),
            target: Some(b),
        },
        RequestTimes {
            source: Some(a),
            target: Some(b - TimeDelta::milliseconds(5001)),
        },
        RequestTimes {
            source: None,
            target: Some(b),
        },
        RequestTimes {
            source: Some(a),
            target: None,
        },
    ] {
        assert!(capture.compare(source, target, times).is_err());
    }
    for invalid in [
        "112233445566_20260230000000_7_100",
        "112233445566_20261010000060_7_100",
        "112233445566_20261010000000_8_100",
        "112233445566_20261010000000_7_101",
        "not-hex-xxxx_20261010000000_7_100",
    ] {
        assert!(
            capture
                .compare(
                    source,
                    invalid,
                    RequestTimes {
                        source: Some(a),
                        target: Some(b)
                    }
                )
                .is_err(),
            "{invalid}"
        );
    }
    assert_eq!(
        capture
            .extract("/bucket/attachments/aabbccddeeff%5F20200101000000_7_100")
            .unwrap(),
        source
    );
    for path in [
        "/bucket/attachments/bad%",
        "/bucket/attachments/bad%2Fname",
        "/bucket/attachments/%ff",
        "/bucket/attachments/",
    ] {
        assert!(capture.extract(path).is_err());
    }
}

#[test]
fn pending_path_capture_preserves_payload_and_committed_binding_checks_sql_json_references() {
    let rule = rule();
    let runtime = DynamicValues::new(
        vec![rule],
        BTreeMap::from([
            ("case".into(), "/upload".into()),
            ("other".into(), "/upload".into()),
        ]),
    );
    let endpoint = TargetKey {
        host: "s3.example.test".into(),
        port: 80,
    };
    let source = "aabbccddeeff_20200101000000_7_100";
    let target = "112233445566_20261010000000_7_100";
    let left = format!("/bucket/attachments/{source}");
    let right = format!("/bucket/attachments/{target}");
    let value = runtime
        .http(
            Some("case"),
            &endpoint,
            "PUT",
            HttpInput {
                uri: &left,
                body: source.as_bytes(),
                request_started_at: Some(clock("2020-01-01T00:00:00Z")),
            },
            HttpInput {
                uri: &right,
                body: target.as_bytes(),
                request_started_at: Some(clock("2026-10-10T00:00:00Z")),
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(value.source_uri, value.actual_uri.to_string());
    assert_ne!(
        value.source_body, value.actual_body,
        "uploaded bytes must remain exact"
    );
    assert!(
        runtime.report().is_empty(),
        "preview cannot commit a failed upload"
    );
    let db = TargetKey {
        host: "db.example.test".into(),
        port: 3306,
    };
    let left =
        vec![format!("{{\"storage_key\":\"attachments/{source}\",\"stable\":1}}").into_bytes()];
    let right =
        vec![format!("{{\"stable\":1,\"storage_key\":\"attachments/{target}\"}}").into_bytes()];
    assert!(
        runtime
            .normalize_arguments(Some("case"), &db, &left, &right)
            .is_none()
    );
    runtime.commit("case", value.decision);
    let (a, b) = runtime
        .normalize_arguments(Some("case"), &db, &left, &right)
        .unwrap()
        .unwrap();
    assert_eq!(a, b);
    let wrong = vec![
        right[0]
            .iter()
            .copied()
            .map(|byte| if byte == b'6' { b'9' } else { byte })
            .collect(),
    ];
    let (a, b) = runtime
        .normalize_arguments(Some("case"), &db, &left, &wrong)
        .unwrap()
        .unwrap();
    assert_ne!(a, b);
    assert!(
        runtime
            .normalize_arguments(Some("other"), &db, &left, &right)
            .is_none()
    );
    assert!(
        runtime
            .normalize_arguments(
                Some("case"),
                &TargetKey {
                    host: db.host.clone(),
                    port: 3307
                },
                &left,
                &right
            )
            .is_none()
    );
    runtime.begin_case("case");
    assert!(
        runtime
            .normalize_arguments(Some("case"), &db, &left, &right)
            .is_none()
    );
}
