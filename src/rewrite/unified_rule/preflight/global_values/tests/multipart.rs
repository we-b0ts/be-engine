//! Protected multipart witnesses retain their physical envelope and native body.
use super::*;
use base64::engine::general_purpose::STANDARD;

fn envelope(boundary: &str, content: &str) -> Value {
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"file.txt\"\r\n\r\n{content}\r\n--{boundary}--\r\n"
    );
    json!({"protocol":"http", "exchange_id":boundary, "scheme":"http",
        "endpoint":{"host":"upload.test","port":80}, "method":"POST", "uri":"/upload?mode=original",
        "request_headers":{"content-type":[format!("multipart/form-data; boundary={boundary}")], "authorization":["Bearer same"]},
        "request_body":STANDARD.encode(body), "request_started_at":null})
}

#[test]
fn global_preflight_reuses_native_multipart_comparison_without_counting_json_coverage() {
    let event = json!({"event_type":"http_exchange"});
    let source = envelope("source", "unchanged");
    let target = envelope("target-longer", "unchanged");
    let encode = |value: &Value| serde_json::to_vec(value).unwrap();
    let policy = policy();
    let comparison = compare(
        &event,
        Surface::DependencyRequest,
        &encode(&source),
        &encode(&target),
        &policy,
        AnchorClocks::default(),
    )
    .unwrap();
    assert!(comparison.passed());
    assert!(comparison.evaluated.is_empty());
    for (field, changed) in [
        ("endpoint", json!({"host":"other.test","port":80})),
        ("method", json!("PUT")),
        ("uri", json!("/upload?mode=changed")),
        (
            "request_headers",
            json!({"content-type":["multipart/form-data; boundary=target-longer"],"authorization":["Bearer changed"]}),
        ),
        (
            "request_body",
            envelope("target-longer", "changed")["request_body"].clone(),
        ),
    ] {
        let mut target = target.clone();
        target[field] = changed;
        assert!(
            compare(
                &event,
                Surface::DependencyRequest,
                &encode(&source),
                &encode(&target),
                &policy,
                AnchorClocks::default()
            )
            .is_err(),
            "{field} must remain strict"
        );
    }
    let mut malformed = target.clone();
    malformed["request_body"] = STANDARD.encode("malformed Target").into();
    assert!(
        compare(
            &event,
            Surface::DependencyRequest,
            &encode(&source),
            &encode(&malformed),
            &policy,
            AnchorClocks::default()
        )
        .is_err()
    );
}
