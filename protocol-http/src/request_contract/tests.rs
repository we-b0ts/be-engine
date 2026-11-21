use super::*;

#[test]
fn opaque_body_comparison_runs_after_native_request_positions_match() {
    let record: RecordedExchange = serde_json::from_value(serde_json::json!({
        "scheme":"http", "method":"POST", "uri":"/object?a=1",
        "request_body":{"encoding":"utf8","truncated":false,"data":"source"}
    }))
    .unwrap();
    let calls = std::cell::Cell::new(0);
    let values = |source: &[u8], target: &[u8]| {
        assert_eq!(source, b"source");
        assert_eq!(target, b"target");
        calls.set(calls.get() + 1);
        true
    };
    assert_eq!(
        compare_request(
            &record,
            &Method::POST,
            &"/object?a=1".parse().unwrap(),
            b"target",
            &[],
            values
        ),
        (None, None)
    );
    for (method, uri) in [
        (Method::GET, "/object?a=1"),
        (Method::POST, "/other?a=1"),
        (Method::POST, "/object?a=2"),
    ] {
        assert!(
            compare_request(
                &record,
                &method,
                &uri.parse().unwrap(),
                b"target",
                &[],
                values
            )
            .0
            .is_some()
        );
    }
    assert_eq!(calls.get(), 1);
}

#[test]
fn ignored_query_values_are_still_required_on_both_requests() {
    let ignored = vec!["signature".to_string()];
    assert!(
        uri_mismatch_reason(
            "/path?a=1&Signature=recorded",
            "/path?Signature=current&a=1",
            &ignored,
        )
        .is_none()
    );
    assert!(uri_mismatch_reason("/path?a=1&Signature=recorded", "/path?a=1", &ignored,).is_some());
}

#[test]
fn uri_mismatch_diagnostics_never_include_query_values() {
    let ignored = vec!["signature".to_string()];
    let reason = uri_mismatch_reason(
        "/path?a=recorded-secret&Signature=recorded-signature",
        "/path?a=current-secret&Signature=current-signature",
        &ignored,
    )
    .unwrap();
    assert_eq!(reason, "HTTP stable query parameter values differed for: a");
    assert!(!reason.contains("secret"));
    assert!(!reason.contains("signature"));

    let reason = uri_mismatch_reason(
        "/path?a=1&Signature=recorded-signature",
        "/path?b=1",
        &ignored,
    )
    .unwrap();
    assert_eq!(
        reason,
        "HTTP ignored query parameter presence differed: signature (recorded 1, actual 0)"
    );
    assert!(!reason.contains("recorded-signature"));
}
