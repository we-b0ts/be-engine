//! Primary adapter output enters the actual assertion path with typed provenance.
use super::*;

fn evaluate(options: &ResponseAssertionOptions) -> Result<ResponseAssertionCaseReport> {
    assert_recorded_response(ResponseAssertionOptions {
        case_id: options.case_id.clone(),
        request: options.request.clone(),
        expected_response: options.expected_response.clone(),
        actual_response: options.actual_response.clone(),
        policy: options.policy.clone(),
    })
}

fn with_primary(options: &ResponseAssertionOptions) -> serde_json::Value {
    let mut actual: serde_json::Value =
        serde_json::from_slice(&fs::read(&options.actual_response).unwrap()).unwrap();
    actual["primary"] = json!({
        "api": {"protocol":"http", "method":"GET", "route":"/api/resource/token"},
        "clocks": {
            "case": {"source":"2023-11-14T22:13:20Z", "target":"2023-11-14T22:14:20Z"},
            "dependency": {"source":null,"target":null},
            "delivery": {"source":null,"target":null}
        }
    });
    actual
}

#[test]
fn primary_metadata_preserves_independent_status_and_body_assertions() {
    let (_temp, options) = write_raw_case("", r#"{"ok":true}"#, r#"{"ok":true}"#);
    let actual = with_primary(&options);
    fs::write(&options.actual_response, actual.to_string()).unwrap();
    assert!(evaluate(&options).unwrap().passed);

    let mut failed = actual;
    failed["status"] = json!(500);
    fs::write(&options.actual_response, failed.to_string()).unwrap();
    let report = evaluate(&options).unwrap();
    assert!(!report.passed);
    assert!(
        report
            .differences
            .iter()
            .any(|difference| { difference.kind == ResponseDifferenceKind::StatusMismatch })
    );

    failed["status"] = json!(200);
    failed["body"]["data"] = json!(r#"{"ok":false}"#);
    fs::write(&options.actual_response, failed.to_string()).unwrap();
    assert!(!evaluate(&options).unwrap().passed);
}

#[test]
fn non_json_target_response_preserves_status_and_body_differences() {
    let (_temp, options) = write_raw_case(
        "",
        r#"{"id":"11111111-1111-4111-8111-111111111111"}"#,
        "fallback upstream unavailable",
    );
    fs::write(
        &options.policy,
        "format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [uuid]}\n",
    )
    .unwrap();
    for status in [200, 502] {
        let mut actual = with_primary(&options);
        actual["status"] = json!(status);
        fs::write(&options.actual_response, actual.to_string()).unwrap();
        let report = evaluate(&options).unwrap();
        assert!(!report.passed);
        assert_eq!(report.body_codec, ResponseBodyCodec::Json);
        assert!(report.identity_pairs.is_empty());
        assert!(report.applied_body_rule_ids.is_empty());
        assert!(
            report
                .differences
                .iter()
                .any(|difference| { difference.kind == ResponseDifferenceKind::ValueMismatch })
        );
        assert_eq!(
            report
                .differences
                .iter()
                .any(|difference| { difference.kind == ResponseDifferenceKind::StatusMismatch }),
            status != 200
        );
    }
}

#[test]
fn primary_metadata_cannot_override_input_identity_or_observed_clocks() {
    let (_temp, options) = write_raw_case("", "{}", "{}");
    let original = with_primary(&options);
    for (pointer, replacement, message) in [
        (
            "/primary/api/route",
            json!("/another-api"),
            "primary API identity",
        ),
        ("/primary/clocks/case/source", json!(null), "primary clocks"),
        (
            "/primary/clocks/case/target",
            json!("2023-11-14T22:13:20Z"),
            "primary clocks",
        ),
        (
            "/primary/clocks/dependency/target",
            json!("2023-11-14T22:14:20Z"),
            "dependency or delivery clocks",
        ),
    ] {
        let mut invalid = original.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        fs::write(&options.actual_response, invalid.to_string()).unwrap();
        let error = evaluate(&options).unwrap_err();
        assert!(format!("{error:#}").contains(message), "{error:#}");
    }
}

#[test]
fn http_extension_method_named_motan_uses_the_http_assertion_adapter() {
    let (_temp, options) = write_raw_case("", "{}", "{}");
    let mut request: serde_json::Value =
        serde_json::from_slice(&fs::read(&options.request).unwrap()).unwrap();
    request["method"] = json!("MOTAN");
    fs::write(&options.request, request.to_string()).unwrap();
    let report = evaluate(&options).unwrap();
    assert!(report.passed);
    assert_eq!(report.gateway_protocol, ResponseGatewayProtocol::Http);
}

#[cfg(any())]
#[test]
fn native_motan_version_selects_native_assertion_independently_of_the_method_label() {
    let (_temp, options) = write_motan2_case(
        Some("3"),
        Some("1"),
        "value",
        "value",
        b"business",
        b"business",
    );
    let mut request: serde_json::Value =
        serde_json::from_slice(&fs::read(&options.request).unwrap()).unwrap();
    request["method"] = json!("POST");
    fs::write(&options.request, request.to_string()).unwrap();
    let report = evaluate(&options).unwrap();
    assert!(report.passed);
    assert_eq!(report.gateway_protocol, ResponseGatewayProtocol::Motan2);
}
