use super::*;
use crate::interaction::model::{EndObservation, EndReason, OutputEvent};

fn output(message: &str) -> OutputObservation {
    OutputObservation {
        version: TRANSCRIPT_VERSION,
        protocol: Protocol::SocketIo,
        events: vec![OutputEvent {
            sequence: 1,
            offset_ms: 0,
            heartbeat: false,
            message: WireMessage::text(message),
        }],
        end: EndObservation {
            reason: EndReason::ClientClose,
            offset_ms: 1,
            pending: vec![],
            clean: true,
            partial_message: None,
            close: None,
        },
    }
}

fn policy() -> crate::policy::CompiledPolicy {
    crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /id: {kind: identity, formats: [decimal]}
    /plugins/*/expires_at: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap()
}

fn check(source: &str, target: &str) -> Comparison {
    check_with_limit(source, target, 8 * 1024 * 1024).unwrap()
}

fn check_with_limit(source: &str, target: &str, limit: usize) -> Result<Comparison> {
    let policy = policy();
    compare_outputs_global(
        Some(&output(source)),
        Some(&output(target)),
        policy.global_json.as_ref(),
        super::super::super::RequestTimes {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        Default::default(),
        limit,
    )
}

#[test]
fn large_socketio_ack_uses_the_case_message_limit_for_both_sides() {
    let payload = "x".repeat(1024 * 1024);
    let source = format!(r#"43/chat,0[{{"id":"11","payload":"{payload}"}}]"#);
    let target = source.replace(r#""11""#, r#""999""#);
    assert!(check(&source, &target).passed());
    assert!(
        !check_with_limit(&source, &target, source.len())
            .unwrap()
            .passed()
    );
    assert!(check_with_limit(&source, &target, 1024 * 1024).is_err());
}

#[test]
fn socketio_arguments_use_payload_root_formats_and_retain_server_ack_normalization() {
    let source =
        r#"42/worker,9["arbitrary",{"id":"11","plugins":[{"expires_at":1050}],"stable":true}]"#;
    let target =
        r#"42/worker,77["arbitrary",{"stable":true,"plugins":[{"expires_at":2050}],"id":"99"}]"#;
    let result = check(source, target);
    assert!(result.passed(), "{:?}", result.differences);
    assert!(!result.evaluated.is_empty());
    for changed in [
        target.replace("arbitrary", "other-event"),
        target.replace("/worker", "/other"),
        target.replace("true", "false"),
        target.replace("2050", "2090"),
        target.replace("\"99\"", "99"),
        target.replace("\"stable\":true,", ""),
    ]
    .into_iter()
    {
        assert!(
            !check(source, &changed).passed(),
            "accepted metadata/value change"
        );
    }
    let changed = target.replace("true", "false");
    assert!(
        check(source, &changed)
            .differences
            .iter()
            .any(|d| d.pointer == "$interaction/events/0/data/socketio/arguments/0/stable")
    );
}

#[test]
fn ack_ids_argument_count_order_attachments_and_transport_controls_stay_strict() {
    let ack = r#"43/worker,2[{"id":"11"}]"#;
    assert!(check(ack, r#"43/worker,2[{"id":"99"}]"#).passed());
    assert!(!check(ack, r#"43/worker,3[{"id":"99"}]"#).passed());
    let event = r#"42["e",{"id":"11","tag":"one"},{"id":"22","tag":"two"}]"#;
    for target in [
        r#"42["e",{"id":"99","tag":"one"}]"#,
        r#"42["e",{"id":"99","tag":"two"},{"id":"88","tag":"one"}]"#,
        r#"42["e",{"id":"99","tag":"one"},{"id":"88","tag":"two"},null]"#,
        r#"432["e",{"id":"99","tag":"one"},{"id":"88","tag":"two"}]"#,
    ] {
        assert!(!check(event, target).passed());
    }
    let global = policy().global_json.unwrap();
    assert!(
        compare_message(
            &WireMessage::text("0{\"sid\":\"a\"}"),
            &WireMessage::text("0{\"sid\":\"b\"}"),
            &global,
            Default::default(),
            "root",
            8 * 1024 * 1024,
        )
        .unwrap()
        .is_none()
    );
    let source = r#"451-["binary",{"_placeholder":true,"num":0}]"#;
    let target = r#"452-["binary",{"_placeholder":true,"num":0}]"#;
    assert!(!check(source, target).passed());
}

#[test]
fn business_formats_cannot_change_binary_placeholder_identity() {
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /num: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap();
    let result = compare_message(
        &WireMessage::text(r#"451024-["binary",{"_placeholder":true,"num":100}]"#),
        &WireMessage::text(r#"451024-["binary",{"_placeholder":true,"num":101}]"#),
        compiled.global_json.as_ref().unwrap(),
        crate::value_contract::json::AnchorClocks::for_response(
            Default::default(),
            super::super::super::RequestTimes {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(1000, 0),
            },
        ),
        "event",
        8 * 1024 * 1024,
    )
    .unwrap()
    .unwrap();
    assert!(!result.passed());
    assert!(
        result
            .differences
            .iter()
            .any(|d| d.pointer.ends_with("/binary_placeholder"))
    );
}

#[test]
#[ignore = "requires TRAFFIC_E2E_SOCKETIO_PROOF_PROJECT, REPORTS and CASES"]
fn recorded_socketio_global_arguments_validate_without_editing_policy_or_evidence() {
    use std::{fs, path::PathBuf};
    let root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_SOCKETIO_PROOF_PROJECT").unwrap());
    let reports = PathBuf::from(std::env::var_os("TRAFFIC_E2E_SOCKETIO_PROOF_REPORTS").unwrap());
    let cases = std::env::var("TRAFFIC_E2E_SOCKETIO_PROOF_CASES").unwrap();
    let policy = root.join(".traffic-e2e/policy.yaml");
    let policy_before = fs::read(&policy).unwrap();
    for id in cases.split(',') {
        let detail = fs::read_dir(&reports)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("assertion-detail-")
            })
            .map(|p| {
                serde_json::from_slice::<crate::replay::ResponseAssertionCaseReport>(
                    &fs::read(p).unwrap(),
                )
                .unwrap()
            })
            .find(|detail| detail.case_id == id)
            .unwrap();
        let request = PathBuf::from(&detail.request_path);
        let expected = PathBuf::from(&detail.expected_response_path);
        let actual = PathBuf::from(&detail.actual_response_path);
        let originals = [request.clone(), expected.clone(), actual.clone()]
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect::<Vec<_>>();
        let result = crate::assert_recorded_response(crate::ResponseAssertionOptions {
            case_id: id.into(),
            request,
            expected_response: expected,
            actual_response: actual,
            policy: policy.clone(),
        })
        .unwrap();
        let pointers = result
            .differences
            .iter()
            .map(|d| d.pointer.as_str())
            .collect::<Vec<_>>();
        assert!(result.passed, "recorded Socket.IO case {id}: {pointers:?}");
        for (path, bytes) in originals {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
    assert_eq!(fs::read(policy).unwrap(), policy_before);
}
