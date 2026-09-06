use std::fs;
use std::process::Command;

use super::*;
use crate::rewrite::{
    ip_capture,
    model::{RewriteAttemptDelta, RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn fixture() -> (tempfile::TempDir, tempfile::TempDir, RewriteState) {
    let target = tempfile::tempdir().unwrap();
    let recording = tempfile::tempdir().unwrap();
    let case = recording.path().join("apis/api/case-1");
    fs::create_dir_all(&case).unwrap();
    fs::write(
        case.join("request.json"),
        r#"{"method":"GET","uri":"/api","api_pattern":"/api"}"#,
    )
    .unwrap();
    fs::write(case.join("expected-response.json"), "{}").unwrap();
    let event = json!({
        "event_type":"http_exchange","id":"response-1","scheme":"http","method":"GET",
        "uri":"/executor-manager/sandboxes/123","authority":"cs.wegent.intra.demo.test",
        "response_status":200,"response_headers":{"content-type":["application/json"]},
        "response_body":{"encoding":"base64","truncated":false,"data":STANDARD.encode(br#"{"base_url":"http://10.36.14.118:8080/secret?token=do-not-expose","other":"https://example.test"}"#)}
    });
    fs::write(case.join("dependencies.jsonl"), format!("{event}\n")).unwrap();
    let mut recorder = crate::AppConfig::default();
    recorder.dns_mock.enabled = true;
    recorder.tcp_gateway.enabled = true;
    recorder.tcp_gateway.record_http = true;
    crate::rewrite::test_support::install_project_config(target.path(), "master", recorder, None);
    for args in [
        vec!["init"],
        vec!["config", "user.email", "test@example.test"],
        vec!["config", "user.name", "test"],
        vec!["add", "."],
        vec!["commit", "-m", "baseline"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let mut state = crate::rewrite::test_state();
    state.api = "GET /api".into();
    state.phase = RewritePhase::ImplementationRequired;
    state.case_source = Some(recording.path().to_path_buf());
    state.source_revision = Some("source-1".into());
    state.attempt_delta = Some(RewriteAttemptDelta {
        previous_attempt: 1,
        current_attempt: 2,
        response_passed_delta: 0,
        response_nonpassing_delta: 0,
        improved: false,
        regressed: false,
    });
    state.active_issue = Some(RewriteIssue {
        id: "issue-1".into(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "503 instead of 200".into(),
        pointer_pattern: None,
        representative: None,
        response_diagnosis: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        possible_causes: vec![],
        observed_target_fingerprint: fingerprint::repository_fingerprint(target.path()).unwrap(),
        attempt: 2,
        comparison_observation: None,
    });
    (target, recording, state)
}

fn report_ip(
    target: &Path,
    state: &mut RewriteState,
    origin: &str,
) -> crate::RewriteIpCaptureReport {
    let evidence = evidence::commands(target, state)
        .into_iter()
        .find(|command| command.query_id.ends_with("attempt-delta"))
        .unwrap();
    let id = evidence::query(target, state, &evidence.query_id)
        .unwrap()
        .evidence_id;
    ip_capture::investigate(
        target,
        state,
        &id,
        "service.py:42 list_tree consumes sandbox base_url; source ListDir dependency is absent",
        "case-1".into(),
        "10.36.14.118:8080".into(),
        origin.into(),
    )
    .unwrap()
}

fn options(report: &crate::RewriteIpCaptureReport) -> RewriteHttpResponseCapturePlanOptions {
    RewriteHttpResponseCapturePlanOptions {
        evidence_id:report.evidence.evidence_id.clone(),case_id:"case-1".into(),response_id:"response-1".into(),
        rule:serde_yaml::from_str("name: sandbox-base-url\nauthorities: [cs.wegent.intra.demo.test]\nmethods: [GET]\npath_pattern: /executor-manager/sandboxes/*\npointers: [/base_url]\n").unwrap(),
        source_evidence:"service.py:42 list_tree reads sandbox.base_url and invokes ListDir on it".into(),
    }
}

#[test]
fn ip_preflight_returns_guidance_then_plan_apply_parks_for_refresh() {
    let (target, _recording, mut state) = fixture();
    let unknown = report_ip(target.path(), &mut state, "unknown");
    assert!(!unknown.accepted);
    assert_eq!(unknown.kind, "source_investigation_required");
    assert!(unknown.evidence.applicable_rule_planners.is_empty());
    assert!(
        ip_capture::ensure_before_system_repair(target.path(), &state, "recorder_capability_gap")
            .is_err()
    );
    let report = report_ip(target.path(), &mut state, "http-response");
    assert_eq!(report.kind, "recorder_capture_required");
    assert_eq!(report.evidence.applicable_rule_planners.len(), 1);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("do-not-expose")
    );
    assert!(!serde_json::to_string(&report).unwrap().contains("/secret"));
    assert!(
        ip_capture::ensure_before_system_repair(target.path(), &state, "recorder_capability_gap")
            .is_err()
    );
    let config = target
        .path()
        .join(".traffic-e2e/source-traffic-policy.yaml");
    let before = fs::read_to_string(&config).unwrap();
    let planned = plan(target.path(), &mut state, options(&report)).unwrap();
    assert_eq!(fs::read_to_string(&config).unwrap(), before);
    assert!(planned.next_command.argv.contains(&"apply".into()));
    let action = super::super::pending_plan_action(target.path(), &state).unwrap();
    assert_eq!(
        serde_json::to_value(action).unwrap()["commands"]["apply"]["argv"],
        json!(planned.next_command.argv)
    );
    assert!(
        ip_capture::ensure_before_system_repair(target.path(), &state, "recorder_capability_gap")
            .is_err()
    );
    super::super::apply(target.path(), &mut state, &planned.plan_id).unwrap();
    assert_eq!(state.phase, RewritePhase::AwaitingRecordingRefresh);
    assert_eq!(
        crate::AppConfig::load(target.path().join(".traffic-e2e/project.yaml"))
            .unwrap()
            .http_response_rewrite
            .rules[0]
            .pointers,
        ["/base_url"]
    );
    assert!(state.recording_refresh.is_some());
}

#[test]
fn wrong_pointer_and_changed_recorded_response_cannot_be_applied() {
    let (target, recording, mut state) = fixture();
    let report = report_ip(target.path(), &mut state, "http-response");
    let mut wrong = options(&report);
    wrong.rule.pointers = vec!["/other".into()];
    assert!(plan(target.path(), &mut state, wrong).is_err());
    let planned = plan(target.path(), &mut state, options(&report)).unwrap();
    fs::write(
        recording.path().join("apis/api/case-1/dependencies.jsonl"),
        "",
    )
    .unwrap();
    assert!(super::super::apply(target.path(), &mut state, &planned.plan_id).is_err());
    assert!(
        crate::AppConfig::load(target.path().join(".traffic-e2e/project.yaml"))
            .unwrap()
            .http_response_rewrite
            .rules
            .is_empty()
    );
}
