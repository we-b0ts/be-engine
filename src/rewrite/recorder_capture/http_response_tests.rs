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
        pattern_checked: true,
    }
}

fn checked_plan(
    target: &Path,
    state: &mut RewriteState,
    options: RewriteHttpResponseCapturePlanOptions,
) -> crate::RewriteRecorderCaptureReport {
    match plan(target, state, options).unwrap() {
        RewriteHttpResponseCaptureReport::Planned { plan } => plan,
        report => panic!("expected checked plan, got {report:?}"),
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
    let config = target.path().join(".traffic-e2e/policy.yaml");
    let before = fs::read_to_string(&config).unwrap();
    let planned = checked_plan(target.path(), &mut state, options(&report));
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
    let planned = checked_plan(target.path(), &mut state, options(&report));
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

fn rule(pattern: &str) -> HttpResponseRewriteRuleConfig {
    crate::config::source_traffic_policy::http_response::Document {
        name: "cs.wegent.intra.demo.test".into(),
        path_pattern: format!("GET {pattern}"),
        pointer: "/base_url".into(),
        source_evidence: "sandbox_id varies; consume base_url".into(),
    }
    .into_rule()
    .unwrap()
}

fn install_rules(target: &Path, rules: Vec<HttpResponseRewriteRuleConfig>) {
    let path = super::super::source_traffic_policy_path(target).unwrap();
    let original = fs::read_to_string(&path).unwrap();
    let mut policy = crate::config::SourceTrafficPolicyConfig::parse(&original, &path).unwrap();
    policy.http_response_rewrite = rules;
    fs::write(
        path,
        crate::config::native_policy::render_updated(
            &original,
            &policy,
            &crate::policy::Proof {
                source: "src/SandboxClient.java:42 response URL construction".into(),
                fact: "sandbox_id varies; consume base_url".into(),
            },
        )
        .unwrap(),
    )
    .unwrap();
}

fn configured_rules(target: &Path) -> Vec<HttpResponseRewriteRuleConfig> {
    crate::AppConfig::load(super::super::project_config(target))
        .unwrap()
        .http_response_rewrite
        .rules
}

#[test]
fn first_plan_requires_explicit_review_without_a_proof_format_or_apply_command() {
    let (target, _recording, mut state) = fixture();
    let report = report_ip(target.path(), &mut state, "http-response");
    let initial =
        serde_json::to_value(&report.evidence.applicable_rule_planners[0].command).unwrap();
    assert!(!initial.to_string().contains("pattern-checked"));
    assert!(
        !initial
            .to_string()
            .contains("BACKEND_REWRITE_SOURCE_EVIDENCE")
    );
    assert!(!initial.to_string().contains("json-url-"));
    let initial_argv = initial["argv"].as_array().unwrap();
    assert!(initial_argv.contains(&json!("--file")));
    assert!(initial_argv.contains(&json!("--evidence")));
    assert!(initial_argv.contains(&json!(report.evidence.evidence_id)));
    assert!(
        report.evidence.facts["http_response_url_candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |candidate| candidate["path"] == "/executor-manager/sandboxes/123"
                    && candidate["response_id"] == "response-1"
            )
    );
    let mut input = options(&report);
    input.pattern_checked = false;
    input.source_evidence.clear();
    let before =
        fs::read(super::super::source_traffic_policy_path(target.path()).unwrap()).unwrap();
    let result =
        serde_json::to_value(plan(target.path(), &mut state, input.clone()).unwrap()).unwrap();
    assert_eq!(result["status"], "path_pattern_review_required");
    assert_eq!(result["pattern_review"]["existing_rules"], json!([]));
    assert_eq!(
        result["pattern_review"]["current_path"],
        "/executor-manager/sandboxes/123"
    );
    assert!(result.get("plan_id").is_none());
    assert!(!result["next_command"].to_string().contains("apply"));
    assert!(
        !result["next_command"]
            .to_string()
            .contains("pattern-checked")
    );
    assert!(state.recorder_capture_plan.is_none());
    assert_eq!(
        fs::read(super::super::source_traffic_policy_path(target.path()).unwrap()).unwrap(),
        before
    );
    input.pattern_checked = true;
    assert!(
        plan(target.path(), &mut state, input.clone())
            .unwrap_err()
            .to_string()
            .contains("source evidence")
    );
    input.source_evidence = "sandbox_id is dynamic; use *; read base_url".into();
    let checked = plan(target.path(), &mut state, input).unwrap();
    let json = serde_json::to_value(checked).unwrap();
    assert_eq!(json["status"], "planned");
    assert!(json["plan_id"].is_string());
    assert_eq!(
        json["traffic_e2e_report"]["rule"]["name"],
        "cs.wegent.intra.demo.test"
    );
    assert_eq!(
        json["traffic_e2e_report"]["rule"]["path_pattern"],
        "GET /executor-manager/sandboxes/*"
    );
    assert!(
        json["next_command"]["argv"]
            .as_array()
            .unwrap()
            .contains(&json!("apply"))
    );
}

#[test]
fn a_new_review_invalidates_the_previous_http_apply_plan() {
    let (target, _recording, mut state) = fixture();
    let report = report_ip(target.path(), &mut state, "http-response");
    let checked = checked_plan(target.path(), &mut state, options(&report));
    let mut input = options(&report);
    input.pattern_checked = false;
    plan(target.path(), &mut state, input).unwrap();
    assert!(super::super::pending_plan_action(target.path(), &state).is_none());
    assert!(super::super::apply(target.path(), &mut state, &checked.plan_id).is_err());
    assert!(configured_rules(target.path()).is_empty());
}

#[test]
fn review_lists_matching_selectors_without_path_similarity_filtering() {
    let (target, _recording, mut state) = fixture();
    let mut other_method = rule("/executor-manager/sandboxes/456");
    other_method.methods = vec!["POST".into()];
    let mut other_host = rule("/executor-manager/sandboxes/456");
    other_host.name = "other.test".into();
    other_host.authorities = vec!["other.test".into()];
    let mut other_pointer = rule("/executor-manager/sandboxes/456");
    other_pointer.pointers = vec!["/other".into()];
    install_rules(
        target.path(),
        vec![
            rule("/executor-manager/sandboxes/456"),
            rule("/entirely/different/path"),
            other_method,
            other_host,
            other_pointer,
        ],
    );
    let report = report_ip(target.path(), &mut state, "http-response");
    let mut input = options(&report);
    input.pattern_checked = false;
    let review = serde_json::to_value(plan(target.path(), &mut state, input).unwrap()).unwrap();
    let paths: Vec<_> = review["pattern_review"]["existing_rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["path_pattern"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "GET /executor-manager/sandboxes/456",
            "GET /entirely/different/path"
        ]
    );
}

#[test]
fn checked_pattern_merges_old_ids_and_preserves_uncovered_or_different_rules() {
    let (target, _recording, mut state) = fixture();
    let mut another_pointer = rule("/executor-manager/sandboxes/987");
    another_pointer.pointers = vec!["/other".into()];
    install_rules(
        target.path(),
        vec![
            rule("/executor-manager/sandboxes/789"),
            rule("/executor-manager/sandboxes/456"),
            rule("/executor-manager/sandboxes/*/detail"),
            rule("/other/*"),
            another_pointer.clone(),
        ],
    );
    let report = report_ip(target.path(), &mut state, "http-response");
    let before = configured_rules(target.path());
    let path = super::super::source_traffic_policy_path(target.path()).unwrap();
    let original = crate::policy::parse_policy(&fs::read_to_string(&path).unwrap()).unwrap();
    let planned = checked_plan(target.path(), &mut state, options(&report));
    assert_eq!(configured_rules(target.path()), before);
    let replaced: Vec<_> = planned.traffic_e2e_report["replaced_rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["path_pattern"].as_str().unwrap())
        .collect();
    assert_eq!(
        replaced,
        [
            "GET /executor-manager/sandboxes/789",
            "GET /executor-manager/sandboxes/456"
        ]
    );
    super::super::apply(target.path(), &mut state, &planned.plan_id).unwrap();
    let after = configured_rules(target.path());
    assert_eq!(after.len(), 4);
    assert_eq!(
        after[0].path_pattern.as_deref(),
        Some("/executor-manager/sandboxes/*")
    );
    assert_eq!(after[3], before[4]);
    let updated = crate::policy::parse_policy(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(updated.format, crate::policy::POLICY_FORMAT);
    assert_eq!(updated.rules.len(), 4);
    for untouched in &original.rules[2..] {
        assert_eq!(
            updated
                .rules
                .iter()
                .find(|rule| rule.id() == untouched.id()),
            Some(untouched),
            "an uncovered selector retains its complete typed rule and proofs"
        );
    }
    let merged = updated.rules[0].as_native().unwrap();
    assert!(
        merged.proof.is_none(),
        "Source proof stays in the capture plan rather than runtime policy"
    );
    let crate::policy::native::NativeEffect::CaptureHttpResponse(effect) = &merged.effect else {
        panic!("wrong effect")
    };
    assert_eq!(effect.authorities, ["cs.wegent.intra.demo.test"]);
    assert_eq!(effect.methods, ["GET"]);
    let crate::policy::native::CaptureResponseContract::Urls { pointers } = &effect.contract else {
        panic!("wrong response contract")
    };
    assert_eq!(pointers[0].contract, "/base_url");
    assert_eq!(state.phase, RewritePhase::AwaitingRecordingRefresh);
}

#[test]
fn checked_exact_path_can_stay_separate_with_a_brief_note_and_same_domain_name() {
    let (target, _recording, mut state) = fixture();
    install_rules(target.path(), vec![rule("/executor-manager/sandboxes/456")]);
    let before = configured_rules(target.path());
    let report = report_ip(target.path(), &mut state, "http-response");
    let mut input = options(&report);
    input.rule.path_pattern = Some("/executor-manager/sandboxes/123".into());
    input.source_evidence = "fixed configured path; keep exact; consume base_url".into();
    let planned = checked_plan(target.path(), &mut state, input);
    assert_eq!(planned.traffic_e2e_report["replaced_rules"], json!([]));
    super::super::apply(target.path(), &mut state, &planned.plan_id).unwrap();
    let rules = configured_rules(target.path());
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0], before[0]);
    assert_ne!(rules[0].name, rules[1].name);
    assert_eq!(rules[0].authorities, rules[1].authorities);
    assert_eq!(
        rules[1].path_pattern.as_deref(),
        Some("/executor-manager/sandboxes/123")
    );
}

#[test]
fn existing_pattern_is_reused_without_adding_the_new_id() {
    let (target, _recording, mut state) = fixture();
    install_rules(target.path(), vec![rule("/executor-manager/sandboxes/*")]);
    let report = report_ip(target.path(), &mut state, "http-response");
    let mut input = options(&report);
    input.rule.path_pattern = Some("/executor-manager/sandboxes/123".into());
    let before =
        fs::read(super::super::source_traffic_policy_path(target.path()).unwrap()).unwrap();
    let planned = checked_plan(target.path(), &mut state, input);
    assert_eq!(planned.traffic_e2e_report["reused_existing"], true);
    assert_eq!(planned.traffic_e2e_report["changed"], false);
    super::super::apply(target.path(), &mut state, &planned.plan_id).unwrap();
    assert_eq!(
        fs::read(super::super::source_traffic_policy_path(target.path()).unwrap()).unwrap(),
        before
    );
}

#[test]
fn changed_policy_and_unreviewed_legacy_plans_cannot_apply() {
    let (target, _recording, mut state) = fixture();
    let report = report_ip(target.path(), &mut state, "http-response");
    let planned = checked_plan(target.path(), &mut state, options(&report));
    let spec = state
        .recorder_capture_plan
        .as_mut()
        .unwrap()
        .http_response
        .as_mut()
        .unwrap();
    let mut legacy = serde_json::to_value(&*spec).unwrap();
    legacy.as_object_mut().unwrap().remove("pattern_checked");
    *spec = serde_json::from_value(legacy).unwrap();
    let error = super::super::apply(target.path(), &mut state, &planned.plan_id).unwrap_err();
    assert!(error.to_string().contains("path review"));
    assert!(configured_rules(target.path()).is_empty());
    let planned = checked_plan(target.path(), &mut state, options(&report));
    install_rules(target.path(), vec![rule("/other/path")]);
    let unchanged = configured_rules(target.path());
    assert!(super::super::apply(target.path(), &mut state, &planned.plan_id).is_err());
    assert_eq!(configured_rules(target.path()), unchanged);
}

#[test]
fn related_rules_compare_pointer_sets_and_do_not_use_path_shape() {
    let mut first = rule("/one/*");
    first.pointers = vec!["/base_url".into(), "/endpoints/0".into()];
    let mut second = rule("/entirely/different/resource/path");
    second.pointers = vec!["/endpoints/0".into(), "/base_url".into()];
    assert!(rules::related(&first, &second));
    second.pointers = vec!["/base_url".into()];
    assert!(!rules::related(&first, &second));
}

#[test]
fn consolidation_preserves_static_rows_even_when_names_match() {
    let (target, _recording, _state) = fixture();
    let mut app = crate::AppConfig::load(super::super::project_config(target.path())).unwrap();
    let static_rule = rule("/executor-manager/sandboxes/456");
    app.http_response_rewrite.rules.push(static_rule.clone());
    let mut policy = crate::config::SourceTrafficPolicyConfig::empty();
    let requested = rule("/executor-manager/sandboxes/*");
    let result = rules::converge(&mut app, &mut policy, &requested).unwrap();
    assert!(result.replaced_rules.is_empty());
    assert_eq!(
        app.http_response_rewrite.rules,
        vec![static_rule, requested.clone()]
    );
    assert_eq!(policy.http_response_rewrite, vec![requested]);
}
