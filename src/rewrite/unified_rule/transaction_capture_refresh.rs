//! Acquisition proof and freshness are separate from unchanged declarations.
use super::*;
use serde_json::Value;

fn capture(name: &str, path: &str) -> Value {
    json!({"name":name,"host":"service.test:8080","method":"GET","path":path,
        "json_urls":["/base_url"],
        "proof":{"source":"sandbox.py:12","fact":"Source follows the sandbox address returned in this exact response"}})
}

fn fixture(existing_capture: bool) -> Fixture {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
        write(
            &source.join("recording-run.json"),
            json!({"run_id":"recording","status":"completed"}),
        );
        let event = json!({"event_type":"http_exchange","id":uuid::Uuid::new_v4(),"scheme":"http",
            "authority":"service.test:8080","method":"GET","uri":"/sandbox/1",
            "request_headers":{},"request_body":raw_body(b""),"response_status":200,
            "response_headers":{"content-type":["application/json"]},
            "response_body":raw_body(br#"{"base_url":"http://10.0.0.1:8080/service"}"#),
            "timestamp":"2026-10-16T00:00:00Z","request_started_at":"2026-10-16T00:00:00Z",
            "duration_ms":0,"outcome":"response","error":null});
        fs::write(
            source.join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl"),
            format!("{event}\n"),
        )
        .unwrap();
        if existing_capture {
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v3",
                "http":{"response_rewrite":[capture("sandbox-url", "/sandbox/1")]}}),
            );
        }
        vec![]
    });
    let mut state = fixture.state();
    state.recording_run_id = "recording".into();
    fixture.store().save(&state).unwrap();
    fixture
}

fn proposal(fixture: &Fixture, declaration: Value) {
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3",
        "json":super::super::rule()["json"],"http":{"response_rewrite":[declaration]}}),
    );
}

#[test]
fn unchanged_named_capture_keeps_inventory_proof_without_requiring_new_recording() {
    for stale in [false, true] {
        let fixture = fixture(true);
        proposal(&fixture, capture("sandbox-url", "/sandbox/1"));
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(
            planned.traffic_e2e_report["requires_fresh_recording"],
            false
        );
        assert!(
            planned.traffic_e2e_report["preflight"]["rules"]["sandbox-url"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(planned.traffic_e2e_report["requires_fresh_replay"], true);
        let original = fs::read(fixture.policy()).unwrap();
        if stale {
            let source = fixture.state().case_source.clone().unwrap();
            fs::write(
                source.join("dependencies.jsonl"),
                "changed authoritative Source after planning",
            )
            .unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &planned.plan_id).is_err());
            assert_eq!(fs::read(fixture.policy()).unwrap(), original);
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_replay"
            );
            assert!(fixture.state().recording_refresh.is_none());
            assert!(fixture.state().rule_replay_pending);
        }
    }
}

#[test]
fn new_capture_and_expanded_capture_scope_keep_fresh_recording_obligations() {
    for expanded in [false, true] {
        let fixture = fixture(expanded);
        proposal(
            &fixture,
            capture(
                if expanded {
                    "expanded-sandbox-url"
                } else {
                    "sandbox-url"
                },
                if expanded { "/sandbox/*" } else { "/sandbox/1" },
            ),
        );
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(planned.traffic_e2e_report["requires_fresh_recording"], true);
        let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert_eq!(
            applied.traffic_e2e_report["status"],
            "applied_pending_recording"
        );
        assert_scoped_capture_pending(&fixture);
    }
}

#[test]
fn registered_capture_policy_uses_public_plan_apply_and_requires_fresh_recording() {
    let fixture = fixture(false);
    proposal(
        &fixture,
        json!({
            "name":"registered-addresses", "host":"service.test:8080", "method":"GET", "path":"/sandbox/1",
            "policy":{"id":"documents","version":1,"options":{"rules":[{
                "fields":[{"path":"/base_url","format":"url"}]
            }]}},
            "proof":{"source":"sandbox.py:12","fact":"Source uses the response address for a later dependency request"}
        }),
    );
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(planned.traffic_e2e_report["requires_fresh_recording"], true);
    assert!(
        planned.traffic_e2e_report["preflight"]["rules"]["registered-addresses"]
            .as_u64()
            .unwrap()
            > 0
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_recording"
    );
    assert_scoped_capture_pending(&fixture);
    let document =
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
    let rendered = crate::policy::render_policy(&document).unwrap();
    let value: Value = serde_yaml::from_str(&rendered).unwrap();
    assert_eq!(
        value["http"]["response_rewrite"][0]["policy"]["id"],
        "documents"
    );
}

#[test]
fn retained_capture_does_not_clear_an_earlier_unfinished_scoped_capture_obligation() {
    let fixture = fixture(true);
    let mut state = fixture.state();
    crate::rewrite::verification_obligations::request_capture(
        &mut state,
        &std::collections::BTreeMap::from([(
            "GET /api".into(),
            "Earlier missing Source evidence".into(),
        )]),
        "earlier-source-plan",
    )
    .unwrap();
    fixture.store().save(&state).unwrap();
    proposal(&fixture, capture("sandbox-url", "/sandbox/1"));
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["requires_fresh_recording"],
        false
    );
    apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_scoped_capture_pending(&fixture);
    assert!(
        fixture
            .state()
            .dependency_review
            .obligations
            .values()
            .any(|obligation| obligation.proof_id == "earlier-source-plan" && obligation.pending())
    );
}

#[test]
fn equivalent_recording_case_paths_do_not_create_a_fresh_recording_obligation() {
    let revision = format!("sha256:{}", "1".repeat(64));
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
        assert_eq!(
            crate::source_snapshot::test_fixture::install(root),
            revision
        );
        write(
            &source.join("recording-run.json"),
            json!({"run_id":"recording","status":"completed"}),
        );
        write(
            &root.join(".traffic-e2e/policy.yaml"),
            json!({
                "format":"traffic-policy/v3","source_revision":revision,
                "rules":[{"id":"source-capture-http","match":{},"effect":{
                    "kind":"capture_http","case_paths":["/api"]},
                    "proof":{"source":"routes.py:12","fact":"Source owns this exact captured route"}}]
            }),
        );
        vec![]
    });
    let inventory = fixture
        .paths
        .replay
        .ancestors()
        .map(|path| path.join("case-groups.json"))
        .find(|path| path.is_file())
        .unwrap();
    let mut groups: Value = serde_json::from_slice(&fs::read(&inventory).unwrap()).unwrap();
    groups["source_revision"] = revision.clone().into();
    write(&inventory, groups);
    let runner_path = fixture
        .paths
        .replay
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("state.yaml");
    let mut runner: Value =
        serde_yaml::from_str(&fs::read_to_string(&runner_path).unwrap()).unwrap();
    runner["source_revision"] = revision.clone().into();
    fs::write(runner_path, serde_yaml::to_string(&runner).unwrap()).unwrap();
    let mut state = fixture.state();
    state.source_revision = Some(revision.clone());
    state.recording_run_id = "recording".into();
    fixture.store().save(&state).unwrap();
    write(
        &fixture.proposal,
        json!({
            "format":"traffic-policy/v3","source_revision":revision,
            "json":super::super::rule()["json"],
            "recording":{"case_paths":["/api"],"proof":{
                "source":"routes.py:12","fact":"Source owns this exact captured route"}}
        }),
    );
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["requires_fresh_recording"],
        false
    );
    assert!(
        planned.traffic_e2e_report["preflight"]["rules"]["source-capture-http"]
            .as_u64()
            .unwrap()
            > 0
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    assert!(fixture.state().recording_refresh.is_none());
}

#[test]
fn template_only_public_plan_reports_stateful_identity_replay_evidence() {
    let fixture = Fixture::new();
    fixture.replace_response_bodies(
        br#"{"url":"https://example.test/session/11111111-1111-4111-8111-111111111111"}"#,
        br#"{"url":"https://example.test/session/22222222-2222-4222-8222-222222222222"}"#,
    );
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3","json":{"fields":{
            "/url":{"kind":"template","formats":[{
                "template":"https://example.test/session/{id}","fields":{"id":"uuid"}
            }]}
        }}}),
    );
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["stateful_target_obligations"],
        json!(["global.json"])
    );
    assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
    assert_eq!(
        planned.traffic_e2e_report["requires_fresh_recording"],
        false
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
}
