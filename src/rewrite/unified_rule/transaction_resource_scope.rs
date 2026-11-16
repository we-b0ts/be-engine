//! Resource authoring is checked over other APIs, with independent Target
//! evidence when available and explicit Replay obligations when it is absent.
use super::*;
use crate::policy::{Resource, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata, WitnessStore,
};

fn rule() -> serde_json::Value {
    json!({"format":"traffic-policy/v3","json":{"fields":{
        "/members":{"kind":"unordered"},
        "/lastActiveDate":{"kind":"time","formats":[{"format":"calendar_date","utc_offset":"+08:00"}]}
    }}})
}

fn resource() -> Resource {
    serde_json::from_value(json!({"protocol":"redis","endpoint":"cache.test:6379","database":0}))
        .unwrap()
}

fn event(date: &str) -> serde_json::Value {
    json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::new_v4(),"sequence":1,
        "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "target_host":"cache.test","target_port":6379,"database":0,"resp_version":2,"command":"SET",
        "args":[raw_body(b"pet"),raw_body(json!({"lastActiveDate":date,"counter":136}).to_string().as_bytes())],
        "response_kind":"simple", "response":raw_body(b"+OK\r\n"), "replay_safe":true})
}

fn fixture() -> Fixture {
    let fixture = Fixture::new();
    write(&fixture.proposal, rule());
    dependency_transaction::install(&fixture, event("2026-10-16"), |raw| raw);
    fixture
}

fn foreign(fixture: &Fixture, event: &serde_json::Value) -> PathBuf {
    let source = fixture.state().case_source.clone().unwrap();
    let case = source.join("apis/other/00000000-0000-4000-8000-000000000002");
    fs::create_dir_all(&case).unwrap();
    write(
        &case.join("request.json"),
        json!({"timestamp":"2026-10-16T00:00:00Z",
        "method":"POST","uri":"/other","body":body(json!({}))}),
    );
    write(
        &case.join("expected-response.json"),
        json!({"status":200,"body":body(json!({}))}),
    );
    fs::write(case.join("dependencies.jsonl"), format!("{event}\n")).unwrap();
    recording_fixture::seal(&source);
    case
}

fn foreign_execution(fixture: &Fixture, event: &serde_json::Value, date: &str) -> PathBuf {
    let case = foreign(fixture, event);
    let source = fixture.state().case_source.clone().unwrap();
    // This API's execution is one local day later than the owner's Target.
    let time = "2026-10-17T00:01:00Z".parse().unwrap();
    let evidence = crate::e2e_run::jwt_evidence::test_support::install_attempt_for_api(
        fixture.root(),
        &source,
        &[(case.clone(), 200, 200)],
        time,
        "POST /other",
    );
    recording_fixture::seal(&source);
    let run = fixture
        .paths
        .replay
        .ancestors()
        .find(|p| p.file_name().is_some_and(|n| n == "focused"))
        .unwrap()
        .parent()
        .unwrap();
    crate::case_group::ensure_case_group(crate::CaseGroupOptions {
        case_source: source.clone(),
        case_dir: source.join("apis"),
        method: "POST".into(),
        source_route: "/other".into(),
        pattern: None,
        source_revision: "source".into(),
        output: run.join("case-groups.json"),
        recorder_config: None,
    })
    .unwrap();
    let policy = crate::validate_replay_policy(&fixture.policy())
        .unwrap()
        .fingerprint;
    let store =
        WitnessStore::new_bound(evidence.replay.parent().unwrap(), "foreign", &policy).unwrap();
    let clocks = ClockPair {
        source: Some("2026-10-16T00:00:00Z".parse().unwrap()),
        target: Some(time),
    };
    let raw =
        preflight::dependency::source_witness(Surface::DependencyRequest, event, &case).unwrap();
    let mut actual: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
    actual[1] = json!({"lastActiveDate":date,"counter":136})
        .to_string()
        .into_bytes();
    store
        .record(
            WitnessMetadata {
                surface: Surface::DependencyRequest,
                source_role: SourceRole::DependencyRequest,
                target_role: TargetRole::IndependentTargetObservation,
                source: SourceIdentity {
                    case_id: "00000000-0000-4000-8000-000000000002".into(),
                    exchange_id: None,
                    connection_id: event["connection_id"].as_str().map(str::to_owned),
                    sequence: Some(1),
                },
                resource: Some(resource()),
                operation: "SET".into(),
                slot: Slot::Value,
                clocks: WitnessClocks {
                    case: clocks.clone(),
                    dependency: clocks.clone(),
                    delivery: clocks,
                },
            },
            &case,
            &raw,
            Some(&serde_json::to_vec(&actual).unwrap()),
        )
        .unwrap();
    write(
        &evidence.replay,
        json!({"version":7,"finalized":true,"session_id":"foreign",
        "replay_policy":{"fingerprint":policy},"policy_witnesses":store.sealed_manifest().unwrap(),
        "cases":[{"case_id":"00000000-0000-4000-8000-000000000002","case_dir":case,"source_request_started_at":"2026-10-16T00:00:00Z",
            "target_request_started_at":time}]}),
    );
    write(
        &evidence.assertions,
        json!({"case_source":source,"policy_fingerprint":policy,
        "expected_response":"assertions_only","assertion_mode":"runner_owned","cases":[]}),
    );
    write(
        &evidence.aggregate,
        json!({"case_source":source,"complete":true,"selected_case_ids":["00000000-0000-4000-8000-000000000002"]}),
    );
    evidence.replay
}

#[test]
fn resource_scope_is_not_serialized_and_foreign_source_needs_replay() {
    let fixture = fixture();
    foreign(&fixture, &event("2026-10-16"));
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    assert!(
        plan.traffic_e2e_report["expanded_rules"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        plan.traffic_e2e_report["json"]["fields"]["/lastActiveDate"]["kind"],
        "time"
    );
    let preflight = &plan.traffic_e2e_report["preflight"];
    assert_eq!(preflight["source_validations"], 3);
    assert_eq!(preflight["independent_target_validations"], 2);
    assert_eq!(preflight["missing_target_witnesses"], 1);
    assert_eq!(
        preflight["resource_scope"]["affected_apis"],
        json!(["GET /api", "POST /other"])
    );
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    let saved = fs::read_to_string(fixture.policy()).unwrap();
    assert!(!saved.contains("api:"));
    assert!(saved.contains("+08:00"));
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
}

#[test]
fn global_fields_apply_to_foreign_json_in_every_database() {
    for database in [0, 1] {
        let fixture = fixture();
        let mut other = event("2026-10-16");
        other["database"] = json!(database);
        foreign(&fixture, &other);
        fixture.confirm();
        let plan = fixture.plan().unwrap();
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["source_validations"],
            3
        );
    }
}

fn interrupted_foreign_execution(fixture: &Fixture) -> PathBuf {
    let replay = foreign_execution(fixture, &event("2026-10-16"), "2026-10-17");
    let state_path = replay
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("state.yaml");
    let mut state: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state["status"] = "interrupted".into();
    state["replay_finalized"] = false.into();
    state["aggregate_complete"] = false.into();
    for name in ["assertions_report", "aggregate_report"] {
        fs::remove_file(state[name].as_str().unwrap()).unwrap();
    }
    fs::write(&state_path, serde_yaml::to_string(&state).unwrap()).unwrap();
    state_path
}

#[test]
fn interrupted_foreign_attempt_preserves_source_coverage_and_fresh_replay_obligation() {
    let fixture = fixture();
    interrupted_foreign_execution(&fixture);
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let preflight = &plan.traffic_e2e_report["preflight"];
    assert_eq!(preflight["source_validations"], 3);
    assert_eq!(preflight["independent_target_validations"], 2);
    assert_eq!(preflight["missing_target_witnesses"], 1);
    assert!(
        preflight["resource_scope"]["unavailable_executions"]["POST /other"]["sha256"]
            .as_str()
            .is_some()
    );
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
}

#[test]
fn interrupted_foreign_attempt_identity_and_later_completion_invalidate_the_plan() {
    for completed in [false, true] {
        let fixture = fixture();
        let state_path = interrupted_foreign_execution(&fixture);
        fixture.confirm();
        let plan = fixture.plan().unwrap();
        if completed {
            foreign_execution(&fixture, &event("2026-10-16"), "2026-10-17");
        } else {
            let mut state: serde_yaml::Value =
                serde_yaml::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
            state["sequence"] = 2.into();
            fs::write(&state_path, serde_yaml::to_string(&state).unwrap()).unwrap();
        }
        assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
        assert!(
            fs::read_to_string(fixture.policy())
                .unwrap()
                .contains("rules: []")
        );
    }
}

#[test]
fn missing_artifacts_in_a_complete_foreign_attempt_remain_an_error() {
    let fixture = fixture();
    let replay = foreign_execution(&fixture, &event("2026-10-16"), "2026-10-17");
    fs::remove_file(replay.parent().unwrap().join("assertions.json")).unwrap();
    fixture.confirm();
    assert!(fixture.plan().is_err());
}

#[test]
fn resource_scope_validates_independent_foreign_target_observations() {
    for date in ["2026-10-18", "2026-10-17"] {
        let fixture = fixture();
        foreign_execution(&fixture, &event("2026-10-16"), date);
        fixture.confirm();
        let report = fixture.plan().unwrap().traffic_e2e_report;
        let preflight = &report["preflight"];
        if date.ends_with("18") {
            assert_eq!(report["status"], "planned_needs_replay");
            assert_eq!(preflight["independent_target_validations"], 2);
            assert_eq!(
                preflight["target_comparison_failures"][0]["surface"],
                "dependency.request"
            );
        } else {
            assert_eq!(preflight["independent_target_validations"], 3);
            assert_eq!(preflight["missing_target_witnesses"], 0);
        }
    }
}

#[test]
fn resource_scope_rejects_changed_membership_and_new_target_evidence_before_apply() {
    for new_target in [false, true] {
        let fixture = fixture();
        let other = event("2026-10-16");
        if new_target {
            foreign(&fixture, &other);
        }
        fixture.confirm();
        let plan = fixture.plan().unwrap();
        if new_target {
            foreign_execution(&fixture, &other, "2026-10-17");
        } else {
            foreign(&fixture, &other);
        }
        assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
        assert!(
            fs::read_to_string(fixture.policy())
                .unwrap()
                .contains("rules: []")
        );
    }
}

#[test]
fn resource_scope_marks_other_apis_stale_after_apply() {
    let fixture = fixture();
    let replay = foreign_execution(&fixture, &event("2026-10-16"), "2026-10-17");
    fixture.confirm();
    let mut state = fixture.state();
    let mut other = state.api_inventory[0].clone();
    other.api = "POST /other".into();
    other.status = crate::rewrite::model::RewriteApiStatus::Complete;
    other.e2e_current = true;
    other.verified_target_fingerprint = Some("before-resource-rule".into());
    state.api_inventory.push(other);
    fixture.store().save(&state).unwrap();
    let plan = fixture.plan().unwrap();
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    let state = fixture.state();
    let other = state
        .api_inventory
        .iter()
        .find(|a| a.api == "POST /other")
        .unwrap();
    assert!(!other.e2e_current && other.verified_target_fingerprint.is_none());
    assert!(replay.is_file());
}

#[test]
fn resource_scope_rejects_changed_foreign_target_before_apply() {
    let fixture = fixture();
    let replay = foreign_execution(&fixture, &event("2026-10-16"), "2026-10-17");
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&replay).unwrap()).unwrap();
    report["session_id"] = json!("replaced-foreign-execution");
    write(&replay, report);
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
}

#[test]
fn resource_scope_checks_native_http_source_on_other_apis() {
    for scenario in [
        "valid",
        "truncated-body",
        "other-endpoint",
        "other-consumer",
    ] {
        let fixture = Fixture::new();
        let mut event = json!({"event_type":"http_exchange","id":"foreign-http",
            "scheme":"http","authority":"client.test:8080","method":"POST","uri":"/responses?generated_at=1792108800",
            "request_body":body(json!({"input":"hello"})),"request_headers":{"x-stainless-lang":["python"]},
            "response_status":200,"response_headers":{},"response_body":body(json!({})),
            "timestamp":"2026-10-16T00:00:00Z","request_started_at":"2026-10-16T00:00:00Z","duration_ms":0,"outcome":"response"});
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001");
        fs::write(case.join("dependencies.jsonl"), format!("{event}\n")).unwrap();
        if scenario != "valid" {
            event["request_body"]["truncated"] = json!(true);
        }
        if scenario == "other-endpoint" {
            event["authority"] = json!("elsewhere.test:8080");
        }
        if scenario == "other-consumer" {
            event["uri"] = json!("/another-service");
        }
        foreign(&fixture, &event);
        write(
            &fixture.proposal,
            json!({"id":"query-clock","match":{"resource":{"protocol":"http","endpoint":"client.test:8080"},
            "operation":"POST","path":"/responses"},"effect":{"kind":"http_request","query":{"generated_at":{"relative_time":"unix_seconds"}}},
            "proof":{"source":"client.py:request","fact":"Source sends the current dependency request clock in generated_at"}}),
        );
        fixture.confirm();
        let planned = fixture.plan();
        if scenario == "truncated-body" {
            assert!(planned.is_err());
        } else {
            let planned = planned.unwrap();
            assert!(
                planned.traffic_e2e_report["expanded_rules"][0]["match"]
                    .get("api")
                    .is_none()
            );
            assert_eq!(
                planned.traffic_e2e_report["preflight"]["rules"]["query-clock"],
                if scenario == "valid" { 2 } else { 1 }
            );
        }
    }
}

#[test]
fn resource_scope_waits_for_related_replay_reservations_only() {
    use crate::rewrite::traffic_operation::{self, TrafficOperationClaim, TrafficOperationKind};
    for api in ["POST /other", "GET /unrelated"] {
        let fixture = fixture();
        foreign(&fixture, &event("2026-10-16"));
        fixture.confirm();
        let claim = traffic_operation::claim_current(
            fixture.root(),
            "foreign-replay".into(),
            TrafficOperationKind::Replay,
            Some(api.into()),
        )
        .unwrap();
        let TrafficOperationClaim::Acquired(_guard) = claim else {
            panic!("Replay reservation")
        };
        let planned = fixture.plan();
        assert_eq!(planned.is_ok(), api == "GET /unrelated");
    }
}
