//! Resource authoring is checked over other APIs, with independent Target
//! evidence when available and explicit Replay obligations when it is absent.
use super::*;
use crate::policy::{Resource, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata, WitnessStore,
};

fn rule() -> serde_json::Value {
    json!({"id":"pet-date","surface":"dependency.request",
        "match":{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
            "operation":"SET","key":{"exact":"pet"}},"slot":"value","codec":"json",
        "contract":{"/lastActiveDate":{"relative_time":"calendar_date","utc_offset":"+08:00"}},
        "proof":{"source":"pet.py:update","fact":"The stored business date preserves its local day distance; counters remain exact"}})
}

fn event(date: &str) -> serde_json::Value {
    json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::new_v4(),"sequence":1,
        "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "target_host":"cache.test","target_port":6379,"database":0,"command":"SET",
        "args":[raw_body(b"pet"),raw_body(json!({"lastActiveDate":date,"counter":136}).to_string().as_bytes())],
        "response":raw_body(b"+OK\r\n")})
}

fn fixture() -> Fixture {
    let fixture = Fixture::new();
    write(&fixture.proposal, rule());
    dependency_transaction::install(&fixture, event("2026-10-16"), |raw| raw);
    fixture
}

fn foreign(fixture: &Fixture, event: &serde_json::Value) -> PathBuf {
    let source = fixture.state().case_source.clone().unwrap();
    let case = source.join("apis/other/case-2");
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
                    case_id: "case-2".into(),
                    exchange_id: None,
                    connection_id: event["connection_id"].as_str().map(str::to_owned),
                    sequence: Some(1),
                },
                resource: Some(
                    serde_json::from_value::<Resource>(rule()["match"]["resource"].clone())
                        .unwrap(),
                ),
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
        json!({"finalized":true,"session_id":"foreign",
        "replay_policy":{"fingerprint":policy},"policy_witnesses":store.sealed_manifest().unwrap(),
        "cases":[{"case_id":"case-2","case_dir":case,"source_request_started_at":"2026-10-16T00:00:00Z",
            "target_request_started_at":time}]}),
    );
    write(
        &evidence.assertions,
        json!({"case_source":source,"policy_fingerprint":policy,
        "expected_response":"assertions_only","assertion_mode":"runner_owned","cases":[]}),
    );
    write(
        &evidence.aggregate,
        json!({"case_source":source,"complete":true,"selected_case_ids":["case-2"]}),
    );
    evidence.replay
}

#[test]
fn resource_scope_is_not_serialized_and_foreign_source_needs_replay() {
    let fixture = fixture();
    foreign(&fixture, &event("2026-10-16"));
    // A legacy API hint in a new proposal is not copied into resource matching.
    let mut proposed = rule();
    proposed["match"]["api"] = json!("GET /api");
    write(&fixture.proposal, proposed);
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    assert!(
        plan.traffic_e2e_report["expanded_rules"][0]["match"]
            .get("api")
            .is_none()
    );
    let preflight = &plan.traffic_e2e_report["preflight"];
    assert_eq!(preflight["source_validations"], 2);
    assert_eq!(preflight["independent_target_validations"], 1);
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
fn resource_scope_validates_foreign_values_and_retains_resource_isolation() {
    for other_resource in [false, true] {
        let fixture = fixture();
        let mut other = event("invalid-date");
        if other_resource {
            other["database"] = json!(1);
        }
        foreign(&fixture, &other);
        fixture.confirm();
        let planned = fixture.plan();
        assert_eq!(planned.is_ok(), other_resource);
    }
}

#[test]
fn resource_scope_validates_independent_foreign_target_observations() {
    for date in ["2026-10-16", "2026-10-17"] {
        let fixture = fixture();
        foreign_execution(&fixture, &event("2026-10-16"), date);
        fixture.confirm();
        let plan = fixture.plan();
        if date.ends_with("16") {
            assert!(plan.is_err());
        } else {
            let plan = plan.unwrap();
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                2
            );
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["missing_target_witnesses"],
                0
            );
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
            "scheme":"http","authority":"client.test:8080","method":"POST","uri":"/responses",
            "request_body":body(json!({"input":"hello"})),"request_headers":{"x-stainless-lang":["python"]},
            "response_status":200,"response_headers":{},"response_body":body(json!({})),
            "timestamp":"2026-10-16T00:00:00Z","request_started_at":"2026-10-16T00:00:00Z","duration_ms":0,"outcome":"response"});
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1");
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
            json!({"id":"sdk","match":{"resource":{"protocol":"http","endpoint":"client.test:8080"},
            "operation":"POST","path":"/responses"},"effect":{"kind":"http_client_metadata","headers":["x-stainless-lang"]},
            "proof":{"source":"sdk.py:headers; consumer.py:route","fact":"The consumer never reads SDK runtime metadata"}}),
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
                planned.traffic_e2e_report["preflight"]["rules"]["sdk"],
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
