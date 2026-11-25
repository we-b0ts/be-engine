//! Native proposal transactions retain Source scope and genuine Replay duties.
use super::*;
use serde_json::Value;
use traffic_rewrite_rules::rewrite::unified_rule::preflight::PreflightMethods;

fn generated() -> serde_json::Value {
    let proof =
        json!({"source":"src/session.rs:12","fact":"Source generates a fresh UUID for this field"});
    json!({"id":"generated","match":{"api":"GET /api"},"effect":{"kind":"response_generated",
        "fields":{"/id":{"contract":{"kind":"uuid_v4"},"proof":proof}}},"proof":proof})
}

#[test]
fn public_apply_rejects_a_changed_independent_source_proof_before_writing_runtime_policy() {
    let fixture = Fixture::new();
    fixture.replace_response_bodies(
        br#"{"id":"11111111-1111-4111-8111-111111111111"}"#,
        br#"{"id":"22222222-2222-4222-8222-222222222222"}"#,
    );
    write(&fixture.proposal, generated());
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    let original = fs::read(fixture.policy()).unwrap();
    let events_path =
        crate::internal_runtime::root(fixture.root()).join("rewrite/rule-plans/events.json");
    let mut events: serde_json::Value =
        serde_json::from_slice(&fs::read(&events_path).unwrap()).unwrap();
    events["plans"]["GET /api"]["plan"]["unified"]["source_proofs"]["rules"][0]["proof"]["fact"] =
        json!("Changed Source claim after plan publication");
    write(&events_path, events);
    let error = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap_err();
    assert!(format!("{error:#}").contains("Source proof snapshot changed"));
    assert_eq!(fs::read(fixture.policy()).unwrap(), original);
}

#[test]
fn native_response_and_global_formats_share_the_public_strict_payload_transaction() {
    for changed_business in [false, true] {
        let fixture = Fixture::new();
        let source =
            json!({"id":"11111111-1111-4111-8111-111111111111","members":[1,2],"business":"exact"});
        let mut target =
            json!({"id":"22222222-2222-4222-8222-222222222222","members":[2,1],"business":"exact"});
        if changed_business {
            target["business"] = json!("different");
        }
        fixture
            .replace_response_bodies(source.to_string().as_bytes(), target.to_string().as_bytes());
        write(
            &fixture.proposal,
            json!({"format":"traffic-policy/v3","json":super::super::rule()["json"],"rules":[generated()]}),
        );
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        if changed_business {
            assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
            assert_eq!(
                planned.traffic_e2e_report["preflight"]["independent_target_validations"],
                0
            );
            continue;
        }
        assert_eq!(
            planned.traffic_e2e_report["expanded_rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["rules"]["generated"],
            1
        );
        let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["verified"], false);
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}

fn source_event() -> serde_json::Value {
    json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,"timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "target_host":"cache.test","target_port":6379,"database":0,"command":"GET",
        "args":[raw_body(b"session")],"response":raw_body(b"$1\r\n2\r\n"),"replay_safe":true,
        "session_setup":false,"outcome":"response"})
}

fn ownership() -> serde_json::Value {
    json!({"id":"refresh","match":{},"effect":{"kind":"process_owned","task_name":"refresh",
        "source_revision":format!("sha256:{}","1".repeat(64)),
        "selector":{"protocol":"redis","ports":[6379],"operation":"GET",
        "keys":[{"kind":"exact","value":"session"}]}},
        "proof":{"source":"src/session.rs:42","fact":"The process refreshes this exact cache key independently of API calls"}})
}

fn source_scope(fixture: &Fixture) -> PathBuf {
    let mut state = fixture.state();
    let revision = crate::source_snapshot::test_fixture::install(fixture.root());
    let inventory = fixture
        .paths
        .replay
        .ancestors()
        .map(|path| path.join("case-groups.json"))
        .find(|path| path.is_file())
        .unwrap();
    let mut groups: Value = serde_json::from_slice(&fs::read(&inventory).unwrap()).unwrap();
    groups["source_revision"] = json!(revision);
    write(&inventory, groups);
    let runner = fixture
        .paths
        .replay
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("state.yaml");
    let mut execution: Value = serde_yaml::from_str(&fs::read_to_string(&runner).unwrap()).unwrap();
    execution["source_revision"] = json!(revision);
    fs::write(&runner, serde_yaml::to_string(&execution).unwrap()).unwrap();
    state.source_revision = Some(revision);
    state.recording_run_id = "recording".into();
    let source = state.case_source.clone().unwrap();
    write(
        &source.join("recording-run.json"),
        json!({"run_id":"recording","status":"completed"}),
    );
    fs::write(
        source.join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl"),
        source_event().to_string(),
    )
    .unwrap();
    fixture.store().save(&state).unwrap();
    write(&fixture.proposal, ownership());
    source
}

#[test]
fn source_only_ownership_reenumerates_added_cases_without_inventing_ownerless_work() {
    for added_case in [false, true] {
        let fixture = Fixture::new();
        let source = source_scope(&fixture);
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["obligations"],
            json!(["attribution_review"])
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        if added_case {
            let other = source.join("apis/other/00000000-0000-4000-8000-000000000002");
            fs::create_dir_all(&other).unwrap();
            write(
                &other.join("request.json"),
                json!({"method":"GET","uri":"/other"}),
            );
            write(&other.join("expected-response.json"), json!({}));
            fs::write(other.join("dependencies.jsonl"), source_event().to_string()).unwrap();
            recording_fixture::seal(&source);
            assert!(apply_rewrite_rule(fixture.context(), &planned.plan_id).is_err());
            assert!(fixture.state().rule_plan.is_some());
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], false);
            let state = fixture.state();
            assert!(!state.e2e_current);
            assert!(!state.rule_replay_pending);
            // These original occurrences already belong to a Case. A policy
            // proposal alone neither disputes that owner nor applies new proof.
            assert!(crate::dependency_review::required_action(fixture.root(), &state).is_none());
            assert!(state.dependency_review.decisions.is_empty());
            assert!(state.dependency_review.receipts.is_empty());
        }
    }
}

#[test]
fn capture_source_proof_requires_fresh_recording_and_crash_recovery_restores_the_original_effect() {
    for fail_publication in [false, true] {
        let fixture = Fixture::new();
        let source = source_scope(&fixture);
        let event = json!({"event_type":"http_exchange","id":uuid::Uuid::new_v4(),"scheme":"http",
            "authority":"service.test:8080","method":"GET","uri":"/config",
            "request_headers":{},"request_body":raw_body(b""),"response_status":200,
            "response_headers":{"content-type":["application/json"]},"response_body":raw_body(br#"{"addresses":["10.0.0.1:6379"]}"#),
            "timestamp":"2026-10-16T00:00:00Z","request_started_at":"2026-10-16T00:00:00Z",
            "duration_ms":0,"outcome":"response","error":null});
        fs::write(
            source.join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl"),
            event.to_string(),
        )
        .unwrap();
        write(
            &fixture.proposal,
            json!({"id":"capture-config","match":{},"effect":{
            "kind":"capture_http_response","authorities":["service.test:8080"],"methods":["GET"],
            "path":{"kind":"exact","value":"/config"},"status_codes":[200],
            "content_types":["application/json"],"contract":{"kind":"documents","rules":[{"fields":[{"path":"/addresses/*","format":"host_port","protocol":"redis"}]}]}},
            "proof":{"source":"src/config.rs:12","fact":"Source loads the process cache configuration from this exact response"}}),
        );
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(
            planned.traffic_e2e_report["status"],
            "planned_needs_recording"
        );
        assert_eq!(planned.traffic_e2e_report["requires_fresh_recording"], true);
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["pending_effect_evidence"],
            json!(["capture-config"])
        );
        let original = fs::read(fixture.policy()).unwrap();
        let collisions = if fail_publication {
            (1..=16)
                .map(|advance| {
                    let path = crate::internal_runtime::root(fixture.root())
                        .join("rewrite")
                        .join(format!(
                            ".state.json.tmp.{}.{}",
                            std::process::id(),
                            fixture.state().revision + advance
                        ));
                    fs::write(&path, "force final workflow publication to fail").unwrap();
                    path
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id);
        for path in collisions {
            fs::remove_file(path).unwrap();
        }
        if fail_publication {
            assert!(applied.is_err());
            assert_eq!(fs::read(fixture.policy()).unwrap(), original);
            let journal = fixture.state();
            let record = journal
                .rule_plan
                .as_ref()
                .unwrap()
                .unified
                .as_ref()
                .unwrap();
            assert!(record.applying() && record.preflight.needs_recording());
            // A crash may publish the exact updated policy. Recovery must undo
            // its effect before retiring the saved fresh-recording obligation.
            fs::write(fixture.policy(), &record.updated).unwrap();
            fs::write(
                source.join("dependencies.jsonl"),
                "changed authoritative Source",
            )
            .unwrap();
            recover_rewrite_rule_plan(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(fs::read(fixture.policy()).unwrap(), original);
            assert!(fixture.state().rule_replay_pending && fixture.state().rule_plan.is_none());
        } else {
            let applied = applied.unwrap();
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_recording"
            );
            assert_scoped_capture_pending(&fixture);
        }
    }
}
