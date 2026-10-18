//! Native proposal transactions retain Source scope and genuine Replay duties.
use super::*;

fn generated() -> serde_json::Value {
    let proof =
        json!({"source":"src/session.rs:12","fact":"Source generates a fresh UUID for this field"});
    json!({"id":"generated","match":{"api":"GET /api"},"effect":{"kind":"response_generated",
        "fields":{"/id":{"contract":{"kind":"uuid_v4"},"proof":proof}}},"proof":proof})
}

#[test]
fn native_response_and_value_rules_share_the_public_strict_payload_transaction() {
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
            json!([super::super::rule(), generated()]),
        );
        fixture.confirm();
        let planned = fixture.plan();
        if changed_business {
            assert!(planned.is_err());
            continue;
        }
        let planned = planned.unwrap();
        assert_eq!(
            planned.traffic_e2e_report["expanded_rules"]
                .as_array()
                .unwrap()
                .len(),
            2
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
        "target_host":"cache.test","target_port":6379,"database":0,"command":"SCARD",
        "args":[raw_body(b"session")],"response":raw_body(b":2\r\n"),"replay_safe":true,
        "session_setup":false,"outcome":"response"})
}

fn ownership() -> serde_json::Value {
    json!({"id":"refresh","match":{},"effect":{"kind":"process_owned","source_revision":"",
        "selector":{"protocol":"redis","ports":[6379],"operation":"SCARD",
        "keys":[{"kind":"exact","value":"session"}],"initial_load_timeout_ms":1000}},
        "proof":{"source":"src/session.rs:42","fact":"The process refreshes this exact cache key independently of API calls"}})
}

fn source_scope(fixture: &Fixture) -> PathBuf {
    let mut state = fixture.state();
    state.recording_run_id = "recording".into();
    let source = state.case_source.clone().unwrap();
    write(
        &source.join("recording-run.json"),
        json!({"run_id":"recording","status":"completed"}),
    );
    fs::write(
        source.join("apis/api/case-1/dependencies.jsonl"),
        source_event().to_string(),
    )
    .unwrap();
    fixture.store().save(&state).unwrap();
    write(&fixture.proposal, ownership());
    source
}

#[test]
fn source_only_ownership_reenumerates_added_cases_at_apply_and_retains_replay_obligation() {
    for added_case in [false, true] {
        let fixture = Fixture::new();
        let source = source_scope(&fixture);
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["obligations"],
            json!(["reclassify"])
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        if added_case {
            let other = source.join("apis/other/case-2");
            fs::create_dir_all(&other).unwrap();
            write(
                &other.join("request.json"),
                json!({"method":"GET","uri":"/other"}),
            );
            write(&other.join("expected-response.json"), json!({}));
            fs::write(other.join("dependencies.jsonl"), source_event().to_string()).unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &planned.plan_id).is_err());
            assert!(fixture.state().rule_plan.is_some());
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert!(fixture.state().rule_replay_pending);
            assert!(!fixture.state().e2e_current);
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
            "response_headers":{"content-type":["application/json"]},"response_body":raw_body(b"{}"),
            "timestamp":"2026-10-16T00:00:00Z","request_started_at":"2026-10-16T00:00:00Z",
            "duration_ms":0,"outcome":"response","error":null});
        fs::write(
            source.join("apis/api/case-1/dependencies.jsonl"),
            event.to_string(),
        )
        .unwrap();
        write(
            &fixture.proposal,
            json!({"id":"capture-config","match":{},"effect":{
            "kind":"capture_http_response","authorities":["service.test:8080"],"methods":["GET"],
            "path":{"kind":"exact","value":"/config"},"status_codes":[200],
            "content_types":["application/json"],"contract":{"kind":"vintage_cache_config"}},
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
            fs::write(source.join("apis/api/case-1/dependencies.jsonl"), "changed").unwrap();
            recover_rewrite_rule_plan(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(fs::read(fixture.policy()).unwrap(), original);
            assert!(fixture.state().rule_replay_pending && fixture.state().rule_plan.is_none());
        } else {
            let applied = applied.unwrap();
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_recording"
            );
            assert!(fixture.state().recording_refresh.is_some());
            assert!(!fixture.state().e2e_current);
            assert!(matches!(
                fixture.state().phase,
                crate::rewrite::model::RewritePhase::AwaitingRecordingRefresh
                    | crate::rewrite::model::RewritePhase::RecordingRequired
            ));
        }
    }
}

#[test]
fn stateful_sequence_plan_requires_the_complete_source_trace_and_preserves_target_replay_obligation()
 {
    for complete in [false, true] {
        let fixture = Fixture::new();
        let proof = json!({"source":"src/tasks.rs:12","fact":"Source issues this ordered two-command update using request-relative scores"});
        let time = json!({"contract":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"},"proof":proof});
        write(
            &fixture.proposal,
            json!({"id":"task-window","match":{"api":"GET /api",
            "resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"writer"},
            "key":{"kind":"exact","value":"tasks"}},"effect":{"kind":"redis_sequence",
            "commands":[{"operation":"ZADD","arguments":{"1":time}},
                {"operation":"ZREMRANGEBYSCORE","arguments":{"2":time}}]},"proof":proof}),
        );
        let event = |command: &str, args: &[&str], sequence: u64| {
            json!({"event_type":"redis_exchange",
            "timestamp":format!("2026-10-16T00:00:0{sequence}Z"),"duration_ms":0,
            "connection_id":uuid::Uuid::nil(),"sequence":sequence,
            "target_host":"cache.test","target_port":6379,"database":0,"username":"writer","resp_version":2,
            "command":command,"args":args.iter().map(|value|raw_body(value.as_bytes())).collect::<Vec<_>>(),
            "response_kind":"integer","response":raw_body(b":1\r\n"),"outcome":"response","replay_safe":true})
        };
        let mut events = vec![event("ZADD", &["tasks", "1000.25", "member"], 1)];
        if complete {
            events.push(event("ZREMRANGEBYSCORE", &["tasks", "-inf", "910.25"], 2));
        }
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1");
        fs::write(
            case.join("dependencies.jsonl"),
            events
                .into_iter()
                .map(|event| format!("{event}\n"))
                .collect::<String>(),
        )
        .unwrap();
        fixture.confirm();
        let planned = fixture.plan();
        if !complete {
            assert!(planned.is_err());
            continue;
        }
        let planned = planned.unwrap();
        assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["rules"]["task-window"],
            2
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["stateful_target_obligations"],
            json!(["task-window"])
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}

#[test]
fn independent_redis_nonce_with_key_capture_survives_public_plan_and_apply() {
    let fixture = Fixture::new();
    let proof = json!({"source":"src/auth.rs:create_session","fact":"Source writes an independent canonical token_urlsafe(32) with a fresh UUID key and fixed TTL"});
    write(
        &fixture.proposal,
        json!({"id":"session-nonce","match":{"api":"GET /api",
        "resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "key":{"kind":"affix","prefix":"sessions:"}},"effect":{"kind":"redis_sequence",
        "key":{"kind":"capture","binding":"session","template":"sessions:{value}","format":{"kind":"uuid_v4"}},
        "commands":[{"operation":"SET","arguments":{"1":{"kind":"json","fields":{
            "/poll_token":{"kind":"random","format":"base64url","length":43}
        }}}}]},"proof":proof}),
    );
    let source = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/case-1");
    fs::write(source.join("dependencies.jsonl"),json!({"event_type":"redis_exchange","timestamp":"2026-10-16T00:00:00Z",
        "connection_id":uuid::Uuid::nil(),"sequence":1,"duration_ms":0,"target_host":"cache.test","target_port":6379,
        "database":0,"resp_version":2,"command":"SET","args":[raw_body(b"sessions:01234567-89ab-4def-8123-456789abcdef"),
            raw_body(json!({"poll_token":"A".repeat(43),"status":"pending"}).to_string().as_bytes()),raw_body(b"EX"),raw_body(b"300")],
        "response_kind":"simple_string","response":raw_body(b"+OK\r\n"),"outcome":"response","replay_safe":true}).to_string()).unwrap();
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["rules"]["session-nonce"],
        1
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(applied.traffic_e2e_report["verified"], false);
    assert!(fixture.state().rule_replay_pending);
}

#[test]
fn generated_queue_uuid_and_bounded_origin_survive_public_plan_apply_with_fresh_replay_pending() {
    let fixture = Fixture::new();
    write(
        &fixture.proposal,
        json!({"id":"queue-generated","match":{"api":"GET /api",
        "resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"key":{"kind":"exact","value":"queue"}},
        "effect":{"kind":"redis_sequence","commands":[{"operation":"LPUSH","arguments":{"1":{"kind":"json","fields":{
            "/delivery_tag":{"kind":"random","format":"uuid","length":36},
            "/origin":{"kind":"random","format":"string","max_length":255}
        }}}}]},"proof":{"source":"src/producer.rs:publish","fact":"Source generates a fresh delivery UUID and process origin metadata while preserving the queued business body"}}),
    );
    let source = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/case-1");
    let event = json!({"event_type":"redis_exchange","timestamp":"2026-10-16T00:00:00Z",
        "connection_id":uuid::Uuid::nil(),"sequence":1,"duration_ms":0,"target_host":"cache.test","target_port":6379,
        "database":0,"resp_version":2,"command":"LPUSH","args":[raw_body(b"queue"),raw_body(json!({"delivery_tag":"01234567-89ab-4def-8123-456789abcdef","origin":"gen123@source","body":"exact"}).to_string().as_bytes())],
        "response_kind":"integer","response":raw_body(b":1\r\n"),"outcome":"response","replay_safe":true}).to_string();
    fs::write(source.join("dependencies.jsonl"), &event).unwrap();
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["rules"]["queue-generated"],
        1
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(applied.traffic_e2e_report["verified"], false);
    assert!(fixture.state().rule_replay_pending);
    assert_eq!(
        fs::read_to_string(source.join("dependencies.jsonl")).unwrap(),
        event
    );
}
