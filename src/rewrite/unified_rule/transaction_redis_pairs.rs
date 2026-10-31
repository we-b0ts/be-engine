//! Same-key Redis candidates retain strict values without certifying failed pairs.
use super::*;
use crate::policy::{Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata, WitnessStore,
};
use serde_json::Value;

fn install(fixture: &Fixture, scenario: &str, reversed: bool) {
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3","json":{"fields":{
            "/members":{"kind":"unordered"},
            "/id":{"kind":"identity","formats":[
                {"prefix":"thinking-","hex":12},
                {"prefix":"text-","format":"decimal"}
            ]},
            "/timestamp":{"kind":"time","formats":["unix_milliseconds"]}
        }}}),
    );
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/00000000-0000-4000-8000-000000000001");
    let source_time: chrono::DateTime<chrono::Utc> = "2026-10-16T00:00:00Z".parse().unwrap();
    let target_time = source_time + chrono::Duration::seconds(60);
    let block = |thinking: bool, time: chrono::DateTime<chrono::Utc>, content: &str| {
        json!({
            "id":if thinking {"thinking-aaaaaaaaaaaa".into()} else {format!("text-{}",time.timestamp_millis())},
            "type":if thinking {"thinking"} else {"text"},
            "timestamp":time.timestamp_millis(),"content":content,"status":"streaming"
        })
    };
    let args = |value: Value| vec![b"blocks".to_vec(), value.to_string().into_bytes()];
    let mut sources = [
        args(block(true, source_time, "")),
        args(block(false, source_time, "")),
    ];
    if reversed {
        sources.reverse();
    }
    let events = sources.iter().enumerate().map(|(index, source)| {
        json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":index+1,
            "target_host":"cache.test","target_port":6379,"database":0,"resp_version":2,"command":"RPUSH",
            "args":source.iter().map(|value|raw_body(value)).collect::<Vec<_>>(),
            "response_kind":"integer","response":raw_body(format!(":{}\r\n",index+1).as_bytes()),
            "timestamp":source_time,"duration_ms":0,"outcome":"response","replay_safe":true})
    }).collect::<Vec<_>>();
    fs::write(
        case.join("dependencies.jsonl"),
        events
            .iter()
            .map(|event| format!("{event}\n"))
            .collect::<String>(),
    )
    .unwrap();
    crate::platform::encryption_key::load_or_create(fixture.root()).unwrap();
    let mut report: Value =
        serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    report["session_id"] = json!(session);
    let store = WitnessStore::new_bound(
        fixture.paths.replay.parent().unwrap(),
        &session,
        report["replay_policy"]["fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    let mut target = block(false, target_time, "");
    if scenario == "invalid-time" {
        target["timestamp"] = json!((target_time + chrono::Duration::days(1)).timestamp_millis());
    }
    if scenario == "invalid-content" {
        target["content"] = json!("changed business content");
    }
    let mut targets = if scenario == "missing-target" {
        vec![]
    } else {
        vec![args(target)]
    };
    if scenario == "another-invalid-target" {
        targets.push(args(block(false, target_time, "changed business content")));
    }
    if scenario == "extra-argument" {
        targets[0].push(b"unexpected list member".to_vec());
    }
    for (index, source) in sources.iter().enumerate() {
        let mut metadata = WitnessMetadata {
            surface: Surface::DependencyRequest,
            source_role: SourceRole::DependencyRequest,
            target_role: TargetRole::IndependentTargetObservation,
            source: SourceIdentity {
                case_id: "00000000-0000-4000-8000-000000000001".into(),
                exchange_id: None,
                connection_id: Some(uuid::Uuid::nil().to_string()),
                sequence: Some(index as u64 + 1),
            },
            resource: Some(
                serde_json::from_value(json!({
                    "protocol":"redis","endpoint":"cache.test:6379","database":0
                }))
                .unwrap(),
            ),
            operation: "RPUSH".into(),
            slot: Slot::Value,
            clocks: WitnessClocks {
                case: ClockPair {
                    source: Some(source_time),
                    target: Some(target_time),
                },
                dependency: ClockPair {
                    source: Some(source_time),
                    target: Some(target_time),
                },
                delivery: Default::default(),
            },
        };
        if targets.is_empty() {
            metadata.target_role = TargetRole::Unavailable;
            store
                .record(metadata, &case, &serde_json::to_vec(source).unwrap(), None)
                .unwrap();
        } else {
            for (target_index, target) in targets.iter().enumerate() {
                store
                    .record_observation(
                        metadata.clone(),
                        &case,
                        &serde_json::to_vec(source).unwrap(),
                        Some(&serde_json::to_vec(target).unwrap()),
                        Some(&format!("target-{target_index}")),
                    )
                    .unwrap();
            }
        }
    }
    report["cases"][0]["target_request_started_at"] = json!(target_time);
    report["policy_witnesses"] = serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
    write(&fixture.paths.replay, report);
}

#[test]
fn redis_request_candidates_find_their_valid_source_pair_in_either_source_order() {
    for reversed in [false, true] {
        let fixture = Fixture::new();
        install(&fixture, "valid", reversed);
        fixture.confirm();
        let plan = fixture.plan().unwrap();
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["independent_target_validations"],
            2
        );
        // The unused thinking call stays unobserved; a content pair is not consumption.
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["missing_target_witnesses"],
            1
        );
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}

#[test]
fn redis_request_pair_search_cannot_hide_an_invalid_actual_observation() {
    for scenario in [
        "invalid-content",
        "invalid-time",
        "extra-argument",
        "another-invalid-target",
    ] {
        let fixture = Fixture::new();
        install(&fixture, scenario, false);
        fixture.confirm();
        let original = fs::read(fixture.policy()).unwrap();
        let error = format!("{:#}", fixture.plan().unwrap_err());
        assert!(error.contains("no valid pair"), "{scenario}: {error}");
        assert!(
            error.contains("Source candidate case=00000000-0000-4000-8000-000000000001"),
            "{scenario}: {error}"
        );
        assert!(
            !error.contains("changed business content"),
            "{scenario}: {error}"
        );
        assert!(fixture.state().rule_plan.is_none());
        assert_eq!(fs::read(fixture.policy()).unwrap(), original);
    }
}

#[test]
fn absent_redis_target_keeps_source_validation_and_a_fresh_replay_obligation() {
    let fixture = Fixture::new();
    install(&fixture, "missing-target", false);
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["independent_target_validations"],
        1
    );
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["missing_target_witnesses"],
        2
    );
    let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
}
