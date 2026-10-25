//! Redis search edges outside a rule's actual key scope never prove a match.
use super::*;
use crate::policy::{Resource, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata, WitnessStore,
};

fn proposal() -> serde_json::Value {
    json!({"format":"traffic-policy/v2","redis":{"keys":{"as-of":{"kind":"time","formats":["unix_seconds"]}}}})
}

fn resource() -> Resource {
    serde_json::from_value(json!({"protocol":"redis","endpoint":"cache.test:6379","database":0}))
        .unwrap()
}

#[test]
fn redis_candidates_exclude_other_keys_but_preserve_same_key_options_and_missing_target() {
    for scenario in [
        "related-plus-unrelated",
        "unrelated-only",
        "wrong-ttl",
        "wrong-option",
    ] {
        let fixture = Fixture::new();
        write(&fixture.proposal, proposal());
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1");
        let source_time = chrono::DateTime::parse_from_rfc3339("2026-10-16T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let target_time = source_time + chrono::Duration::seconds(60);
        let args = |key: &str, time: i64, option: &str, ttl: &str| {
            vec![
                key.as_bytes().to_vec(),
                format!("{time}.125").into_bytes(),
                option.as_bytes().to_vec(),
                ttl.as_bytes().to_vec(),
            ]
        };
        let source = args("as-of", source_time.timestamp(), "EX", "2764800");
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,"timestamp":source_time,"duration_ms":0,
            "target_host":"cache.test","target_port":6379,"database":0,"resp_version":2,"command":"SET","args":source.iter().map(|v|raw_body(v)).collect::<Vec<_>>(),"response_kind":"simple_string","response":raw_body(b"+OK\r\n"),"outcome":"response","replay_safe":true});
        fs::write(case.join("dependencies.jsonl"), format!("{event}\n")).unwrap();
        crate::platform::encryption_key::load_or_create(fixture.root()).unwrap();
        let mut report: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        report["session_id"] = json!(session);
        let store = WitnessStore::new_bound(
            fixture.paths.replay.parent().unwrap(),
            &session,
            report["replay_policy"]["fingerprint"].as_str().unwrap(),
        )
        .unwrap();
        let metadata = WitnessMetadata {
            surface: Surface::DependencyRequest,
            source_role: SourceRole::DependencyRequest,
            target_role: TargetRole::IndependentTargetObservation,
            source: SourceIdentity {
                case_id: "case-1".into(),
                exchange_id: None,
                connection_id: Some(uuid::Uuid::nil().to_string()),
                sequence: Some(1),
            },
            resource: Some(resource()),
            operation: "SET".into(),
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
        let mut targets = vec![args("other-cache", target_time.timestamp(), "EX", "3600")];
        if scenario != "unrelated-only" {
            targets.push(args(
                "as-of",
                target_time.timestamp(),
                if scenario == "wrong-option" {
                    "PX"
                } else {
                    "EX"
                },
                if scenario == "wrong-ttl" {
                    "3600"
                } else {
                    "2764800"
                },
            ));
        }
        for target in targets {
            store
                .record(
                    metadata.clone(),
                    &case,
                    &serde_json::to_vec(&source).unwrap(),
                    Some(&serde_json::to_vec(&target).unwrap()),
                )
                .unwrap();
        }
        report["cases"][0]["target_request_started_at"] = json!(target_time);
        report["policy_witnesses"] =
            serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
        write(&fixture.paths.replay, report);
        fixture.confirm();
        let plan = fixture.plan();
        if matches!(scenario, "wrong-ttl" | "wrong-option") {
            let error = format!("{:#}", plan.err().unwrap());
            assert!(
                error.contains(if scenario == "wrong-ttl" {
                    "argument 3"
                } else {
                    "argument 2"
                }),
                "{error}"
            );
        } else {
            let plan = plan.unwrap();
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                if scenario == "unrelated-only" { 0 } else { 1 }
            );
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["missing_target_witnesses"],
                if scenario == "unrelated-only" { 1 } else { 0 }
            );
            assert_eq!(plan.traffic_e2e_report["verified"], false);
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
        }
    }
}
