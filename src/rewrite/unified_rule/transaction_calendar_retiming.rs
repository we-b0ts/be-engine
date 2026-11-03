//! A new input day invalidates old execution evidence, never its strict runtime counters.
use super::*;
use crate::policy::{Resource, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata, WitnessStore,
};

const CASE: &str = "00000000-0000-4000-8000-000000000001";

fn setup(mode: &str) -> Fixture {
    let fixture = Fixture::with_request_time(Some("2026-10-16T15:59:00Z"));
    fixture.replace_responses(
        json!({"status":200,"timestamp":"2026-10-16T15:59:10Z","body":body(json!({}))}),
        json!({"version":1,"status":200,"request_sent_at":"2026-10-16T16:01:00Z","response_completed_at":"2026-10-16T16:01:10Z","body":body(json!({}))}),
    );
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3","json":{"fields":{
            "/lastActiveDate":{"kind":"time","formats":[{"format":"calendar_date","utc_offset":"+08:00"}]}
        }}}),
    );
    let payload = json!({"lastActiveDate":"2026-10-16","currentStreak":86}).to_string();
    let database = if mode == "other-resource" {
        "archive"
    } else {
        "app"
    };
    let read = json!({"event_type":"mysql_exchange","connection_id":uuid::Uuid::nil(),"query_sequence":1,
        "target_host":"db.test","target_port":3306,"database":database,"command":"COM_QUERY",
        "request_started_at":"2026-10-16T15:59:01Z","timestamp":"2026-10-16T15:59:02Z","duration_ms":1000,
        "sql":"SELECT payload FROM pets WHERE id=7","outcome":"response",
        "response":{"status":"resultset","columns":[{"name":"payload","column":"payload","table":"pets","family":"string","sql_type":"VARCHAR"}],"rows":[[{"kind":"string","value":payload}]]}});
    let write_event = json!({"event_type":"mysql_exchange","connection_id":uuid::Uuid::nil(),"query_sequence":2,
        "target_host":"db.test","target_port":3306,"database":"app","command":"COM_QUERY",
        "request_started_at":"2026-10-16T15:59:03Z","timestamp":"2026-10-16T15:59:04Z","duration_ms":1000,
        "sql":format!("UPDATE pets SET payload='{payload}' WHERE id=7"),"response":{"status":"ok"},"outcome":"response"});
    let directory = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join(format!("apis/api/{CASE}"));
    fs::write(
        directory.join("dependencies.jsonl"),
        format!("{read}\n{write_event}\n"),
    )
    .unwrap();
    let key = fixture
        .root()
        .join(".traffic-e2e/local")
        .join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    fs::create_dir_all(key.parent().unwrap()).unwrap();
    fs::write(
        key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    report["session_id"] = json!(session);
    report["complete"] = false.into();
    report["finalized"] = (mode != "unfinalized").into();
    report["cases"][0]["target_request_started_at"] = json!("2026-10-16T16:01:00Z");
    let store = WitnessStore::new_bound(
        fixture.paths.replay.parent().unwrap(),
        &session,
        report["replay_policy"]["fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    for (event, surface, role, start, end) in [
        (
            &read,
            Surface::DependencyRequest,
            TargetRole::IndependentTargetObservation,
            "2026-10-16T16:01:01Z",
            "2026-10-16T16:01:02Z",
        ),
        (
            &read,
            Surface::DependencyResponse,
            if mode == "render-only" {
                TargetRole::DerivedDelivery
            } else {
                TargetRole::DeliveredInput
            },
            "2026-10-16T16:01:01Z",
            if mode == "future-delivery" {
                "2026-10-16T16:01:05Z"
            } else {
                "2026-10-16T16:01:02Z"
            },
        ),
        (
            &write_event,
            Surface::DependencyRequest,
            TargetRole::IndependentTargetObservation,
            "2026-10-16T16:01:03Z",
            "2026-10-16T16:01:04Z",
        ),
    ] {
        if mode == "missing-read" && event["query_sequence"] == 1 {
            continue;
        }
        let source = preflight::dependency::source_witness(surface, event, &directory).unwrap();
        let mut target: serde_json::Value = serde_json::from_slice(&source).unwrap();
        if surface == Surface::DependencyResponse {
            target["request"]["request_started_at"] = json!(start);
            target["response_delivered_at"] = json!(end);
        } else {
            target["request_started_at"] = json!(start);
        }
        if event["query_sequence"] == 2 {
            let changed = json!({"lastActiveDate":"2026-10-17","currentStreak":87});
            target["sql"] = json!(format!("UPDATE pets SET payload='{changed}' WHERE id=7"));
        }
        let metadata = WitnessMetadata {
            surface,
            source_role: if surface == Surface::DependencyResponse {SourceRole::DependencyResponse} else {SourceRole::DependencyRequest},
            target_role: role,
            source: SourceIdentity {case_id:CASE.into(),exchange_id:None,connection_id:Some(uuid::Uuid::nil().to_string()),sequence:event["query_sequence"].as_u64()},
            resource:Some(serde_json::from_value::<Resource>(json!({"protocol":"mysql","endpoint":"db.test:3306","database":event["database"]})).unwrap()),
            operation:"COM_QUERY".into(),slot:Slot::Value,
            clocks:WitnessClocks {
                case:ClockPair {source:Some("2026-10-16T15:59:00Z".parse().unwrap()),target:Some("2026-10-16T16:01:00Z".parse().unwrap())},
                dependency:ClockPair {source:Some(event["request_started_at"].as_str().unwrap().parse().unwrap()),target:Some(start.parse().unwrap())},
                delivery:ClockPair {source:Some(event["timestamp"].as_str().unwrap().parse().unwrap()),target:Some(end.parse().unwrap())},
            },
        };
        store
            .record_observation(
                metadata,
                &directory,
                &source,
                Some(&serde_json::to_vec(&target).unwrap()),
                Some(&format!("{}-{surface:?}", event["query_sequence"])),
            )
            .unwrap();
    }
    report["policy_witnesses"] = serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
    write(&fixture.paths.replay, report);
    let mut aggregate: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.paths.aggregate).unwrap()).unwrap();
    aggregate["complete"] = false.into();
    write(&fixture.paths.aggregate, aggregate);
    fixture.confirm();
    fixture
}

#[test]
fn changed_delivered_calendar_input_preserves_counter_failures_as_fresh_execution_obligations() {
    for mode in [
        "valid",
        "render-only",
        "missing-read",
        "future-delivery",
        "other-resource",
        "unfinalized",
        "stale-source",
        "stale-target",
    ] {
        let fixture = setup(mode);
        let planned = fixture.plan();
        if matches!(
            mode,
            "render-only" | "missing-read" | "future-delivery" | "other-resource" | "unfinalized"
        ) {
            assert!(planned.is_err(), "{mode}");
            assert!(fixture.state().rule_plan.is_none());
            continue;
        }
        let plan = planned.unwrap_or_else(|error| panic!("{mode}: {error:#}"));
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        assert!(
            !plan.traffic_e2e_report["preflight"]["unvalidated_retimed_witnesses"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        if mode == "stale-source" {
            let source = fixture
                .state()
                .case_source
                .as_ref()
                .unwrap()
                .join(format!("apis/api/{CASE}/dependencies.jsonl"));
            fs::write(source, "\n").unwrap();
        } else if mode == "stale-target" {
            let mut report: serde_json::Value =
                serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
            report["changed_after_plan"] = true.into();
            write(&fixture.paths.replay, report);
        }
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id);
        if mode.starts_with("stale-") {
            assert!(applied.is_err(), "{mode}");
            continue;
        }
        assert_eq!(
            applied.unwrap().traffic_e2e_report["requires_fresh_replay"],
            true
        );
        let policy =
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
        assert_eq!(policy.json.unwrap().fields.len(), 1);
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}
