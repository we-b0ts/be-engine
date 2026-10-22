//! Candidate edges are search evidence, not proof that two statements correspond.
use super::*;
use crate::policy::{Resource, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata, WitnessStore,
};
use serde_json::Value;

fn proposal() -> Value {
    json!({"id":"write-clock","match":{"api":"GET /api",
        "resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},
        "operation":"COM_QUERY","sql":"UPDATE events SET updated_at=? WHERE id=?"},
        "effect":{"kind":"mysql_values","values":{"0":{"relative_time":"sql_datetime","utc_offset":"+00:00"}}},
        "proof":{"source":"store.py:save","fact":"Source obtains UTC now immediately before this write"}})
}

fn install(fixture: &Fixture, targets: &[Value]) {
    install_rows(fixture, &[7], targets);
}

fn install_rows(fixture: &Fixture, ids: &[i64], targets: &[Value]) {
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/case-1");
    let events = ids.iter().enumerate().map(|(index, id)| json!({"event_type":"mysql_exchange","connection_id":uuid::Uuid::nil(),"query_sequence":index + 1,
        "target_host":"db.test","target_port":3306,"database":"app","command":"COM_QUERY",
        "sql":format!("UPDATE events SET updated_at='2026-10-16 00:00:00' WHERE id={id}"),
        "response":{"status":"ok"},"timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"outcome":"response"})).collect::<Vec<_>>();
    fs::write(
        case.join("dependencies.jsonl"),
        events
            .iter()
            .map(|event| format!("{event}\n"))
            .collect::<String>(),
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
    let source_time = "2026-10-16T00:00:00Z".parse().unwrap();
    let target_time = "2026-10-16T00:01:00Z".parse().unwrap();
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
        resource: Some(
            serde_json::from_value::<Resource>(proposal()["match"]["resource"].clone()).unwrap(),
        ),
        operation: "COM_QUERY".into(),
        slot: Slot::SqlValue(0),
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
    for event in events {
        let mut metadata = metadata.clone();
        metadata.source.sequence = event["query_sequence"].as_u64();
        let source =
            crate::replay::mysql_source_witness(&event, Surface::DependencyRequest).unwrap();
        if targets.is_empty() {
            metadata.target_role = TargetRole::Unavailable;
            store.record(metadata, &case, &source, None).unwrap();
        } else {
            for (index, target) in targets.iter().enumerate() {
                store
                    .record_observation(
                        metadata.clone(),
                        &case,
                        &source,
                        Some(&serde_json::to_vec(target).unwrap()),
                        Some(&format!("captured-target-{index}")),
                    )
                    .unwrap();
            }
        }
    }
    report["cases"][0]["target_request_started_at"] = json!(target_time);
    report["policy_witnesses"] = serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
    write(&fixture.paths.replay, report);
}

fn target(sql: &str) -> Value {
    json!({"request_started_at":"2026-10-16T00:01:00Z","command":"COM_QUERY","sql":sql,"params":null})
}

#[test]
fn unrelated_mysql_candidates_preserve_missing_target_and_allow_plan_apply() {
    for unrelated in [false, true] {
        let fixture = Fixture::new();
        write(&fixture.proposal, proposal());
        let targets = if unrelated {
            vec![
                target("SELECT name FROM events WHERE id=7"),
                target("UPDATE another_table SET updated_at='2026-10-16 00:01:00' WHERE id=7"),
            ]
        } else {
            vec![]
        };
        install(&fixture, &targets);
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["source_validations"],
            1
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["missing_target_witnesses"],
            1
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["verified"], false);
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}

#[test]
fn unrelated_mysql_candidates_do_not_hide_a_valid_prepared_time_witness() {
    let fixture = Fixture::new();
    write(&fixture.proposal, proposal());
    let mut prepared = target("UPDATE events SET updated_at=? WHERE id=?");
    prepared["command"] = json!("COM_STMT_EXECUTE");
    prepared["params"] =
        json!([{"kind":"string","value":"2026-10-16 00:01:00"},{"kind":"integer","value":7}]);
    install(
        &fixture,
        &[
            target("SELECT name FROM events WHERE id=7"),
            prepared,
            target("UPDATE another_table SET updated_at='2026-10-16 00:01:00' WHERE id=7"),
        ],
    );
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["independent_target_validations"],
        1
    );
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["missing_target_witnesses"],
        0
    );
    apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert!(fixture.state().rule_replay_pending);
}

#[test]
fn same_structure_mysql_candidates_pair_with_their_own_source_rows() {
    for reversed in [false, true] {
        let fixture = Fixture::new();
        write(&fixture.proposal, proposal());
        let mut targets = vec![
            target("UPDATE events SET updated_at='2026-10-16 00:01:00' WHERE id=7"),
            target("UPDATE events SET updated_at='2026-10-16 00:01:00' WHERE id=8"),
        ];
        if reversed {
            targets.reverse();
        }
        install_rows(&fixture, &[7, 8], &targets);
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["independent_target_validations"],
            2
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["missing_target_witnesses"],
            0
        );
        apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert!(fixture.state().rule_replay_pending);
    }
}

#[test]
fn a_valid_mysql_pair_cannot_hide_another_invalid_target_observation() {
    let fixture = Fixture::new();
    write(&fixture.proposal, proposal());
    install_rows(
        &fixture,
        &[7, 8],
        &[
            target("UPDATE events SET updated_at='2026-10-16 00:01:00' WHERE id=7"),
            target("UPDATE events SET updated_at='2026-10-16 00:01:10' WHERE id=8"),
        ],
    );
    fixture.confirm();
    assert!(fixture.plan().is_err());
    assert!(fixture.state().rule_plan.is_none());
}

#[test]
fn an_unobserved_mysql_row_keeps_its_replay_obligation() {
    let fixture = Fixture::new();
    write(&fixture.proposal, proposal());
    install_rows(
        &fixture,
        &[7, 8],
        &[target(
            "UPDATE events SET updated_at='2026-10-16 00:01:00' WHERE id=7",
        )],
    );
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["missing_target_witnesses"],
        1
    );
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["independent_target_validations"],
        1
    );
    apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert!(fixture.state().rule_replay_pending);
}

#[test]
fn related_mysql_candidates_still_reject_unselected_values_and_invalid_times() {
    for sql in [
        "UPDATE events SET updated_at='2026-10-16 00:01:00' WHERE id=8",
        "UPDATE events SET updated_at='2026-10-16 00:01:10' WHERE id=7",
        "UPDATE events SET updated_at=NULL WHERE id=7",
    ] {
        let fixture = Fixture::new();
        write(&fixture.proposal, proposal());
        install(&fixture, &[target(sql)]);
        fixture.confirm();
        let error = format!("{:#}", fixture.plan().unwrap_err());
        assert!(error.contains("write-clock"));
        assert!(error.contains("Source connection"));
        assert!(error.contains("Target observation"));
        assert!(!error.contains(sql));
        assert!(fixture.state().rule_plan.is_none());
    }
}

#[test]
#[ignore = "requires private original finalized Replay evidence and a reviewed proposal"]
fn recorded_mysql_candidate_preflight() {
    let root =
        PathBuf::from(std::env::var_os("TRAFFIC_E2E_MYSQL_PLAN_PROJECT").expect("project path"));
    let report =
        PathBuf::from(std::env::var_os("TRAFFIC_E2E_MYSQL_PLAN_REPORT").expect("report path"));
    let proposal =
        PathBuf::from(std::env::var_os("TRAFFIC_E2E_MYSQL_PLAN_PROPOSAL").expect("proposal path"));
    let proposal_artifact = manifest::Artifact::capture(&proposal).unwrap();
    let proposed = parse_proposal(&fs::read_to_string(&proposal).unwrap()).unwrap();
    assert!(proposed.rules.iter().all(|r| matches!(
        r.as_native().map(|r| &r.effect),
        Some(crate::policy::NativeEffect::MysqlValues(_))
    )));
    let selected = proposed.rules.iter().map(|r| r.id().to_owned()).collect();
    let compiled = compile_policy(&proposed).unwrap();
    let replay: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(replay["finalized"], true);
    let cases = replay["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["case_id"].as_str().unwrap().to_owned(),
                PathBuf::from(c["case_dir"].as_str().unwrap()),
            )
        })
        .collect();
    let mut bundle = manifest::Bundle {
        inventory_path: None,
        replay_path: report.clone(),
        replay,
        assertions: Value::Null,
        cases,
        artifacts: Default::default(),
    };
    bundle.freeze(&report).unwrap();
    bundle.artifacts.insert(proposal, proposal_artifact);
    for directory in bundle.cases.values().cloned().collect::<Vec<_>>() {
        bundle
            .freeze(&directory.join("dependencies.jsonl"))
            .unwrap();
    }
    let fixture = Fixture::new();
    let checked =
        preflight::verify(&root, &fixture.state(), &mut bundle, &compiled, &selected).unwrap();
    assert_eq!(checked.source_validations, 3);
    assert_eq!(checked.independent_target_validations, 1);
    assert_eq!(checked.missing_target_witnesses, 2);
    assert_eq!(checked.status(), "planned_needs_replay");
    for artifact in bundle.artifacts.values() {
        artifact.verify().unwrap();
    }
    println!("{}", serde_json::to_string(&checked).unwrap());
}
