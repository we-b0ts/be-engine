//! Candidate edges are search evidence, not proof that two statements correspond.
use super::*;
use serde_json::Value;
use traffic_rewrite_rules::rewrite::unified_rule::manifest::ArtifactMethods;
use traffic_rewrite_rules::rewrite::unified_rule::preflight::PreflightMethods;

#[test]
fn interrupted_diagnostics_cannot_authorize_a_primary_rule_plan() {
    for finalized in [false, true] {
        let fixture = Fixture::new();
        let mut replay: Value =
            serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
        replay["interrupted"] = true.into();
        replay["finalized"] = finalized.into();
        replay["complete"] = false.into();
        write(&fixture.paths.replay, replay);
        let mut aggregate: Value =
            serde_json::from_slice(&fs::read(&fixture.paths.aggregate).unwrap()).unwrap();
        aggregate["complete"] = false.into();
        write(&fixture.paths.aggregate, aggregate);
        fixture.confirm();
        if !finalized {
            let evidence = fixture.evidence();
            assert_eq!(
                evidence.facts["policy_freshness"]["requires_fresh_replay"],
                true
            );
            assert!(evidence.applicable_rule_planners.is_empty());
        }
        let error = fixture.plan().unwrap_err();
        assert!(
            format!("{error:#}").contains(if finalized {
                "complete finalized Replay"
            } else {
                "evidence=unavailable"
            }),
            "{error:#}"
        );
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
    let checked = preflight::verify(
        &root,
        &fixture.state(),
        &mut bundle,
        &compiled,
        &compiled,
        &selected,
    )
    .unwrap();
    assert_eq!(checked.source_validations, 3);
    assert_eq!(checked.independent_target_validations, 1);
    assert_eq!(checked.missing_target_witnesses, 2);
    assert_eq!(checked.status(), "planned_needs_replay");
    for artifact in bundle.artifacts.values() {
        artifact.verify().unwrap();
    }
    println!("{}", serde_json::to_string(&checked).unwrap());
}
