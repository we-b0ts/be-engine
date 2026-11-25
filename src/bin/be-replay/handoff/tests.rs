use super::*;

const TARGET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FIXED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn failed_attempt(id: u128) -> E2eEventSessionResult {
    E2eEventSessionResult {
        run_key: "fixture".to_owned(),
        attempt_id: Uuid::from_u128(id).simple().to_string(),
        recording_root: "fixture".into(),
        target_commit: Some(TARGET.to_owned()),
        target_inputs: None,
        target_image_id: None,
        passed: false,
        events: Default::default(),
        phase: traffic_e2e::E2eEventSessionPhase::Replaying,
        apis: Default::default(),
        error: None,
        progress: "fixture-progress".into(),
        report: "fixture-report".into(),
    }
}

fn finding(cause: &str, seq: u64) -> Finding {
    Finding {
        root_cause: cause.to_owned(),
        summary: format!("Reviewed {cause}"),
        sequences: BTreeSet::from([seq]),
        scope: None,
    }
}

fn groups(first_unmatched: Option<Finding>, others: Vec<Finding>) -> Findings {
    Findings {
        first_unmatched,
        others,
    }
}

fn gap_receipt(origin: u128, cause: &str, evidence: &str) -> Receipt {
    Receipt::EngineGap {
        attempt_id: Uuid::from_u128(origin),
        root_cause: cause.to_owned(),
        evidence: evidence.to_owned(),
    }
}

#[test]
fn saved_plans_keep_assignments_and_allow_filing_first_unmatched() {
    let attempt = failed_attempt(1);
    let first = finding("first", 9);
    let mut ready = serde_json::to_value(first.clone()).unwrap();
    ready["basis"] = json!("source_proven");
    ready["kind"] = json!("target");
    ready["code_paths"] = json!(["first.rs"]);
    ready["blocked_by"] = json!(["another"]);
    let mut unreviewed = serde_json::to_value(finding("unreviewed", 8)).unwrap();
    unreviewed["basis"] = json!("hypothesis");
    let legacy = serde_json::to_value(finding("legacy coordinator", 10)).unwrap();
    let mut workflow: Workflow = serde_json::from_value(json!({
        "repair": {
            "attempt_id": attempt.attempt_id, "base_commit": TARGET, "failed_sequence": 9,
            "plan": {"implementers":[ready], "coordinator":[unreviewed, legacy], "waiting":[]}
        }
    }))
    .unwrap();
    assert!(workflow.next(&attempt, TARGET).is_none());
    let saved = serde_json::to_value(&workflow).unwrap();
    let plan = &saved["repair"]["plan"];
    assert_eq!(plan["implementers"][0]["root_cause"], "first");
    assert_eq!(plan["waiting"][0]["root_cause"], "legacy coordinator");
    assert!(plan["implementers"][0].get("basis").is_none());
    assert!(plan["implementers"][0].get("kind").is_none());
    assert!(plan["implementers"][0].get("code_paths").is_none());
    assert!(plan["implementers"][0].get("blocked_by").is_none());
    assert!(plan.get("coordinator").is_none());

    let mut legacy_selected = saved;
    legacy_selected["repair"]["blocker"] = json!("first");
    let with_primary: Workflow = serde_json::from_value(legacy_selected).unwrap();
    let action = with_primary.next(&attempt, TARGET).unwrap();
    assert_eq!(action["details"]["first_unmatched"], "first");

    workflow
        .set_plan(&attempt, 9, groups(Some(first), vec![]), 2)
        .unwrap();
    assert_eq!(
        workflow.next(&attempt, TARGET).unwrap()["kind"],
        "implementation_required"
    );
}

#[test]
fn first_unmatched_is_assigned_and_accepts_engine_gap_only_with_evidence() {
    let mut workflow = Workflow::default();
    let attempt = failed_attempt(1);
    let mut first = finding("unsupported event", 9);
    first.scope = Some("startup".into());
    let later = finding("independent Target repair", 8);
    let plan = workflow
        .set_plan(
            &attempt,
            9,
            groups(Some(first.clone()), vec![later.clone()]),
            1,
        )
        .unwrap();
    assert_eq!(plan.implementers, [first.clone()]);
    assert_eq!(plan.waiting, [later]);
    assert_eq!(
        workflow.next(&attempt, TARGET).unwrap()["kind"],
        "implementation_required"
    );
    for receipt in [
        gap_receipt(99, "unsupported event", "unknown attempt"),
        gap_receipt(1, "independent Target repair", "unassigned work"),
        gap_receipt(1, "unsupported event", " "),
    ] {
        assert!(
            workflow
                .report(Path::new("."), TARGET, &attempt, receipt)
                .is_err()
        );
    }

    let evidence = "Replay rejected a supported frame at Source sequence 9.";
    for _ in 0..2 {
        workflow
            .report(
                Path::new("."),
                TARGET,
                &attempt,
                gap_receipt(1, "unsupported event", evidence),
            )
            .unwrap();
    }
    let action = workflow.next(&attempt, TARGET).unwrap();
    assert_eq!(action["kind"], "setup_required");
    assert_eq!(action["details"]["attempt_id"], attempt.attempt_id);
    assert_eq!(action["details"]["root_cause"], "unsupported event");
    assert_eq!(action["details"]["scope"], "startup");
    assert_eq!(action["details"]["evidence"], evidence);
    assert_eq!(action["commands"]["run"], json!(["run"]));
    workflow.require_replay_candidate(&attempt, TARGET).unwrap();

    let latest = failed_attempt(2);
    workflow
        .set_plan(&latest, 9, groups(Some(first), vec![]), 2)
        .unwrap();
    let action = workflow.next(&latest, TARGET).unwrap();
    assert_eq!(action["kind"], "implementation_required");
    assert_eq!(
        action["details"]["assignments"][0]["attempt_id"],
        latest.attempt_id
    );
}

#[test]
fn initial_filing_requires_explicit_first_unmatched_and_allows_follow_up_groups() {
    let mut workflow = Workflow::default();
    let attempt = failed_attempt(1);
    let first = finding("first", 9);
    let mut unrelated = finding("unrelated", 9);
    for initial in [Some(finding("wrong sequence", 8)), None] {
        let error = workflow
            .set_plan(&attempt, 9, groups(initial, vec![unrelated.clone()]), 3)
            .unwrap_err();
        assert!(error.to_string().contains("first failed sequence 9"));
    }
    assert!(workflow.next(&attempt, TARGET).is_none());
    workflow
        .set_plan(&attempt, 9, groups(Some(first.clone()), vec![]), 3)
        .unwrap();
    unrelated.scope = Some("POST /routes".to_owned());
    let mut third = finding("third", 10);
    third.scope.clone_from(&unrelated.scope);
    let plan = workflow
        .set_plan(
            &attempt,
            9,
            groups(None, vec![unrelated.clone(), third.clone()]),
            3,
        )
        .unwrap();
    assert_eq!(plan.implementers, [first, unrelated, third]);
    let action = workflow.next(&attempt, TARGET).unwrap();
    assert_eq!(action["details"]["first_unmatched"], "first");
    assert!(action["details"].get("blocker").is_none());
}

#[test]
fn candidate_covers_only_the_first_unmatched_fix() {
    const OTHER: &str = "cccccccccccccccccccccccccccccccccccccccc";

    let mut workflow = Workflow::default();
    let attempt = failed_attempt(1);
    let first = finding("first", 9);
    let other = finding("other", 9);
    workflow
        .set_plan(&attempt, 9, groups(Some(first), vec![other]), 2)
        .unwrap();
    let repair = workflow.repair.as_mut().unwrap();
    repair.fixes = Some(vec![Fix {
        root_cause: "other".to_owned(),
        commit: OTHER.to_owned(),
        checks: vec!["other check".to_owned()],
    }]);
    let action = workflow.next(&attempt, TARGET).unwrap();
    assert_eq!(action["kind"], "implementation_required");
    assert!(workflow.require_replay_candidate(&attempt, TARGET).is_err());

    let repair = workflow.repair.as_mut().unwrap();
    repair.fixes.as_mut().unwrap().push(Fix {
        root_cause: "first".to_owned(),
        commit: FIXED.to_owned(),
        checks: vec!["first check".to_owned()],
    });
    let action = workflow.next(&attempt, TARGET).unwrap();
    assert_eq!(action["kind"], "integration_required");
    let details = action["details"]["fixes"].as_array().unwrap();
    assert_eq!(details.len(), 1);
    assert_eq!(details[0]["commit"], FIXED);
    assert!(details[0].get("checks").is_none());

    let error = workflow
        .report(
            Path::new("."),
            FIXED,
            &attempt,
            Receipt::Candidate {
                attempt_id: Uuid::from_u128(1),
                commit: FIXED.to_owned(),
                included_fixes: BTreeSet::from([FIXED.to_owned(), OTHER.to_owned()]),
                checks: vec!["fixture integration check".to_owned()],
            },
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("exactly the accepted first unmatched fix")
    );

    workflow.repair.as_mut().unwrap().candidate = Some(Candidate {
        commit: FIXED.to_owned(),
        included_fixes: BTreeSet::from([FIXED.to_owned()]),
        checks: vec!["fixture integration check".to_owned()],
    });
    assert_eq!(
        workflow.next(&attempt, FIXED).unwrap()["kind"],
        "advance_required"
    );
    assert!(workflow.require_replay_candidate(&attempt, TARGET).is_err());
    workflow.require_replay_candidate(&attempt, FIXED).unwrap();
}

#[test]
fn late_engine_gap_follows_its_original_assignment_once() {
    let mut workflow = Workflow::default();
    let first = failed_attempt(1);
    let later = finding("later", 10);
    workflow
        .set_plan(
            &first,
            9,
            groups(Some(finding("first", 9)), vec![later.clone()]),
            2,
        )
        .unwrap();
    let repair = workflow.repair.as_mut().unwrap();
    repair.fixes = Some(vec![Fix {
        root_cause: "first".to_owned(),
        commit: FIXED.to_owned(),
        checks: vec!["first check".to_owned()],
    }]);
    repair.candidate = Some(Candidate {
        commit: FIXED.to_owned(),
        included_fixes: BTreeSet::from([FIXED.to_owned()]),
        checks: vec!["first integration".to_owned()],
    });

    let mut second = failed_attempt(2);
    second.target_commit = Some(FIXED.to_owned());
    workflow
        .report(
            Path::new("."),
            FIXED,
            &second,
            gap_receipt(
                1,
                "later",
                "Replay rejected the recorded event at sequence 10.",
            ),
        )
        .unwrap();
    workflow
        .set_plan(&second, 10, groups(Some(later.clone()), vec![]), 2)
        .unwrap();
    let action = workflow.next(&second, FIXED).unwrap();
    assert_eq!(action["kind"], "setup_required");
    assert_eq!(action["details"]["attempt_id"], first.attempt_id);
    workflow.require_replay_candidate(&second, FIXED).unwrap();

    let mut third = failed_attempt(3);
    third.target_commit = second.target_commit;
    workflow
        .set_plan(&third, 10, groups(Some(later), vec![]), 2)
        .unwrap();
    let action = workflow.next(&third, FIXED).unwrap();
    assert_eq!(action["kind"], "implementation_required");
    assert_eq!(
        action["details"]["assignments"][0]["attempt_id"],
        third.attempt_id
    );
}
