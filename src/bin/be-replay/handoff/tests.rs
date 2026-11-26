use super::*;

const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn failed_attempt(id: u128, base: &str) -> E2eEventSessionResult {
    E2eEventSessionResult {
        run_key: "fixture".to_owned(),
        attempt_id: Uuid::from_u128(id).simple().to_string(),
        recording_root: "fixture".into(),
        target_commit: Some(base.to_owned()),
        target_inputs: None,
        engine_revision: None,
        target_image_id: None,
        passed: false,
        events: Default::default(),
        phase: traffic_e2e::E2eEventSessionPhase::Replaying,
        apis: Default::default(),
        cases: Default::default(),
        error: None,
        progress: "fixture-progress".into(),
        report: "fixture-report".into(),
    }
}

fn workflow_at_failure(attempt: &E2eEventSessionResult, seq: u64) -> Workflow {
    Workflow {
        window: Some(Window {
            from_seq: seq,
            through_seq: seq + 60,
        }),
        failure: Some(Failure {
            attempt_id: attempt_uuid(attempt).unwrap(),
            seq,
        }),
        ..Workflow::default()
    }
}

fn item(scope: &str, sequences: &[u64]) -> WorkItem {
    WorkItem {
        scope: scope.to_owned(),
        sequences: sequences.iter().copied().collect(),
        apis: Vec::new(),
    }
}

fn owner(seq: u64, scope: &str, group: &str) -> Ownership {
    Ownership {
        seq,
        scope: scope.to_owned(),
        group: group.to_owned(),
    }
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "user.name=Replay",
            "-c",
            "user.email=replay@example.test",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn commit(root: &Path, name: &str) -> String {
    git(root, &["commit", "--allow-empty", "-qm", name]);
    git(root, &["rev-parse", "HEAD"])
}

fn assignment_id(workflow: &Workflow, group: &str) -> Uuid {
    workflow
        .groups
        .assignments(AssignmentDetail::Full)
        .as_array()
        .unwrap()
        .iter()
        .find(|assignment| assignment["group"] == group)
        .unwrap()["assignment_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn fix(group: &str, assignment_id: Uuid, commit: &str, sequences: &[u64]) -> Receipt {
    Receipt::Fixes {
        fixes: vec![Fix {
            group: group.to_owned(),
            assignment_id,
            commit: commit.to_owned(),
            sequences: sequences.iter().copied().collect(),
            checks: vec!["fixture implementation checks".to_owned()],
        }],
    }
}

fn candidate(attempt: &E2eEventSessionResult, head: &str, delivered: &[&str]) -> Receipt {
    Receipt::Candidate {
        attempt_id: attempt_uuid(attempt).unwrap(),
        commit: head.to_owned(),
        included_fixes: delivered
            .iter()
            .map(|commit| (*commit).to_owned())
            .collect(),
        checks: vec!["fixture integration checks".to_owned()],
    }
}

#[test]
fn ownership_reuses_the_existing_group_and_only_accepts_the_current_sequence() {
    let attempt = failed_attempt(1, BASE);
    let mut workflow = workflow_at_failure(&attempt, 9);
    workflow
        .groups
        .enqueue("pipelines", item("api:POST /pipelines", &[11, 13]), BASE);
    workflow.reserve_worktrees(|| Ok(2)).unwrap();

    let action = workflow.with_assignments(workflow.failed_action(9), AssignmentDetail::Full);
    let lease = assignment_id(&workflow, "pipelines");
    assert_eq!(action["kind"], "ownership_required");
    assert_eq!(action["details"]["seq"], 9);
    assert_eq!(
        action["details"]["assignments"][0]["name"],
        "api-implementer-2"
    );

    assert!(
        workflow
            .set_owner(owner(10, "job:refresh", "pipelines"), BASE)
            .is_err()
    );
    assert!(
        workflow
            .set_owner(owner(9, "refresh", "pipelines"), BASE)
            .is_err()
    );
    workflow
        .set_owner(owner(9, "job:refresh", "pipelines"), BASE)
        .unwrap();
    workflow
        .reserve_worktrees(|| panic!("reuse the assigned worktree"))
        .unwrap();
    let action = workflow.with_assignments(workflow.failed_action(9), AssignmentDetail::Full);
    assert_eq!(action["kind"], "implementation_required");
    let assignments = action["details"]["assignments"].as_array().unwrap();
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0]["name"], "api-implementer-2");
    assert_eq!(assignments[0]["assignment_id"], lease.simple().to_string());
    let items = assignments[0]["items"].as_array().unwrap();
    assert_eq!(items[0]["sequences"], json!([11, 13]));
    assert_eq!(items[1]["scope"], "job:refresh");
    assert_eq!(items[1]["sequences"], json!([9]));
    assert!(
        workflow
            .set_owner(owner(9, "job:another", "pipelines"), BASE)
            .is_err()
    );
}

#[test]
fn candidate_requires_the_owning_groups_new_delivery_for_the_failed_sequence() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q"]);
    let base = commit(root, "base");
    let attempt = failed_attempt(1, &base);
    let mut workflow = workflow_at_failure(&attempt, 9);
    workflow
        .groups
        .enqueue("pipelines", item("api:POST /pipelines", &[11, 13]), &base);
    workflow
        .set_owner(owner(9, "job:refresh", "refresh"), &base)
        .unwrap();
    let mut slots = 0..;
    workflow
        .reserve_worktrees(|| Ok(slots.next().unwrap()))
        .unwrap();
    let pipelines_id = assignment_id(&workflow, "pipelines");
    let refresh_id = assignment_id(&workflow, "refresh");

    let pipelines = commit(root, "another group");
    let mut another_round = workflow_at_failure(&attempt, 9);
    another_round
        .groups
        .enqueue("pipelines", item("api:POST /pipelines", &[11, 13]), &base);
    another_round.reserve_worktrees(|| Ok(0)).unwrap();
    assert!(
        another_round
            .report(
                root,
                &pipelines,
                Some(&attempt),
                Some(9),
                fix("pipelines", pipelines_id, &pipelines, &[9, 11]),
            )
            .is_err()
    );
    workflow
        .report(
            root,
            &pipelines,
            Some(&attempt),
            Some(9),
            fix("pipelines", pipelines_id, &pipelines, &[9, 11]),
        )
        .unwrap();
    let partial = commit(root, "another sequence");
    workflow
        .report(
            root,
            &partial,
            Some(&attempt),
            Some(9),
            fix("refresh", refresh_id, &partial, &[8]),
        )
        .unwrap();
    assert_eq!(workflow.failed_action(9)["kind"], "implementation_required");
    let error = workflow
        .report(
            root,
            &partial,
            Some(&attempt),
            Some(9),
            candidate(&attempt, &partial, &[&pipelines, &partial]),
        )
        .unwrap_err();
    assert!(error.to_string().contains("current failure"));

    let repair = commit(root, "current failed event");
    workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            fix("refresh", refresh_id, &repair, &[9]),
        )
        .unwrap();
    let action = workflow.with_assignments(workflow.failed_action(9), AssignmentDetail::Full);
    assert_eq!(action["kind"], "integration_required");
    assert_eq!(action["details"]["fixes"].as_array().unwrap().len(), 3);
    assert_eq!(
        action["details"]["assignments"][0]["items"][0]["sequences"],
        json!([13])
    );

    let stale = failed_attempt(2, &base);
    let receipt = candidate(&stale, &repair, &[&repair, &pipelines]);
    assert!(
        workflow
            .report(root, &repair, Some(&attempt), Some(9), receipt)
            .is_err()
    );
    workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            candidate(&attempt, &repair, &[&repair, &pipelines]),
        )
        .unwrap();
    assert_eq!(workflow.candidate_commit(&attempt), Some(repair.as_str()));

    let retry = failed_attempt(3, &repair);
    workflow
        .observe_failure(root, root, &repair, &retry, 9)
        .unwrap();
    assert!(!workflow.has_candidate(&retry));
    assert!(workflow.groups.pending("refresh", 9));
    assert_eq!(workflow.failed_action(9)["kind"], "implementation_required");
}

#[test]
fn the_current_failure_needs_a_repair_or_demonstrated_engine_gap() {
    let attempt = failed_attempt(1, BASE);
    let root = Path::new(".");
    let mut workflow = workflow_at_failure(&attempt, 9);
    workflow
        .set_owner(owner(9, "startup", "startup"), BASE)
        .unwrap();
    workflow.reserve_worktrees(|| Ok(1)).unwrap();
    let lease = assignment_id(&workflow, "startup");
    assert!(
        workflow
            .report(
                root,
                BASE,
                Some(&attempt),
                Some(9),
                Receipt::Review {
                    group: "startup".into(),
                    assignment_id: lease,
                    sequences: [9].into(),
                    checks: vec!["checked".into()]
                }
            )
            .is_err()
    );
    let gap = |evidence: &str| Receipt::EngineGap {
        group: "startup".into(),
        assignment_id: lease,
        sequences: [9].into(),
        evidence: evidence.to_owned(),
    };
    assert!(
        workflow
            .report(root, BASE, Some(&attempt), Some(9), gap(" "))
            .is_err()
    );
    workflow
        .report(
            root,
            BASE,
            Some(&attempt),
            Some(9),
            gap("Observed rejected frame."),
        )
        .unwrap();
    assert_eq!(workflow.failed_action(9)["kind"], "setup_required");

    let retry = failed_attempt(2, BASE);
    workflow
        .observe_failure(root, root, BASE, &retry, 9)
        .unwrap();
    let action = workflow.with_assignments(workflow.failed_action(9), AssignmentDetail::Full);
    assert_eq!(action["kind"], "implementation_required");
    assert_eq!(
        action["details"]["assignments"][0]["name"],
        "api-implementer-1"
    );
}
