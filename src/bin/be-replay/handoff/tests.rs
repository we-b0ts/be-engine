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
    let mut workflow = Workflow::default();
    observe_fixture_window(&mut workflow, attempt, seq);
    workflow
}

fn observe_fixture_window(workflow: &mut Workflow, attempt: &E2eEventSessionResult, seq: u64) {
    workflow
        .observe_window(
            attempt.target_commit.as_deref().unwrap(),
            attempt_uuid(attempt).unwrap(),
            seq,
            traffic_e2e::session::DispatchWindow {
                from_seq: seq,
                through_seq: seq + 60,
                apis: Vec::new(),
                matches: BTreeMap::new(),
                failure_owner: None,
            },
        )
        .unwrap();
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
        .assignments()
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

fn start_worker(workflow: &mut Workflow, group: &str, assignment_id: Uuid) {
    let workers = serde_json::from_value(json!([{
        "group": group,
        "assignment_id": assignment_id,
        "agent_handle": format!("worker-{group}"),
        "state": "started",
    }]))
    .unwrap();
    workflow.groups.update_implementers(workers).unwrap();
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
    let task = Task::integration(
        &attempt.run_key,
        &attempt.attempt_id,
        delivered.len(),
        Some(9),
    );
    Receipt::Candidate {
        task_id: task.id().to_owned(),
        agent_handle: "integrator".into(),
        attempt_id: attempt_uuid(attempt).unwrap(),
        commit: head.to_owned(),
        included_fixes: delivered
            .iter()
            .map(|commit| (*commit).to_owned())
            .collect(),
        included_rule_plans: BTreeSet::new(),
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

    let lease = assignment_id(&workflow, "pipelines");
    assert!(workflow.failure_owner(9).is_none());

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
    let action = workflow.with_assignments(
        workflow.repair_action(workflow.failure_owner(9).unwrap()),
        AssignmentDetail::Full,
        false,
    );
    assert_eq!(action["kind"], "dispatch_required");
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
    start_worker(&mut workflow, "pipelines", pipelines_id);
    start_worker(&mut workflow, "refresh", refresh_id);

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
                None,
                fix("pipelines", pipelines_id, &pipelines, &[9, 11]),
            )
            .is_err()
    );
    assert!(
        workflow
            .report(
                root,
                &pipelines,
                Some(&attempt),
                Some(9),
                None,
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
            None,
            fix("pipelines", pipelines_id, &pipelines, &[11]),
        )
        .unwrap();
    workflow
        .groups
        .enqueue("refresh", item("job:refresh", &[15]), &base);
    let partial = commit(root, "another sequence");
    workflow
        .report(
            root,
            &partial,
            Some(&attempt),
            Some(9),
            None,
            fix("refresh", refresh_id, &partial, &[15]),
        )
        .unwrap();
    assert!(
        workflow
            .ready_integration(workflow.failure_owner(9))
            .is_none()
    );

    let repair = commit(root, "current failed event");
    workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            None,
            fix("refresh", refresh_id, &repair, &[9]),
        )
        .unwrap();
    let ready = workflow
        .ready_integration(workflow.failure_owner(9))
        .unwrap();
    let task = Task::integration(&attempt.run_key, &attempt.attempt_id, ready, Some(9));
    let action =
        workflow.with_assignments(workflow.task_action(&task), AssignmentDetail::Full, false);
    assert_eq!(action["kind"], "dispatch_task");
    assert_eq!(action["details"]["fixes"].as_array().unwrap().len(), 3);
    assert_eq!(
        action["details"]["assignments"][0]["items"][0]["sequences"],
        json!([13])
    );
    workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            Some(&task),
            Receipt::TaskDispatch {
                task_id: task.id().into(),
                agent_handle: "integrator".into(),
                state: DispatchState::Started,
            },
        )
        .unwrap();
    let error = workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            None,
            candidate(&attempt, &repair, &[&pipelines, &partial]),
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("candidate must include window fix")
    );

    let stale = failed_attempt(2, &base);
    let receipt = candidate(&stale, &repair, &[&repair, &pipelines]);
    assert!(
        workflow
            .report(root, &repair, Some(&attempt), Some(9), None, receipt)
            .is_err()
    );
    workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            None,
            candidate(&attempt, &repair, &[&repair, &pipelines]),
        )
        .unwrap();
    assert_eq!(workflow.candidate_commit(&attempt), Some(repair.as_str()));

    let retry = failed_attempt(3, &repair);
    observe_fixture_window(&mut workflow, &retry, 9);
    workflow.reserve_worktrees(|| Ok(0)).unwrap();
    assert!(!workflow.has_candidate(&retry));
    assert!(workflow.groups.pending("refresh", 9));
    assert_eq!(
        workflow.repair_action(workflow.failure_owner(9).unwrap())["kind"],
        "implementation_required"
    );
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
    start_worker(&mut workflow, "startup", lease);
    assert!(
        workflow
            .report(
                root,
                BASE,
                Some(&attempt),
                Some(9),
                None,
                Receipt::Review {
                    group: "startup".into(),
                    assignment_id: lease,
                    sequences: [9].into(),
                    checks: vec!["checked".into()],
                    confirms_apis: false,
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
            .report(root, BASE, Some(&attempt), Some(9), None, gap(" "))
            .is_err()
    );
    workflow
        .report(
            root,
            BASE,
            Some(&attempt),
            Some(9),
            None,
            gap("Observed rejected frame."),
        )
        .unwrap();
    assert_eq!(
        workflow.repair_action(workflow.failure_owner(9).unwrap())["kind"],
        "setup_required"
    );

    let retry = failed_attempt(2, BASE);
    observe_fixture_window(&mut workflow, &retry, 9);
    let action = workflow.with_assignments(
        workflow.repair_action(workflow.failure_owner(9).unwrap()),
        AssignmentDetail::Full,
        false,
    );
    assert_eq!(action["kind"], "worker_status_required");
    assert_eq!(
        action["details"]["assignments"][0]["name"],
        "api-implementer-1"
    );
}

#[test]
fn a_new_attempt_reopens_checked_work_in_the_overlapping_window() {
    use traffic_e2e::session::{DispatchWindow, WindowMatch, WindowMatchKind, WindowOwner};

    let candidate = |sequence| WindowMatch {
        kind: WindowMatchKind::PrimaryRequest,
        exchange_sequence: sequence,
        owner: Some(WindowOwner {
            scope: "api:/accounts".into(),
            group: Some("accounts".into()),
        }),
    };
    let dispatch = |from| DispatchWindow {
        from_seq: from,
        through_seq: 20,
        apis: Vec::new(),
        matches: [(12, candidate(12)), (17, candidate(17))].into(),
        failure_owner: None,
    };
    let mut workflow = Workflow::default();
    workflow
        .observe_window(BASE, Uuid::from_u128(1), 5, dispatch(5))
        .unwrap();
    workflow.reserve_worktrees(|| Ok(0)).unwrap();
    let assignment = assignment_id(&workflow, "accounts");
    start_worker(&mut workflow, "accounts", assignment);
    workflow
        .confirm(
            serde_json::from_value(json!({
                "group":"accounts", "assignment_id":assignment,
                "sequences":[12], "format":"matches", "rule":"not_needed",
            }))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        workflow.assignment_sequences(assignment, None).unwrap(),
        [17].into()
    );

    workflow
        .observe_window(BASE, Uuid::from_u128(2), 7, dispatch(7))
        .unwrap();
    assert_eq!(
        workflow
            .assignment_sequences(assignment, Some("api:/accounts"))
            .unwrap(),
        [12, 17].into()
    );
}

#[test]
fn migrating_a_legacy_window_reuses_its_candidate_repair_and_awaits_new_confirmations() {
    use traffic_e2e::session::{DispatchWindow, WindowMatch, WindowMatchKind};

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q"]);
    let base = commit(root, "base");
    let attempt = failed_attempt(1, &base);
    let mut workflow = workflow_at_failure(&attempt, 9);
    workflow
        .set_owner(owner(9, "job:refresh", "refresh"), &base)
        .unwrap();
    workflow.reserve_worktrees(|| Ok(0)).unwrap();
    let lease = assignment_id(&workflow, "refresh");
    start_worker(&mut workflow, "refresh", lease);
    let repair = commit(root, "repair failed admission");
    workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            None,
            fix("refresh", lease, &repair, &[9]),
        )
        .unwrap();
    let task = Task::integration(&attempt.run_key, &attempt.attempt_id, 1, Some(9));
    workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            Some(&task),
            Receipt::TaskDispatch {
                task_id: task.id().into(),
                agent_handle: "integrator".into(),
                state: DispatchState::Started,
            },
        )
        .unwrap();
    workflow
        .report(
            root,
            &repair,
            Some(&attempt),
            Some(9),
            None,
            candidate(&attempt, &repair, &[&repair]),
        )
        .unwrap();
    assert_eq!(workflow.candidate_commit(&attempt), Some(repair.as_str()));

    let mut legacy = serde_json::to_value(workflow).unwrap();
    legacy["window"].as_object_mut().unwrap().remove("coverage");
    let mut restored: Workflow = serde_json::from_value(legacy).unwrap();
    assert!(!restored.failure_observed(&attempt, 9));
    assert!(!restored.has_candidate(&attempt));

    restored
        .observe_window(
            &repair,
            attempt_uuid(&attempt).unwrap(),
            9,
            DispatchWindow {
                from_seq: 9,
                through_seq: 20,
                apis: Vec::new(),
                matches: [(
                    12,
                    WindowMatch {
                        kind: WindowMatchKind::DependencyOutput,
                        exchange_sequence: 9,
                        owner: None,
                    },
                )]
                .into(),
                failure_owner: None,
            },
        )
        .unwrap();
    assert!(restored.failure_observed(&attempt, 9));
    assert!(restored.failure_was_applied(9));
    assert_eq!(restored.pending_confirmation(), Some([12].into()));
    assert!(!restored.has_candidate(&attempt));

    restored.reserve_worktrees(|| Ok(0)).unwrap();
    let lease = assignment_id(&restored, "refresh");
    assert_eq!(
        restored.assignment_sequences(lease, None).unwrap(),
        [12].into()
    );
    start_worker(&mut restored, "refresh", lease);
    let confirmation = serde_json::from_value(json!({
        "kind":"confirmed", "group":"refresh", "assignment_id":lease,
        "sequences":[12], "format":"matches", "rule":"not_needed"
    }))
    .unwrap();
    restored
        .report(root, &repair, Some(&attempt), Some(9), None, confirmation)
        .unwrap();
    assert!(restored.window_ready());
    assert_eq!(restored.candidate_commit(&attempt), Some(repair.as_str()));
}
