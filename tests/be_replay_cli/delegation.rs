use super::*;

pub(super) fn assert_dispatch(state: &Value, requirement: &str, role: &str) {
    let action = &state["action"];
    assert_eq!(action["kind"], "dispatch_task");
    assert!(action.get("command").is_none());
    let task = &action["details"]["task"];
    assert_eq!(task["requirement"], requirement);
    assert_eq!(task["role"], role);
    assert!(task["task_id"].is_string());
    assert!(task.get("agent_handle").is_none());
    assert_coordinator_task(task);
}

pub(super) fn register_task(root: &Path, dispatch: &Value, handle: &str) -> Value {
    let reported = successful(report(root, dispatch_receipt(dispatch, handle, "started")));
    let action = &reported["action"];
    assert_eq!(action["kind"], "await_delivery");
    assert!(action.get("command").is_none());
    let task = &action["details"]["task"];
    assert_coordinator_task(task);
    let mut dispatched_task = dispatch["action"]["details"]["task"].clone();
    dispatched_task["agent_handle"] = json!(handle);
    assert_eq!(*task, dispatched_task);
    reported
}

fn assert_coordinator_task(task: &Value) {
    for field in [
        "input_query",
        "role_reference",
        "register_command",
        "submit_command",
    ] {
        assert!(task.get(field).is_none(), "unexpected task field {field}");
    }
}

pub(super) fn bind_delivery(mut delivery: Value, state: &Value) -> Value {
    let task = &state["action"]["details"]["task"];
    assert!(task["task_id"].is_string());
    delivery["task_id"] = task["task_id"].clone();
    delivery["agent_handle"] = task["agent_handle"].clone();
    delivery
}

fn dispatch_receipt(state: &Value, handle: &str, update: &str) -> Value {
    json!({"kind":"task_dispatch", "task_id":state["action"]["details"]["task"]["task_id"],
        "agent_handle":handle, "state":update})
}

fn candidate(attempt: &Value, head: &str, included: &[&str]) -> Value {
    json!({"kind":"candidate","attempt_id":attempt["attempt_id"],"commit":head,
        "included_fixes":included})
}

#[tokio::test]
async fn a_session_rule_plan_repairs_a_failure_through_the_integration_candidate() {
    let target = tempfile::tempdir().unwrap();
    let integration = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    fs::write(root.join(".traffic-e2e/apis.yaml"), "fixture: [/items/*]\n").unwrap();
    commit_catalog(root);
    seal_events_with_apis(&recording_dir(root), &[(800, "GET", "/items/1")]).await;
    let attempt = run_attempt_with_invalid_source(
        root,
        &["run", "--user-confirm", "--recording-run-id", RECORDING_ID],
    );
    publish_mismatch(attempt.clone(), 8);
    register_implementers(root);
    let assigned = assignments(root);
    let worker = group(&assigned, "fixture");

    let delivery = tempfile::tempdir().unwrap();
    let proposal = delivery.path().join("proposal.json");
    let sequences = delivery.path().join("claimed.txt");
    fs::write(
        delivery.path().join("policy.yaml"),
        "format: traffic-policy/v3\njson:\n  fields:\n    /fixture_at: {kind: time, formats: [unix_seconds]}\n",
    ).unwrap();
    fs::write(&proposal, serde_json::to_vec(&json!({
        "group":"fixture", "assignment_id":worker["assignment_id"],
        "sequences_file":"claimed.txt", "proposal_file":"policy.yaml",
        "source_evidence":{"source":"src/fixture.rs:7", "fact":"The handler emits the current time in Unix seconds."},
        "checks":["Verified the handler uses the current clock"]
    })).unwrap()).unwrap();
    let register = ["rule", "plan", "--file", proposal.to_str().unwrap()];
    fs::write(&sequences, "9\n").unwrap();
    assert!(!command(root, &register).status.success());
    fs::write(&sequences, "8\n").unwrap();
    let plan_output = successful(command(root, &register));
    assert_eq!(successful(command(root, &register)), plan_output);
    let plan_id = plan_output["rule_plan"]["id"].as_str().unwrap();

    let pending = assignments(root);
    assert_dispatch(&pending, "integration_required", "code-integrator");
    assert_eq!(pending["action"]["details"]["rule_plans"][0]["id"], plan_id);
    let registered = register_task(root, &pending, "fixture-integrator");
    let task = registered["action"]["details"]["task"]["task_id"]
        .as_str()
        .unwrap();
    let apply = |worktree: &Path| {
        command(
            root,
            &[
                "rule",
                "apply",
                "--worktree",
                worktree.to_str().unwrap(),
                "--task-id",
                task,
                "--agent-handle",
                "fixture-integrator",
                "--plan-id",
                plan_id,
            ],
        )
    };
    let policy_path = ".traffic-e2e/policy.yaml";
    let original = fs::read(root.join(policy_path)).unwrap();
    assert!(!apply(root).status.success());
    let worktree = integration.path().join("candidate");
    git(
        root,
        &[
            "worktree",
            "add",
            "--detach",
            worktree.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert_eq!(successful(apply(&worktree))["changed"], true);
    assert_eq!(successful(apply(&worktree))["changed"], false);
    assert_eq!(fs::read(root.join(policy_path)).unwrap(), original);

    git(&worktree, &["add", policy_path]);
    git(&worktree, &["commit", "-qm", "apply reviewed rule"]);
    let commit = git(&worktree, &["rev-parse", "HEAD"]);
    git(root, &["merge", "--ff-only", &commit]);
    let delivery = bind_delivery(
        json!({
            "kind":"candidate", "attempt_id":attempt["attempt_id"], "commit":commit,
            "included_fixes":[], "included_rule_plans":[plan_id]
        }),
        &registered,
    );
    assert_eq!(
        successful(report(root, delivery))["action"]["kind"],
        "advance_required"
    );
}

#[tokio::test]
async fn new_api_grouping_gates_first_replay_but_implementation_runs_in_parallel() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let catalog = root.join(".traffic-e2e/apis.yaml");
    fs::write(&catalog, "users: [/users/*]\n").unwrap();
    git(root, &["add", ".traffic-e2e/apis.yaml"]);
    git(root, &["commit", "-qm", "existing catalog"]);
    let recording = recording_dir(root);
    seal_events_with_apis(
        &recording,
        &[
            (800, "GET", "/users/1"),
            (900, "GET", "/users/2"),
            (1000, "POST", "/new"),
        ],
    )
    .await;

    let inventory = successful(command(root, &["apis", "--recording-run-id", RECORDING_ID]));
    assert_eq!(inventory["apis"][0]["requests"], 2);
    assert_eq!(inventory["apis"][0]["group"], "users");
    assert!(inventory["apis"][1].get("case_pattern").is_none());

    let preflight = confirm_recording(root);
    assert_dispatch(&preflight, "api_grouping_required", "issue-analyst");
    let task = &preflight["action"]["details"]["task"];
    assert_eq!(
        *task,
        json!({"task_id":task["task_id"],"requirement":"api_grouping_required",
            "role":"issue-analyst","ungrouped_apis":1})
    );
    assert!(preflight["action"].get("query").is_none());
    assert!(preflight["session"].is_null());
    assert_eq!(
        successful(command(root, &["status"]))["action"],
        preflight["action"]
    );
    let missing = successful(command(root, &["apis", "--ungrouped"]));
    assert_eq!(missing["apis"].as_array().unwrap().len(), 1);
    assert_eq!(missing["apis"][0]["api"], "POST /new");
    let blocked = successful(command(root, &["run"]));
    assert_eq!(blocked["action"], preflight["action"]);
    assert!(blocked["session"].is_null());
    let new = json!({"api":"POST /new","case_pattern":"/new","group":"new-api"});
    let mut early = bind_delivery(json!({"apis":[new]}), &preflight);
    early["agent_handle"] = json!("fixture-analyst");
    assert!(!plan(root, early.clone()).status.success());
    let mut stale = dispatch_receipt(&preflight, "fixture-analyst", "started");
    stale["task_id"] = json!("stale-task-id");
    assert!(!report(root, stale).status.success());
    let first = register_task(root, &preflight, "fixture-analyst");
    assert_eq!(
        successful(command(root, &["status"]))["action"],
        first["action"]
    );
    assert_eq!(bind_delivery(json!({"apis":[new]}), &first), early);
    let repeated = register_task(root, &preflight, "fixture-analyst");
    assert_eq!(repeated["action"], first["action"]);
    assert!(
        !report(
            root,
            dispatch_receipt(&first, "different-analyst", "started")
        )
        .status
        .success()
    );
    let blocked = successful(command(root, &["run"]));
    assert_eq!(blocked["action"], first["action"]);
    assert!(blocked["session"].is_null());
    let redispatch = successful(report(
        root,
        dispatch_receipt(&first, "fixture-analyst", "exited"),
    ));
    assert_eq!(redispatch["action"], preflight["action"]);
    let awaiting = register_task(root, &redispatch, "replacement-analyst");
    assert!(!plan(root, early).status.success());
    assert!(
        !report(root, dispatch_receipt(&first, "fixture-analyst", "exited"))
            .status
            .success()
    );

    let known = json!({"api":"GET /users/*","case_pattern":"/users/*","group":"users"});
    assert!(
        !plan(root, bind_delivery(json!({"apis":[known]}), &awaiting))
            .status
            .success()
    );
    assert!(
        !plan(root, bind_delivery(json!({"apis":[known,new]}), &awaiting))
            .status
            .success()
    );
    assert_eq!(fs::read_to_string(&catalog).unwrap(), "users: [/users/*]\n");
    fs::create_dir_all(root.join(".traffic-e2e/local/rewrite-worktrees/api-implementer-0"))
        .unwrap();
    let reviewed = successful(plan(root, bind_delivery(json!({"apis":[new]}), &awaiting)));
    assert_eq!(reviewed["action"]["kind"], "configuration_commit_required");
    assert_eq!(
        reviewed["action"]["details"]["files"],
        json!([".traffic-e2e/apis.yaml"])
    );
    assert!(reviewed["action"]["details"]["assignments"].is_null());
    assert!(!command(root, &["run"]).status.success());
    assert_eq!(
        successful(command(root, &["status"]))["action"],
        reviewed["action"]
    );
    commit_catalog(root);
    let assigned = assignments(root);
    let worker = group(&assigned, "new-api");
    assert_eq!(worker["name"], "api-implementer-1");
    assert_eq!(worker["base_commit"], git(root, &["rev-parse", "HEAD"]));
    assert_eq!(worker["items"][0]["scope"], "api:POST /new");
    assert_eq!(worker["items"][0]["apis"][0]["case_pattern"], "/new");
    assert_eq!(
        register_implementers(root)["action"]["kind"],
        "advance_required"
    );

    let attempt = run_attempt_with_invalid_source(root, &["run"]);
    publish_mismatch(attempt.clone(), 10);
    let failed = successful(command(root, &["status", "--with-assignments"]));
    assert_eq!(failed["action"]["kind"], "implementation_required");
    assert_eq!(group(&failed, "new-api")["worktree"], worker["worktree"]);

    let branch = git(root, &["branch", "--show-current"]);
    let fix = fixture_fix(root, "worker-api", "new.rs", &branch);
    let integration = successful(report(root, delivery(worker, &fix, 10)));
    assert_dispatch(&integration, "integration_required", "code-integrator");
    let candidate = candidate(&attempt, &fix, &[&fix]);
    let mut unregistered = bind_delivery(candidate.clone(), &integration);
    unregistered["agent_handle"] = json!("fixture-integrator");
    git(root, &["merge", "--ff-only", &fix]);
    assert!(!report(root, unregistered.clone()).status.success());
    let registered = register_task(root, &integration, "fixture-integrator");
    let ready = successful(command(root, &["status"]));
    assert_eq!(ready["action"], registered["action"]);
    assert!(!command(root, &["run"]).status.success());
    let bound = bind_delivery(candidate, &ready);
    assert_eq!(bound, unregistered);
    let mut invalid = bound.clone();
    invalid["checks"] = json!([" "]);
    assert!(!report(root, invalid).status.success());
    assert_eq!(
        successful(report(root, bound.clone()))["action"]["kind"],
        "advance_required"
    );
    let mut retried = bound;
    retried["checks"] = json!([]);
    assert_eq!(
        successful(report(root, retried))["action"]["kind"],
        "advance_required"
    );

    let verified = run_as_passed(run_attempt_with_invalid_source(root, &["run"]), 2);
    let status = successful(command(root, &["status"]));
    assert_eq!(status["state"], "passed");
    assert_status_attempt(&status, &json!({"session":verified}));
    assert_eq!(status["action"]["kind"], "complete");
    seal_events_with_apis(
        &recording.with_file_name(OTHER_RECORDING_ID),
        &[(800, "POST", "/new")],
    )
    .await;
    let switched = successful(command(root, &["switch-recording-id", OTHER_RECORDING_ID]));
    assert_eq!(switched["action"]["kind"], "advance_required");
}

#[tokio::test]
async fn window_dispatches_api_groups_during_ownership_and_replays_on_covering_delivery() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    fs::write(
        root.join(".traffic-e2e/apis.yaml"),
        "users: [/users/*]\nbatch: [/users/me]\nlater: [/outside]\n",
    )
    .unwrap();
    git(root, &["add", ".traffic-e2e/apis.yaml"]);
    git(root, &["commit", "-qm", "recorded catalog"]);
    let recording = recording_dir(root);
    seal_events_with_apis(
        &recording,
        &[
            (800, "GET", "/users/1"),
            (900, "GET", "/users/me"),
            (950, "GET", "/users/me"),
            (60_000_700, "GET", "/outside"),
        ],
    )
    .await;
    git(root, &["switch", "-qc", "codex/replay/fixture"]);
    let selected = successful(command(root, &["switch-recording-id", RECORDING_ID]));
    assert_eq!(selected["action"]["kind"], "advance_required");

    let initial = run_attempt_with_invalid_source(root, &["run"]);
    publish_mismatch(initial.clone(), 5);
    let status = || assignments(root);
    let failed = status();
    assert_eq!(failed["failure"]["seq"], 5);
    assert_dispatch(&failed, "ownership_required", "issue-analyst");
    let ownership = &failed["action"]["details"]["task"];
    assert_eq!(ownership["seq"], 5);
    assert_eq!(ownership["attempt_id"], initial["attempt_id"]);
    assert_eq!(
        failed["action"]["details"]["assignments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(group(&failed, "users")["items"][0]["sequences"], json!([8]));
    assert_eq!(
        group(&failed, "batch")["items"][0]["sequences"],
        json!([9, 10])
    );
    assert!(!command(root, &["run"]).status.success());
    let awaiting = register_task(root, &failed, "fixture-analyst");
    assert!(
        !plan(
            root,
            bind_delivery(
                json!({"ownership":{"seq":3,"scope":"job:sync_users","group":"sync"}}),
                &awaiting
            ),
        )
        .status
        .success()
    );

    let assigned = successful(plan(
        root,
        bind_delivery(
            json!({"ownership":{"seq":5,
        "scope":"job:sync_users","group":"sync"}}),
            &awaiting,
        ),
    ));
    assert_eq!(assigned["action"]["kind"], "dispatch_required");
    let assigned = status();
    assert_eq!(
        group(&assigned, "sync")["items"][0]["sequences"],
        json!([5])
    );
    assert_eq!(
        group(&assigned, "users")["worktree"],
        group(&failed, "users")["worktree"]
    );
    assert_eq!(
        register_implementers(root)["action"]["kind"],
        "implementation_required"
    );

    let branch = git(root, &["branch", "--show-current"]);
    let job_fix = fixture_fix(root, "worker-job", "job.txt", &branch);
    let users_fix = fixture_fix(root, "worker-users", "users.txt", &branch);
    let batch_fix = fixture_fix(root, "worker-batch", "batch.txt", &branch);
    let mut stale = delivery(group(&assigned, "users"), &users_fix, 8);
    stale["fixes"][0]["assignment_id"] = json!(uuid::Uuid::new_v4());
    assert!(!report(root, stale).status.success());
    assert_eq!(
        successful(report(
            root,
            delivery(group(&assigned, "users"), &users_fix, 8)
        ))["action"]["kind"],
        "implementation_required"
    );
    assert!(!command(root, &["run"]).status.success());
    let ready = successful(report(
        root,
        delivery(group(&assigned, "sync"), &job_fix, 5),
    ));
    assert_dispatch(&ready, "integration_required", "code-integrator");
    assert_eq!(ready["action"]["details"]["task"]["ready_fixes"], 2);
    assert!(ready["action"]["details"]["fixes"].is_null());
    assert!(ready["action"]["details"]["assignments"].is_null());
    assert_eq!(
        status()["action"]["details"]["fixes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let detail = status();
    let batch_worker = group(&detail, "batch");
    let other_worker_exited = successful(report(
        root,
        json!({"kind":"implementers",
        "workers":[{"group":"batch", "assignment_id":batch_worker["assignment_id"],
            "agent_handle":batch_worker["agent_handle"], "state":"exited"}]}),
    ));
    assert_dispatch(
        &other_worker_exited,
        "integration_required",
        "code-integrator",
    );
    let integrator = register_task(root, &ready, "fixture-integrator");
    git(root, &["merge", "--ff-only", &job_fix]);
    let awaiting_candidate = successful(command(root, &["status"]));
    assert_eq!(
        awaiting_candidate["action"]["details"]["task"],
        integrator["action"]["details"]["task"]
    );
    assert!(
        !report(
            root,
            bind_delivery(candidate(&initial, &job_fix, &[&users_fix]), &integrator)
        )
        .status
        .success()
    );
    let published = successful(report(
        root,
        bind_delivery(candidate(&initial, &job_fix, &[&job_fix]), &integrator),
    ));
    assert_eq!(published["action"]["kind"], "advance_required");
    assert_eq!(published["action"]["details"]["pending_dispatch"], 1);
    assert_eq!(
        group(&status(), "batch")["worktree"],
        group(&failed, "batch")["worktree"]
    );

    let next = run_attempt_with_invalid_source(root, &["run"]);
    // Exercise the live receipt path using the same lock and snapshot layout
    // as a running Replay, without needing a Target image.
    let attempt_dir = Path::new(next["progress"].as_str().unwrap())
        .parent()
        .unwrap();
    let result = attempt_dir.join("event-result.json");
    let terminal = fs::read(&result).unwrap();
    fs::remove_file(&result).unwrap();
    let running = fs::File::options()
        .read(true)
        .write(true)
        .open(attempt_dir.join("attempt.lock"))
        .unwrap();
    running.try_lock().unwrap();
    let run_lock = fs::File::options()
        .read(true)
        .write(true)
        .open(traffic_e2e::internal_runtime::root(root).join("replay-run.lock"))
        .unwrap();
    run_lock.try_lock().unwrap();
    assert_eq!(status()["state"], "running");
    register_implementers(root);
    successful(report(
        root,
        delivery(group(&assigned, "batch"), &batch_fix, 9),
    ));
    assert_eq!(
        group(&status(), "batch")["items"][0]["sequences"],
        json!([10])
    );
    fs::write(result, terminal).unwrap();
    drop(running);
    drop(run_lock);

    publish_mismatch(next.clone(), 8);
    let promoted = status();
    assert_dispatch(&promoted, "integration_required", "code-integrator");
    assert_ne!(
        promoted["action"]["details"]["task"]["task_id"],
        integrator["action"]["details"]["task"]["task_id"]
    );
    assert_eq!(
        promoted["action"]["details"]["fixes"][0]["commit"],
        users_fix
    );
    assert_eq!(
        group(&promoted, "later")["items"][0]["sequences"],
        json!([11])
    );
    assert_eq!(
        group(&promoted, "batch")["worktree"],
        group(&failed, "batch")["worktree"]
    );
    let new_integrator = register_task(root, &promoted, "next-integrator");
    let obsolete_candidate =
        bind_delivery(candidate(&initial, &job_fix, &[&job_fix]), &new_integrator);
    let rejected = report(root, obsolete_candidate);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("candidate refers to a stale attempt")
    );

    seal_events(&recording.with_file_name(OTHER_RECORDING_ID)).await;
    let switched = successful(command(root, &["switch-recording-id", OTHER_RECORDING_ID]));
    assert_eq!(switched["state"], "not_started");
    assert!(
        !report(
            root,
            dispatch_receipt(&new_integrator, "next-integrator", "started")
        )
        .status
        .success()
    );
    let restored = successful(command(root, &["switch-recording-id", RECORDING_ID]));
    assert_dispatch(&restored, "integration_required", "code-integrator");
    assert_eq!(
        restored["action"]["details"]["task"]["task_id"],
        new_integrator["action"]["details"]["task"]["task_id"]
    );
    let restored = status();
    assert_eq!(
        restored["action"]["details"]["fixes"],
        promoted["action"]["details"]["fixes"]
    );
    assert_eq!(restored["action"]["details"]["pending_dispatch"], 2);
    assert_eq!(
        group(&restored, "batch")["assignment_id"],
        group(&promoted, "batch")["assignment_id"]
    );
}

#[tokio::test]
async fn lookahead_delegates_unowned_matches_and_validates_sequence_files() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    fs::write(root.join(".traffic-e2e/apis.yaml"), "users: [/users/*]\n").unwrap();
    commit_catalog(root);
    let recording = recording_dir(root);
    seal_events_for_window(
        &recording,
        &[(800, "GET", "/users/1"), (900, "PATCH", "/users/2")],
        &[1_000, 60_000_400],
    )
    .await;
    git(root, &["switch", "-qc", "codex/replay/fixture"]);
    successful(command(root, &["switch-recording-id", RECORDING_ID]));
    let initial = run_attempt_with_invalid_source(root, &["run"]);
    publish_mismatch(initial, 2);
    register_implementers(root);

    let dispatch = assignments(root);
    assert_dispatch(&dispatch, "lookahead_ownership_required", "issue-analyst");
    let task = &dispatch["action"]["details"]["task"];
    assert_eq!(task["from_seq"], 2);
    assert_eq!(task["through_seq"], 11);
    assert_eq!(task["sequence_count"], 2);
    let worker = group(&dispatch, "users");
    let id = worker["assignment_id"].as_str().unwrap();
    let items = worker["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["scope"], "api:/users/*");
    let read_sequences = |args: &[&str]| {
        let result = command(root, args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap()
    };
    let owned = [
        "sequences",
        "--assignment-id",
        id,
        "--scope",
        "api:/users/*",
    ];
    assert_eq!(read_sequences(&owned), "8\n9\n");
    let unowned = ["sequences", "--task-id", task["task_id"].as_str().unwrap()];
    assert_eq!(read_sequences(&unowned), "5\n10\n");

    let analyst = register_task(root, &dispatch, "lookahead-analyst");
    let claim = json!({"kind":"claim", "group":"users", "assignment_id":id, "scope":"api:/users/*",
        "request_seq":8, "sequences_file":"claim.seq", "evidence":"Source call path."});
    fs::write(recording.join("claim.seq"), "9\n10\n").unwrap();
    let rejected = report(root, claim.clone());
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("seq 9 is not an unowned dependency")
    );
    fs::write(recording.join("claim.seq"), "5\n").unwrap();
    let rejected = report(root, claim.clone());
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("seq 5 must follow"));
    fs::write(recording.join("claim.seq"), "10\n").unwrap();
    successful(report(root, claim));
    assert_eq!(read_sequences(&owned), "8\n9\n10\n");
    assert_eq!(read_sequences(&unowned), "5\n");

    let findings = bind_delivery(
        json!({"lookahead":[{
            "sequences_file":"ownership.seq", "scope":"api:/users/*", "group":"users",
            "evidence":"Source call path associates this dependency with the users API."
        }]}),
        &analyst,
    );
    fs::write(recording.join("ownership.seq"), "5,6\n").unwrap();
    let rejected = plan(root, findings.clone());
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("seq 6"));
    fs::write(recording.join("ownership.seq"), "5, 10\n").unwrap();
    successful(plan(root, findings));
    assert_eq!(read_sequences(&owned), "5\n8\n9\n10\n");

    let review = json!({"kind":"review", "group":"users", "assignment_id":id,
        "sequences_file":"review.seq", "checks":["focused comparison passed"]});
    fs::write(recording.join("review.seq"), "5, 8\n6\n").unwrap();
    let rejected = report(root, review.clone());
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("assigned sequences in users"));
    fs::write(recording.join("review.seq"), "5, 8\n").unwrap();
    successful(report(root, review));
    assert_eq!(read_sequences(&owned), "9\n10\n");

    let branch = git(root, &["branch", "--show-current"]);
    let commit = fixture_fix(root, "worker-lookahead", "users.txt", &branch);
    fs::write(recording.join("fix.seq"), "9\n10\n").unwrap();
    successful(report(
        root,
        json!({"kind":"fixes", "fixes":[{
            "group":"users", "assignment_id":id, "commit":commit,
            "sequences_file":"fix.seq", "checks":["users API test passed"]
        }]}),
    ));
}
