use super::*;

pub(super) fn assignments(root: &Path) -> Value {
    successful(command(root, &["status", "--with-assignments"]))
}

pub(super) fn register_implementers(root: &Path) -> Value {
    launch_implementers(root);
    confirm_running(root)
}

fn launch_implementers(root: &Path) -> Value {
    let updates: Vec<_> = assignments(root)["action"]["details"]["assignments"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["agent_handle"].is_null())
        .map(worker_started)
        .collect();
    if updates.is_empty() {
        return successful(command(root, &["status"]));
    }
    successful(report(
        root,
        json!({"kind":"implementers", "workers":updates}),
    ))
}

fn confirm_running(root: &Path) -> Value {
    let updates: Vec<_> = assignments(root)["action"]["details"]["assignments"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["worker_status"] == "check_required")
        .map(|row| {
            json!({"group":row["group"], "assignment_id":row["assignment_id"],
            "agent_handle":row["agent_handle"], "state":"running"})
        })
        .collect();
    if updates.is_empty() {
        return successful(command(root, &["status"]));
    }
    successful(report(
        root,
        json!({"kind":"implementers", "workers":updates}),
    ))
}

fn worker_started(worker: &Value) -> Value {
    json!({"group":worker["group"], "assignment_id":worker["assignment_id"],
        "agent_handle":format!("fixture-{}", worker["name"].as_str().unwrap()), "state":"started"})
}

pub(super) fn commit_catalog(root: &Path) {
    git(root, &["add", ".traffic-e2e/apis.yaml"]);
    git(root, &["commit", "-qm", "register API groupings"]);
}

#[tokio::test]
async fn implementer_can_confirm_an_existing_api_without_a_code_commit() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let requests = [(800, "GET", "/existing")];
    let recording = recording_dir(root);
    seal_events_with_apis(&recording, &requests).await;
    seal_events_with_apis(&recording.with_file_name(OTHER_RECORDING_ID), &requests).await;
    let grouping = confirm_recording(root);
    let analyst = register_task(root, &grouping, "fixture-analyst");
    successful(plan(
        root,
        bind_delivery(
            json!({"apis":[{"api":"GET /existing","case_pattern":"/existing", "group":"existing"}]}),
            &analyst,
        ),
    ));
    commit_catalog(root);
    register_implementers(root);
    let active = assignments(root);
    let worker = group(&active, "existing");
    let mut confirmation = json!({"kind":"review", "group":"existing", "assignment_id":worker["assignment_id"],
        "sequences":worker["items"][0]["sequences"], "checks":["Verified the existing route and handler"]});
    assert!(!report(root, confirmation.clone()).status.success());
    confirmation["confirms_apis"] = true.into();
    let reviewed = successful(report(root, confirmation));
    assert_eq!(reviewed["action"]["kind"], "advance_required");
    assert!(reviewed["action"]["details"]["assignments"].is_null());
    let switched = successful(command(root, &["switch-recording-id", OTHER_RECORDING_ID]));
    assert_eq!(switched["action"]["kind"], "advance_required");
}

#[tokio::test]
async fn recordings_reuse_worktree_slots_with_independent_assignments() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let recording = recording_dir(root);
    seal_events_with_apis(&recording, &[(800, "POST", "/new/123")]).await;
    seal_events_with_apis(
        &recording.with_file_name(OTHER_RECORDING_ID),
        &[(800, "POST", "/new/456"), (900, "GET", "/new/789")],
    )
    .await;
    let analyst = register_task(root, &confirm_recording(root), "fixture-analyst");

    let grouping = json!({"apis":[{"api":"POST /new/123",
        "case_pattern":"/new/*", "group":"new-api"}]});
    assert_eq!(
        successful(plan(root, bind_delivery(grouping, &analyst)))["action"]["kind"],
        "configuration_commit_required"
    );
    commit_catalog(root);
    let first = assignments(root);
    let worker = group(&first, "new-api");
    assert_eq!(worker["name"], "api-implementer-0");
    let path = root.join(worker["worktree"].as_str().unwrap());
    git(
        root,
        &[
            "worktree",
            "add",
            "--detach",
            path.to_str().unwrap(),
            worker["base_commit"].as_str().unwrap(),
        ],
    );
    let unfinished = path.join("unfinished.rs");
    fs::write(&unfinished, "pending work").unwrap();
    register_implementers(root);

    let second = successful(command(root, &["switch-recording-id", OTHER_RECORDING_ID]));
    assert_eq!(second["action"]["kind"], "dispatch_required");
    let new_assignments = assignments(root);
    let replacement = group(&new_assignments, "new-api");
    assert_eq!(replacement["name"], worker["name"]);
    assert_eq!(replacement["worktree"], worker["worktree"]);
    assert_ne!(replacement["assignment_id"], worker["assignment_id"]);
    let scopes: Vec<_> = replacement["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["scope"].as_str().unwrap())
        .collect();
    assert_eq!(scopes, ["api:GET /new/*", "api:POST /new/*"]);
    assert_eq!(fs::read_to_string(&unfinished).unwrap(), "pending work");
    let stale = report(
        root,
        delivery(worker, worker["base_commit"].as_str().unwrap(), 8),
    );
    assert!(!stale.status.success());
    assert!(
        String::from_utf8_lossy(&stale.stderr)
            .contains("delivery does not match the active assignment")
    );

    let restored = successful(command(root, &["switch-recording-id", RECORDING_ID]));
    assert_eq!(restored["action"]["kind"], "dispatch_required");
    assert_eq!(group(&assignments(root), "new-api"), worker);
}

#[tokio::test]
async fn status_waits_for_every_dispatched_worker_before_first_replay() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let paths: Vec<_> = (0..17).map(|index| format!("/api-{index:02}")).collect();
    let requests: Vec<_> = paths
        .iter()
        .enumerate()
        .map(|(index, path)| (800 + index as u64, "GET", path.as_str()))
        .collect();
    seal_events_with_apis(&recording_dir(root), &requests).await;
    let grouping = confirm_recording(root);
    assert_dispatch(&grouping, "api_grouping_required", "issue-analyst");
    let analyst = register_task(root, &grouping, "fixture-analyst");
    let groupings: Vec<_> = paths
        .iter()
        .map(|path| {
            json!({"api":format!("GET {path}"),
            "case_pattern":path, "group":path.trim_start_matches('/')})
        })
        .collect();
    let planned = successful(plan(
        root,
        bind_delivery(json!({"apis":groupings}), &analyst),
    ));
    assert_eq!(planned["action"]["kind"], "configuration_commit_required");
    commit_catalog(root);
    let status = assignments(root);
    let workers = status["action"]["details"]["assignments"]
        .as_array()
        .unwrap();
    assert_eq!(workers.len(), 16);
    let compact = successful(command(root, &["status"]));
    assert_eq!(compact["action"]["kind"], "dispatch_required");
    assert_eq!(
        compact["action"]["query"],
        json!(["status", "--with-assignments"])
    );
    assert!(compact["action"]["details"]["assignments"].is_null());
    let blocked = successful(command(root, &["run"]));
    assert_eq!(blocked["action"]["kind"], "dispatch_required");
    assert_eq!(blocked["action"]["details"]["pending_dispatch"], 16);
    assert!(blocked["action"]["details"]["assignments"].is_null());
    assert!(blocked["session"].is_null());
    let worker = worker_started(&workers[0]);
    let first = successful(report(
        root,
        json!({"kind":"implementers", "workers":[worker]}),
    ));
    assert_eq!(first["action"]["details"]["pending_dispatch"], 15);
    assert_eq!(first["action"]["details"]["pending_worker_status"], 1);
    let check = launch_implementers(root);
    assert_eq!(check["action"]["kind"], "worker_status_required");
    assert_eq!(check["action"]["details"]["pending_worker_status"], 16);
    assert!(check["action"]["details"]["assignments"].is_null());
    let blocked = successful(command(root, &["run"]));
    assert_eq!(blocked["action"]["kind"], "worker_status_required");
    assert!(blocked["session"].is_null());
    let waiting = confirm_running(root);
    assert_eq!(waiting["action"]["kind"], "implementation_required");
    assert_eq!(waiting["action"]["details"]["queued_api_groups"], 1);
    let blocked = successful(command(root, &["run"]));
    assert_eq!(blocked["action"]["kind"], "implementation_required");
    assert!(blocked["session"].is_null());

    let mut exited = worker;
    exited["state"] = "exited".into();
    let redispatch = successful(report(
        root,
        json!({"kind":"implementers", "workers":[exited]}),
    ));
    assert_eq!(redispatch["action"]["details"]["pending_dispatch"], 1);
    let current = assignments(root);
    let same_group = group(&current, workers[0]["group"].as_str().unwrap());
    assert_eq!(same_group["assignment_id"], workers[0]["assignment_id"]);
    let mut replacement = worker_started(same_group);
    replacement["agent_handle"] = "replacement-runtime-id".into();
    let resumed = successful(report(
        root,
        json!({"kind":"implementers", "workers":[replacement]}),
    ));
    assert_eq!(resumed["action"]["kind"], "worker_status_required");
    assert_eq!(
        confirm_running(root)["action"]["kind"],
        "implementation_required"
    );

    let branch = git(root, &["branch", "--show-current"]);
    let fixed = fixture_fix(root, "worker-fix", "api.rs", &branch);
    let sequence = workers[0]["items"][0]["sequences"][0].as_u64().unwrap();
    let refill = successful(report(root, delivery(&workers[0], &fixed, sequence)));
    assert_eq!(refill["action"]["kind"], "dispatch_required");
    assert_eq!(refill["action"]["details"]["pending_dispatch"], 1);
    assert_eq!(
        group(&assignments(root), "api-16")["name"],
        workers[0]["name"]
    );
    assert_eq!(
        register_implementers(root)["action"]["kind"],
        "advance_required"
    );
}

#[tokio::test]
async fn newly_grouped_apis_are_dispatched_before_an_optional_engine_retry() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let catalog = root.join(".traffic-e2e/apis.yaml");
    fs::write(&catalog, "prior: [/onboard]\n").unwrap();
    commit_catalog(root);
    seal_events_with_apis(&recording_dir(root), &[(800, "GET", "/onboard")]).await;
    let mut failed = run_attempt_with_invalid_source(
        root,
        &["run", "--user-confirm", "--recording-run-id", RECORDING_ID],
    );
    allow_engine_retry(root, &mut failed);
    publish_mismatch(failed.clone(), 5);
    let before = assignments(root);
    assert_eq!(before["action"]["kind"], "advance_required");
    assert_eq!(before["action"]["details"]["reason"], "engine_changed");

    fs::write(&catalog, "unrelated: [/unused]\n").unwrap();
    commit_catalog(root);
    let ungrouped = assignments(root);
    assert_dispatch(&ungrouped, "api_grouping_required", "issue-analyst");
    let analyst = register_task(root, &ungrouped, "fixture-analyst");
    successful(plan(
        root,
        bind_delivery(
            json!({"apis":[{"api":"GET /onboard","case_pattern":"/onboard","group":"onboard"}]}),
            &analyst,
        ),
    ));
    commit_catalog(root);

    let dispatched = assignments(root);
    assert_eq!(dispatched["action"]["kind"], "dispatch_required");
    let worker = group(&dispatched, "onboard");
    assert_eq!(worker["base_commit"], git(root, &["rev-parse", "HEAD"]));
    let blocked = successful(command(root, &["run"]));
    assert_eq!(blocked["action"]["kind"], "dispatch_required");
    assert_eq!(blocked["session"]["attempt_id"], failed["attempt_id"]);
    assert_eq!(
        launch_implementers(root)["action"]["kind"],
        "worker_status_required"
    );
    let retry = confirm_running(root);
    assert_eq!(retry["action"]["kind"], "advance_required");
    assert_eq!(retry["action"]["details"]["reason"], "engine_changed");
}
