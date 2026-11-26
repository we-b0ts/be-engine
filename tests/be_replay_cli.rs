use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use traffic_recording_store::writer::{JsonlBufferSettings, JsonlWriterPool, LedgerFiles};

#[path = "be_replay_cli/worktrees.rs"]
mod worktrees;
use worktrees::{assignments, commit_catalog, register_implementers};

const RECORDING_ID: &str = "20261125131020";
const OTHER_RECORDING_ID: &str = "20261125141020";

fn command(target: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_be-replay"))
        .arg("--target-root")
        .arg(target)
        .args(args)
        .output()
        .unwrap()
}

fn successful(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_status_attempt(status: &Value, run: &Value) {
    let attempt = &status["session"];
    assert_eq!(attempt["attempt_id"], run["session"]["attempt_id"]);
    assert!(attempt.get("progress").is_none());
    assert!(attempt.get("report").is_none());
    assert!(attempt.get("events").is_none());
    assert!(status.get("next").is_none());
}

fn recording_dir(target: &Path) -> PathBuf {
    target
        .join(traffic_e2e::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings")
        .join(RECORDING_ID)
}

fn git(target: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn configure(target: &Path) {
    let traffic = target.join(".traffic-e2e");
    fs::create_dir_all(&traffic).unwrap();
    fs::write(
        traffic.join("project.yaml"),
        include_str!("manual/readonly/project.yaml").replace(
            "tests/manual/readonly/policy.yaml",
            ".traffic-e2e/policy.yaml",
        ),
    )
    .unwrap();
    fs::write(
        traffic.join("policy.yaml"),
        include_str!("manual/readonly/policy.yaml"),
    )
    .unwrap();
    fs::write(traffic.join("Dockerfile.target"), "FROM scratch\n").unwrap();
    fs::write(target.join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    git(target, &["init", "-q", "-b", "dev-migration"]);
    git(target, &["config", "user.name", "Test"]);
    git(target, &["config", "user.email", "test@example.com"]);
    git(target, &["add", "."]);
    git(
        target,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
    );
}

#[tokio::test]
async fn switching_rejects_incomplete_capture_even_if_the_runtime_report_completed() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    git(root, &["switch", "-qc", "codex/replay/fixture"]);
    let recording = recording_dir(root);
    seal_events(&recording).await;
    let manifest = recording.join("dependency-manifest.json");
    let mut document: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    document["capture_complete"] = json!(false);
    document["coverage"]["capture_failures"] = json!(1);
    fs::write(&manifest, serde_json::to_vec(&document).unwrap()).unwrap();
    fs::write(
        recording.join("recording-run.json"),
        br#"{"status":"completed"}"#,
    )
    .unwrap();

    let output = command(root, &["switch-recording-id", RECORDING_ID]);
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("Source session capture is incomplete"));
    assert!(error.contains("capture_failures=1"));
    assert!(error.contains(manifest.to_str().unwrap()));
}

#[tokio::test]
async fn status_starts_a_new_round_on_approval_and_preserves_attempt_history() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let recording = recording_dir(root);
    seal_events(&recording).await;
    let not_started = successful(command(root, &["status"]));
    assert_eq!(not_started["action"]["kind"], "select_recording");
    assert_eq!(
        not_started["action"]["command"],
        json!(["status", "--recording-run-id", "<ID>"])
    );
    assert_eq!(
        not_started["action"]["details"]["recording_ids"],
        json!([RECORDING_ID])
    );
    let confirm = successful(command(
        root,
        &["status", "--recording-run-id", RECORDING_ID],
    ));
    assert_eq!(confirm["action"]["kind"], "confirm_regression");
    assert_eq!(confirm["branch"], "dev-migration");
    assert_eq!(
        confirm["action"]["command"],
        json!(["run", "--user-confirm", "--recording-run-id", RECORDING_ID]),
    );
    assert!(!traffic_e2e::internal_runtime::root(root).exists());
    assert!(
        !command(root, &["run", "--recording-run-id", RECORDING_ID])
            .status
            .success()
    );
    assert_eq!(git(root, &["branch", "--show-current"]), "dev-migration");

    // Fail authentication before Docker while retaining sealed metadata, so the
    // real CLI exercises attempt publication and failure routing.
    fs::write(recording.join("events.tsv"), b"broken\n").unwrap();
    let failed_run = |args: &[&str]| -> Value {
        let output = command(root, args);
        assert!(!output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "missing run JSON: {error}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        });
        assert_eq!(result["session"]["passed"], false);
        assert_eq!(result["action"]["kind"], "setup_required");
        result
    };
    let first = failed_run(&["run", "--user-confirm", "--recording-run-id", RECORDING_ID]);
    let branch = git(root, &["branch", "--show-current"]);
    assert!(branch.starts_with("codex/replay/"));
    let second = failed_run(&["run"]);
    let first_id = first["session"]["attempt_id"].as_str().unwrap();
    assert_ne!(
        first["session"]["attempt_id"],
        second["session"]["attempt_id"]
    );
    assert_eq!(first["session"]["run_key"], second["session"]["run_key"]);
    assert_eq!(
        first["session"]["target_commit"],
        git(root, &["rev-parse", "HEAD"])
    );
    let latest = successful(command(root, &["status"]));
    assert_eq!(latest["state"], "failed");
    assert_status_attempt(&latest, &second);
    assert_eq!(latest["action"], second["action"]);
    let historical = successful(command(root, &["status", "--attempt-id", first_id]));
    assert_status_attempt(&historical, &first);
    assert_eq!(historical["failure"]["reason"], first["session"]["error"]);
    assert!(historical["action"].is_null());

    let other = recording.with_file_name(OTHER_RECORDING_ID);
    seal_events(&other).await;
    let pending = successful(command(
        root,
        &["status", "--recording-run-id", OTHER_RECORDING_ID],
    ));
    assert_eq!(
        pending["action"]["command"],
        json!(["switch-recording-id", OTHER_RECORDING_ID])
    );
    assert_eq!(
        successful(command(root, &["status"]))["recording_id"],
        RECORDING_ID
    );

    let lock = fs::File::options()
        .read(true)
        .write(true)
        .open(traffic_e2e::internal_runtime::root(root).join("event-replay.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let busy = command(root, &["switch-recording-id", OTHER_RECORDING_ID]);
    assert!(!busy.status.success());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("another event Replay is active"));
    drop(lock);
    assert_status_attempt(&successful(command(root, &["status"])), &second);

    fs::write(other.join("events.tsv"), b"broken\n").unwrap();
    let other_attempt = failed_run(&["run", "--recording-run-id", OTHER_RECORDING_ID]);
    assert_ne!(
        other_attempt["session"]["run_key"],
        first["session"]["run_key"]
    );
    let historical = successful(command(
        root,
        &[
            "status",
            "--recording-run-id",
            RECORDING_ID,
            "--attempt-id",
            first_id,
        ],
    ));
    assert_status_attempt(&historical, &first);
    assert_status_attempt(&successful(command(root, &["status"])), &other_attempt);
    let restored = successful(command(root, &["switch-recording-id", RECORDING_ID]));
    assert_status_attempt(&restored, &second);
    assert_eq!(git(root, &["branch", "--show-current"]), branch);
    assert_eq!(
        git(root, &["rev-parse", "HEAD"]),
        first["session"]["target_commit"].as_str().unwrap()
    );

    git(root, &["switch", "dev-migration"]);
    let fresh = successful(command(
        root,
        &["status", "--recording-run-id", RECORDING_ID],
    ));
    assert_eq!(fresh["action"]["kind"], "confirm_regression");
    assert!(fresh["session"].is_null());
    git(root, &["switch", &branch]);
    assert_status_attempt(&successful(command(root, &["status"])), &second);
}

async fn seal_events(recording: &Path) {
    seal_events_with_apis(recording, &[]).await;
}

async fn seal_events_with_apis(recording: &Path, requests: &[(u64, &str, &str)]) {
    fs::create_dir_all(recording).unwrap();
    let run_epoch = uuid::Uuid::new_v4();
    let process_epoch = uuid::Uuid::new_v4();
    let mut ledger = LedgerFiles::initialize_for_mode(recording, run_epoch, process_epoch, true)
        .await
        .unwrap();
    let mut stream = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: std::time::Duration::from_secs(1),
    });
    let mut sequence = 0;
    for (dependency, mut row) in [
        (false, json!({"event_type": "source_start"})),
        (false, json!({"event_type": "ready"})),
        (
            true,
            json!({"event_type": "message_started", "dependency_sequence": 3}),
        ),
        (
            true,
            json!({"event_type": "wire_output_started", "dependency_sequence": 3,
            "output": {"kind": "end"}}),
        ),
        (
            true,
            json!({"event_type": "capture_started", "dependency_sequence": 5,
            "phase": "runtime"}),
        ),
        (
            true,
            json!({"event_type": "wire_output", "dependency_sequence": 3,
            "output": {"kind": "end"}}),
        ),
        (
            true,
            json!({"event_type": "wire_output", "dependency_sequence": 5,
            "output": {"kind": "end"}}),
        ),
    ] {
        sequence += 1;
        row["sequence"] = json!(sequence);
        row["offset_micros"] = json!((sequence - 1) * 100);
        if dependency {
            let row = serde_json::from_value(row).unwrap();
            ledger.append_event(&mut stream, &row).await.unwrap();
        } else {
            let row = serde_json::from_value(row).unwrap();
            ledger
                .append_session_event(&mut stream, &row)
                .await
                .unwrap();
        }
    }
    let mut offset = (sequence - 1) * 100;
    for &(at, method, path) in requests {
        sequence += 1;
        offset = at;
        let row = serde_json::from_value(json!({
            "sequence":sequence, "offset_micros": offset, "event_type":"primary_request",
            "exchange":uuid::Uuid::new_v4(), "request":{"method":method,"uri":path}
        }))
        .unwrap();
        ledger
            .append_session_event(&mut stream, &row)
            .await
            .unwrap();
    }
    for event in ["stop", "source_exit"] {
        sequence += 1;
        offset += 100;
        let mut row = json!({"sequence":sequence, "offset_micros":offset, "event_type":event});
        if event == "source_exit" {
            row["status"] = json!(0);
        }
        ledger
            .append_session_event(&mut stream, &serde_json::from_value(row).unwrap())
            .await
            .unwrap();
    }
    let files = ledger.seal(&mut stream).await.unwrap();
    let manifest = json!({
        "schema": "traffic-recording/v14",
        "run_id": recording.file_name().unwrap().to_str().unwrap(),
        "run_epoch": run_epoch, "process_epochs": [process_epoch],
        "capture_policy_identity": "fixture", "sealed": true, "capture_complete": true,
        "source_artifact": {"status": "unavailable", "reason": "fixture"},
        "coverage": {"admitted": 0, "terminal": 0, "capture_failures": 0,
            "inventory_gaps": false, "pending": []},
        "records": 0, "unattributed_records": 0, "inputs": [], "files": files,
        "semantic_inventory": {"total_mandatory": 0, "by_owner_kind": {},
            "unsupported_by_scope": {}, "unattributed_dependencies": 0},
    });
    fs::write(
        recording.join("dependency-manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
}

fn persist_attempt(attempt: &Value) {
    let result =
        Path::new(attempt["progress"].as_str().unwrap()).with_file_name("event-result.json");
    fs::write(result, serde_json::to_vec(attempt).unwrap()).unwrap();
}

fn publish_mismatch(mut attempt: Value, sequence: u64) {
    let expected = json!({"sequence":sequence, "kind":"request", "dependency_sequence":sequence});
    attempt["events"] = json!({"total":null, "matched":2, "complete":false,
        "last_sequence":sequence - 1, "expected":expected, "failure":{
            "expected":expected, "reason":"fixture mismatch",
            "target_observation_id":uuid::Uuid::from_u128(2)}});
    attempt["phase"] = json!("replaying");
    attempt["apis"] = json!({"verified":1,"total":3});
    attempt["cases"] = json!({"completed":1,"total":6});
    persist_attempt(&attempt);
}

fn fixture_fix(root: &Path, work: &str, filename: &str, return_to: &str) -> String {
    git(root, &["switch", "-c", work]);
    fs::write(root.join(filename), "fixed").unwrap();
    git(root, &["add", filename]);
    git(root, &["commit", "-qm", work]);
    let commit = git(root, &["rev-parse", "HEAD"]);
    git(root, &["switch", return_to]);
    commit
}

fn run_attempt_with_invalid_source(root: &Path, args: &[&str]) -> Value {
    let events = recording_dir(root).join("events.tsv");
    let sealed = fs::read(&events).unwrap();
    fs::write(&events, b"broken\n").unwrap();
    let output = command(root, args);
    fs::write(events, sealed).unwrap();
    assert!(!output.status.success());
    serde_json::from_slice::<Value>(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "missing run result: {error}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    })["session"]
        .clone()
}

fn run_as_passed(mut attempt: Value, api_total: usize) -> Value {
    attempt["passed"] = json!(true);
    attempt["error"] = Value::Null;
    attempt["phase"] = json!("complete");
    attempt["events"] = json!({"complete":true,"total":6,"matched":6,"last_sequence":8});
    attempt["apis"] = json!({"total":api_total,"verified":api_total});
    persist_attempt(&attempt);
    attempt
}

#[tokio::test]
async fn an_engine_update_can_retry_once_after_managed_configuration_is_committed() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let project = ".traffic-e2e/project.yaml";
    let policy = "contracts/active.yaml";
    let apis = ".traffic-e2e/apis.yaml";
    let project_contents = fs::read_to_string(root.join(project))
        .unwrap()
        .replace(".traffic-e2e/policy.yaml", policy);
    fs::create_dir_all(root.join("contracts")).unwrap();
    fs::rename(root.join(".traffic-e2e/policy.yaml"), root.join(policy)).unwrap();
    fs::write(root.join(project), &project_contents).unwrap();
    git(root, &["add", ".traffic-e2e", "contracts"]);
    git(root, &["commit", "-qm", "configure custom policy path"]);

    let recording = recording_dir(root);
    seal_events(&recording).await;
    let mut first = run_attempt_with_invalid_source(
        root,
        &["run", "--user-confirm", "--recording-run-id", RECORDING_ID],
    );
    let current_engine = first["engine_revision"].clone();
    assert!(current_engine.is_string());
    publish_mismatch(first.clone(), 5);
    let status = || successful(command(root, &["status"]));
    let blocked = command(root, &["run"]);
    assert!(!blocked.status.success());
    assert_eq!(status()["action"]["kind"], "ownership_required");

    let report = recording.join("candidate.json");
    fs::write(
        &report,
        json!({"kind":"candidate", "attempt_id":first["attempt_id"], "commit":first["target_commit"],
            "included_fixes":[], "checks":["fixture checked"]})
            .to_string(),
    )
    .unwrap();
    let findings = recording.join("findings.json");
    fs::write(
        &findings,
        json!({"ownership":{"seq":5,"scope":"startup","group":"startup"}}).to_string(),
    )
    .unwrap();
    let plan = ["plan", "--findings", findings.to_str().unwrap()];
    let assigned = successful(command(root, &plan));
    assert_eq!(assigned["action"]["kind"], "dispatch_required");
    register_implementers(root);

    // Store a prior engine fingerprint on a failed attempt while keeping its
    // real sequence, Target revision and pending repair.
    let round_file = fs::read_dir(traffic_e2e::internal_runtime::root(root).join("replay-rounds"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let mut round: Value = serde_json::from_slice(&fs::read(&round_file).unwrap()).unwrap();
    round.as_object_mut().unwrap().remove("attempted_engines");
    fs::write(round_file, serde_json::to_vec(&round).unwrap()).unwrap();
    let old_engine = json!("fixture-older-engine");
    first["engine_revision"] = old_engine.clone();
    publish_mismatch(first.clone(), 5);
    assert_eq!(status()["action"]["details"]["reason"], "engine_changed");

    let policy_contents = fs::read_to_string(root.join(policy)).unwrap();
    fs::write(
        root.join(project),
        format!("{project_contents}\n# reviewed\n"),
    )
    .unwrap();
    fs::write(
        root.join(policy),
        format!("{policy_contents}\n# reviewed\n"),
    )
    .unwrap();
    fs::write(root.join(apis), "other: [/never-recorded]\n").unwrap();
    git(root, &["add", policy]);
    let current = status();
    assert_eq!(current["action"]["kind"], "configuration_commit_required");
    let mut files = current["action"]["details"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect::<Vec<_>>();
    files.sort_unstable();
    assert_eq!(files, [apis, project, policy]);
    assert_eq!(current["progress"]["events"], "4/9");
    assert_eq!(current["progress"]["cases"], "1/6");
    for args in [
        &["run"][..],
        &plan,
        &["report", "--file", report.to_str().unwrap()],
    ] {
        let rejected = command(root, args);
        assert!(!rejected.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("commit the managed configuration"),
            "{args:?}"
        );
    }

    git(root, &["add", project, apis]);
    git(root, &["commit", "-qm", "review managed configuration"]);
    let current = status();
    assert_eq!(current["action"]["kind"], "advance_required");
    assert_eq!(current["action"]["details"]["reason"], "engine_changed");
    assert_eq!(current["action"]["command"], json!(["run"]));
    let mut next = run_attempt_with_invalid_source(root, &["run"]);
    assert_ne!(next["attempt_id"], first["attempt_id"]);
    assert_ne!(next["target_commit"], first["target_commit"]);
    assert_eq!(next["engine_revision"], current_engine);
    let old_result =
        Path::new(first["progress"].as_str().unwrap()).with_file_name("event-result.json");
    let old_result: Value = serde_json::from_slice(&fs::read(old_result).unwrap()).unwrap();
    assert_eq!(old_result["engine_revision"], old_engine);
    assert_eq!(status()["progress"]["previous_events"], "4/9");

    publish_mismatch(next.clone(), 7);
    let current = status();
    assert_eq!(current["action"]["kind"], "ownership_required");
    assert_eq!(
        current["progress"],
        json!({"apis":"1/3","cases":"1/6","events":"6/9","previous_events":"4/9"})
    );
    assert!(!command(root, &["run"]).status.success());

    // Simulate falling back to the old engine for the latest attempt. A
    // fingerprint difference alone cannot reopen the consumed retry.
    next["engine_revision"] = old_engine;
    publish_mismatch(next, 7);
    assert_eq!(status()["action"]["kind"], "ownership_required");
    assert!(!command(root, &["run"]).status.success());
}

fn submit(root: &Path, command_name: &str, flag: &str, value: Value) -> Output {
    let file = recording_dir(root).join(format!("{command_name}-submission.json"));
    fs::write(&file, value.to_string()).unwrap();
    command(root, &[command_name, flag, file.to_str().unwrap()])
}

fn plan(root: &Path, value: Value) -> Output {
    submit(root, "plan", "--findings", value)
}

fn report(root: &Path, value: Value) -> Output {
    submit(root, "report", "--file", value)
}

fn group<'a>(state: &'a Value, group: &str) -> &'a Value {
    state["action"]["details"]["assignments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["group"] == group)
        .unwrap_or_else(|| panic!("missing assignment {group} in {state}"))
}

fn confirm_recording(root: &Path) -> Value {
    successful(command(
        root,
        &["run", "--user-confirm", "--recording-run-id", RECORDING_ID],
    ))
}

fn delivery(worker: &Value, commit: &str, seq: u64) -> Value {
    json!({"kind":"fixes","fixes":[{"group":worker["group"],
        "assignment_id":worker["assignment_id"],"commit":commit,
        "sequences":[seq],"checks":["focused checks passed"]}]})
}

fn candidate(attempt: &Value, head: &str, included: &[&str]) -> Value {
    json!({"kind":"candidate","attempt_id":attempt["attempt_id"],"commit":head,
        "included_fixes":included,"checks":["integration checks passed"]})
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
    assert_eq!(preflight["action"]["kind"], "api_grouping_required");
    assert_eq!(preflight["action"]["details"]["ungrouped_apis"], 1);
    assert_eq!(preflight["action"]["query"], json!(["apis", "--ungrouped"]));
    assert!(preflight["session"].is_null());
    let missing = successful(command(root, &["apis", "--ungrouped"]));
    assert_eq!(missing["apis"].as_array().unwrap().len(), 1);
    assert_eq!(missing["apis"][0]["api"], "POST /new");
    assert_eq!(
        successful(command(root, &["run"]))["action"]["kind"],
        "api_grouping_required"
    );
    let known = json!({"api":"GET /users/*","case_pattern":"/users/*","group":"users"});
    assert!(!plan(root, json!({"apis":[known]})).status.success());
    assert!(
        !plan(
            root,
            json!({"apis":[known,{"api":"POST /new","case_pattern":"/new","group":"new-api"}]})
        )
        .status
        .success()
    );
    assert_eq!(fs::read_to_string(&catalog).unwrap(), "users: [/users/*]\n");
    fs::create_dir_all(root.join(".traffic-e2e/local/rewrite-worktrees/api-implementer-0"))
        .unwrap();
    let reviewed = successful(plan(
        root,
        json!({"apis":[{"api":"POST /new","case_pattern":"/new","group":"new-api"}]}),
    ));
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
    assert_eq!(
        successful(report(root, delivery(worker, &fix, 10)))["action"]["kind"],
        "integration_required"
    );
    git(root, &["merge", "--ff-only", &fix]);
    let head = git(root, &["rev-parse", "HEAD"]);
    assert_eq!(
        successful(report(root, candidate(&attempt, &head, &[&fix])))["action"]["kind"],
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
    assert_eq!(failed["action"]["kind"], "ownership_required");
    assert_eq!(failed["action"]["details"]["role"], "issue-analyst");
    assert_eq!(
        failed["action"]["command"],
        json!(["plan", "--findings", "<ownership.json>"])
    );
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
    assert!(
        !plan(
            root,
            json!({"ownership":{"seq":3,"scope":"job:sync_users","group":"sync"}})
        )
        .status
        .success()
    );

    let assigned = successful(plan(
        root,
        json!({"ownership":{"seq":5,
        "scope":"job:sync_users","group":"sync"}}),
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
    assert_eq!(ready["action"]["kind"], "integration_required");
    assert_eq!(ready["action"]["details"]["ready_fixes"], 2);
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
    assert_eq!(
        other_worker_exited["action"]["kind"],
        "integration_required"
    );
    git(root, &["merge", "--ff-only", &job_fix]);
    assert!(
        !report(root, candidate(&initial, &job_fix, &[&users_fix]))
            .status
            .success()
    );
    let published = successful(report(root, candidate(&initial, &job_fix, &[&job_fix])));
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
    assert_eq!(promoted["action"]["kind"], "integration_required");
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

    seal_events(&recording.with_file_name(OTHER_RECORDING_ID)).await;
    let switched = successful(command(root, &["switch-recording-id", OTHER_RECORDING_ID]));
    assert_eq!(switched["state"], "not_started");
    let restored = successful(command(root, &["switch-recording-id", RECORDING_ID]));
    assert_eq!(restored["action"]["kind"], "integration_required");
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
async fn an_assigned_implementer_can_escalate_the_current_failed_sequence() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let recording = recording_dir(root);
    seal_events(&recording).await;
    let run = run_attempt_with_invalid_source(
        root,
        &["run", "--user-confirm", "--recording-run-id", RECORDING_ID],
    );
    publish_mismatch(run.clone(), 5);

    let assigned = successful(plan(
        root,
        json!({
            "ownership":{"seq":5,"scope":"startup","group":"startup"}
        }),
    ));
    assert_eq!(assigned["action"]["kind"], "dispatch_required");
    let details = assignments(root);
    assert_eq!(group(&details, "startup")["items"][0]["scope"], "startup");

    let reported = successful(report(
        root,
        json!({
            "kind":"engine_gap","group":"startup","sequences":[5],
            "assignment_id":group(&details, "startup")["assignment_id"],
            "evidence":"Source seq 5 and the Target observation show the same request."
        }),
    ));
    assert_eq!(reported["action"]["kind"], "setup_required");
    assert_eq!(
        successful(command(root, &["status"]))["action"],
        reported["action"]
    );

    assert!(!command(root, &["run"]).status.success());
}

#[tokio::test]
async fn flat_events_queries_the_recording_without_starting_replay() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    let recording = recording_dir(root);
    seal_events(&recording).await;

    let query_events = |arguments: &[&str]| {
        let mut argv = vec!["events", "--recording-run-id", RECORDING_ID];
        argv.extend_from_slice(arguments);
        successful(command(root, &argv))
    };
    let sequences = |page: &Value| -> Vec<u64> {
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["sequence"].as_u64().unwrap())
            .collect()
    };
    let events = query_events(&["--from-seq", "2", "--limit", "2"]);
    assert_eq!(events["recording_id"], RECORDING_ID);
    assert_eq!(sequences(&events), [2, 5]);
    assert_eq!(events["next_after_sequence"], 5);
    let next = query_events(&["--from-seq", "2", "--limit", "2", "--after-seq", "5"]);
    assert_eq!(sequences(&next), [7, 8]);
    assert_eq!(next["next_after_sequence"], 8);
    let tail = query_events(&["--from-seq", "5"]);
    assert_eq!(sequences(&tail), [5, 7, 8, 9]);
    assert!(tail["next_after_sequence"].is_null());
    let pushes = query_events(&["--from-seq", "3", "--with-push-event"]);
    assert_eq!(sequences(&pushes), [3, 4, 5, 6, 7, 8, 9]);
    let exact = query_events(&["--seq", "3", "--seq", "4", "--seq", "6"]);
    assert_eq!(sequences(&exact), [3, 4, 6]);

    assert!(!traffic_e2e::internal_runtime::root(root).exists());
}
