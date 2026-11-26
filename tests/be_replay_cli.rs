use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use traffic_recording_store::writer::{JsonlBufferSettings, JsonlWriterPool, LedgerFiles};

#[path = "be_replay_cli/delegation.rs"]
mod delegation;
#[path = "be_replay_cli/worktrees.rs"]
mod worktrees;
use delegation::{assert_dispatch, bind_delivery, register_task};
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
    seal_events_for_window(recording, requests, &[]).await;
}

async fn seal_events_for_window(
    recording: &Path,
    requests: &[(u64, &str, &str)],
    dependency_offsets: &[u64],
) {
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
    for &at in dependency_offsets {
        offset = at;
        let dependency_sequence = sequence + 1;
        for mut row in [
            json!({"event_type":"capture_started", "dependency_sequence":dependency_sequence,
                "phase":"runtime"}),
            json!({"event_type":"wire_output", "dependency_sequence":dependency_sequence,
                "output":{"kind":"end"}}),
        ] {
            sequence += 1;
            row["sequence"] = json!(sequence);
            row["offset_micros"] = json!(offset);
            ledger
                .append_event(&mut stream, &serde_json::from_value(row).unwrap())
                .await
                .unwrap();
        }
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

fn allow_engine_retry(root: &Path, failed: &mut Value) {
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
    failed["engine_revision"] = json!("fixture-older-engine");
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
    let dispatch = status();
    assert_dispatch(&dispatch, "ownership_required", "issue-analyst");
    let analyst = register_task(root, &dispatch, "fixture-analyst");

    let report = recording.join("candidate.json");
    fs::write(
        &report,
        json!({"kind":"candidate", "task_id":"fixture-integrator-task", "agent_handle":"fixture-integrator",
            "attempt_id":first["attempt_id"], "commit":first["target_commit"],
            "included_fixes":[], "checks":["fixture checked"]})
            .to_string(),
    )
    .unwrap();
    let findings = recording.join("findings.json");
    fs::write(
        &findings,
        bind_delivery(
            json!({"ownership":{"seq":5,"scope":"startup","group":"startup"}}),
            &analyst,
        )
        .to_string(),
    )
    .unwrap();
    let plan = ["plan", "--findings", findings.to_str().unwrap()];
    let assigned = successful(command(root, &plan));
    assert_eq!(assigned["action"]["kind"], "dispatch_required");
    register_implementers(root);

    // Store a prior engine fingerprint on a failed attempt while keeping its
    // real sequence, Target revision and pending repair.
    allow_engine_retry(root, &mut first);
    let old_engine = first["engine_revision"].clone();
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
    assert_dispatch(&current, "ownership_required", "issue-analyst");
    assert_eq!(
        current["progress"],
        json!({"apis":"1/3","cases":"1/6","events":"6/9","previous_events":"4/9"})
    );
    assert!(!command(root, &["run"]).status.success());

    // Simulate falling back to the old engine for the latest attempt. A
    // fingerprint difference alone cannot reopen the consumed retry.
    next["engine_revision"] = old_engine;
    publish_mismatch(next, 7);
    assert_dispatch(&status(), "ownership_required", "issue-analyst");
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

    let analyst = register_task(root, &assignments(root), "fixture-analyst");
    let assigned = successful(plan(
        root,
        bind_delivery(
            json!({"ownership":{"seq":5,"scope":"startup","group":"startup"}}),
            &analyst,
        ),
    ));
    assert_eq!(assigned["action"]["kind"], "dispatch_required");
    let details = assignments(root);
    assert_eq!(group(&details, "startup")["items"][0]["scope"], "startup");

    let gap = json!({
        "kind":"engine_gap","group":"startup","sequences":[5],
        "assignment_id":group(&details, "startup")["assignment_id"],
        "evidence":"Source seq 5 and the Target observation show the same request."
    });
    assert!(!report(root, gap.clone()).status.success());
    register_implementers(root);
    let reported = successful(report(root, gap));
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

#[tokio::test]
async fn case_pattern_lookup_follows_the_source_cursor_across_methods() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    fs::write(
        root.join(".traffic-e2e/apis.yaml"),
        "users: [/users/*]\ncurrent: [/users/current]\n",
    )
    .unwrap();
    seal_events_with_apis(
        &recording_dir(root),
        &[
            (800, "GET", "/users/1?include=detail"),
            (900, "POST", "/users/current"),
            (1000, "POST", "/other"),
            (1100, "PUT", "/users/2"),
            (1200, "DELETE", "/users/3"),
        ],
    )
    .await;

    let lookup = |extra: &[&str]| {
        let mut args = vec![
            "apis",
            "--recording-run-id",
            RECORDING_ID,
            "--case-pattern",
            "/users/*",
            "--from-seq",
            "8",
            "--through-seq",
            "11",
        ];
        args.extend_from_slice(extra);
        successful(command(root, &args))
    };
    let first = lookup(&[]);
    assert_eq!(first["recording_id"], RECORDING_ID);
    assert_eq!(first["case_pattern"], "/users/*");
    assert_eq!(first["request"]["request_seq"], 8);
    assert_eq!(first["request"]["method"], "GET");
    assert_eq!(first["request"]["path"], "/users/1");
    assert_eq!(first["request"]["offset_micros"], 800);
    assert_eq!(first["next_after_sequence"], 8);
    let evidence = successful(command(
        root,
        &["events", "--recording-run-id", RECORDING_ID, "--seq", "8"],
    ));
    assert_eq!(
        first["request"]["exchange"],
        evidence["events"][0]["exchange"]
    );

    let next = lookup(&["--after-seq", "8"]);
    assert_eq!(next["request"]["request_seq"], 11);
    assert_eq!(next["request"]["method"], "PUT");
    assert_eq!(next["next_after_sequence"], 11);
    let exhausted = lookup(&["--after-seq", "11"]);
    assert!(exhausted["request"].is_null());
    assert!(exhausted["next_after_sequence"].is_null());
    assert!(!traffic_e2e::internal_runtime::root(root).exists());
}
