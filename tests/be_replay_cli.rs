use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use traffic_recording_store::writer::{JsonlBufferSettings, JsonlWriterPool, LedgerFiles};

const RECORDING_ID: &str = "20261125131020";

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
async fn status_starts_a_new_round_on_approval_and_preserves_attempt_history() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let recording = recording_dir(root);
    seal_events(&recording).await;
    let not_started = successful(command(root, &["status"]));
    assert_eq!(not_started["next"]["action"], "select_recording");
    assert_eq!(not_started["next"]["recording_ids"], json!([RECORDING_ID]));
    let confirm = successful(command(
        root,
        &["status", "--recording-run-id", RECORDING_ID],
    ));
    assert_eq!(confirm["next"]["action"], "confirm_regression");
    assert_eq!(confirm["branch"], "dev-migration");
    assert_eq!(confirm["next"]["requires_user_confirmation"], true);
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
        assert_eq!(result["next"]["action"], "inspect_session_setup");
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
    assert_eq!(latest["session"], second["session"]);
    assert_eq!(latest["next"], second["next"]);
    let historical = successful(command(root, &["status", "--attempt-id", first_id]));
    assert_eq!(historical["session"], first["session"]);
    assert!(historical["next"].is_null());

    git(root, &["switch", "dev-migration"]);
    let fresh = successful(command(
        root,
        &["status", "--recording-run-id", RECORDING_ID],
    ));
    assert_eq!(fresh["next"]["action"], "confirm_regression");
    assert!(fresh["session"].is_null());
    git(root, &["switch", &branch]);
    assert_eq!(
        successful(command(root, &["status"]))["session"],
        second["session"]
    );
}

async fn seal_events(recording: &Path) {
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
    for (index, (dependency, mut row)) in [
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
        (false, json!({"event_type": "stop"})),
        (false, json!({"event_type": "source_exit", "status": 0})),
    ]
    .into_iter()
    .enumerate()
    {
        row["sequence"] = json!(index + 1);
        row["offset_micros"] = json!(index * 100);
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
    let files = ledger.seal(&mut stream).await.unwrap();
    let manifest = json!({
        "schema": "traffic-recording/v13", "run_id": RECORDING_ID,
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

#[tokio::test]
async fn reviewed_fixes_and_candidate_receipts_advance_status() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let recording = recording_dir(root);
    seal_events(&recording).await;
    fs::write(recording.join("events.tsv"), b"broken\n").unwrap();
    let output = command(
        root,
        &["run", "--user-confirm", "--recording-run-id", RECORDING_ID],
    );
    assert!(!output.status.success());
    let initial: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "missing run result: {error}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
    let mut failed = initial["session"].clone();
    // Simulate the matching engine's persisted mismatch without invoking Docker.
    failed["events"] = json!({"total":9, "matched":4, "complete":false, "last_sequence":4,
        "expected":{"sequence":5}, "failure":{"reason":"fixture mismatch"}});
    let attempt_file =
        Path::new(failed["progress"].as_str().unwrap()).with_file_name("event-result.json");
    fs::write(&attempt_file, serde_json::to_vec(&failed).unwrap()).unwrap();
    let attempt_id = failed["attempt_id"].as_str().unwrap();
    let status = || successful(command(root, &["status"]));
    assert_eq!(status()["next"]["expected_sequence"], 5);

    let findings = recording.join("findings.json");
    fs::write(
        &findings,
        serde_json::to_vec(&json!([{
            "root_cause":"fixture", "summary":"Source dependency path",
            "kind":"target", "basis":"reproduced", "sequences":[5], "code_paths":["target.txt"]
        }]))
        .unwrap(),
    )
    .unwrap();
    let plan = successful(command(
        root,
        &[
            "plan",
            "--attempt-id",
            attempt_id,
            "--findings",
            findings.to_str().unwrap(),
        ],
    ));
    assert_eq!(plan["implementers"][0]["root_cause"], "fixture");
    assert_eq!(status()["next"]["action"], "implement_fixes");

    let branch = git(root, &["branch", "--show-current"]);
    git(root, &["switch", "-c", "implementer"]);
    fs::write(root.join("target.txt"), "fixed").unwrap();
    git(root, &["add", "target.txt"]);
    git(root, &["commit", "-qm", "fixture fix"]);
    let commit = git(root, &["rev-parse", "HEAD"]);
    git(root, &["switch", &branch]);

    let receipt = recording.join("receipt.json");
    let report = |receipt_value: Value| {
        fs::write(&receipt, serde_json::to_vec(&receipt_value).unwrap()).unwrap();
        command(root, &["report", "--file", receipt.to_str().unwrap()])
    };
    let fixes = successful(report(
        json!({"kind":"fixes", "attempt_id":attempt_id, "fixes":[{
            "root_cause":"fixture", "commit":commit, "checks":["focused checks passed"]
        }]}),
    ));
    assert_eq!(fixes["next"]["action"], "integrate_candidate");
    assert_eq!(status()["next"], fixes["next"]);
    let candidate = json!({"kind":"candidate", "attempt_id":attempt_id, "commit":commit,
        "included_fixes":[commit], "checks":["integration checks passed"]});
    assert!(!report(candidate.clone()).status.success());
    git(root, &["merge", "--ff-only", &commit]);
    let mut stale = candidate.clone();
    stale["attempt_id"] = json!(uuid::Uuid::new_v4());
    assert!(!report(stale).status.success());
    let registered = successful(report(candidate));
    assert_eq!(registered["next"]["action"], "verify_candidate");
    assert_eq!(status()["next"], registered["next"]);

    let rerun = command(root, &["run"]);
    assert!(!rerun.status.success());
    let new_attempt: Value = serde_json::from_slice(&rerun.stdout).unwrap();
    assert_eq!(new_attempt["session"]["target_commit"], commit);
    assert_ne!(new_attempt["session"]["attempt_id"], attempt_id);
    assert_eq!(status()["next"]["action"], "inspect_session_setup");

    let mut passed = new_attempt["session"].clone();
    passed["passed"] = json!(true);
    passed["error"] = Value::Null;
    passed["events"] = json!({"complete":true,"total":9,"matched":9,"last_sequence":9});
    let result =
        Path::new(passed["progress"].as_str().unwrap()).with_file_name("event-result.json");
    fs::write(result, serde_json::to_vec(&passed).unwrap()).unwrap();
    let verified = status();
    assert_eq!(verified["state"], "passed");
    assert!(verified["next"].is_null());
    fs::write(root.join("target.txt"), "new unverified input").unwrap();
    let changed = status();
    assert_eq!(changed["state"], "candidate_changed");
    assert_eq!(changed["next"]["action"], "run_regression");
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
