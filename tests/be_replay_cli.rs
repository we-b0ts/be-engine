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

fn git(target: &Path, args: &[&str]) {
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

#[test]
fn status_is_read_only_and_selects_the_latest_or_exact_failed_attempt() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    fs::create_dir_all(recording_dir(root)).unwrap();
    fs::write(
        root.join(".traffic-e2e/regression.yaml"),
        format!("recording_run_id: '{RECORDING_ID}'\n"),
    )
    .unwrap();
    let not_started = successful(command(root, &["status"]));
    assert_eq!(
        not_started,
        json!({"recording_id": RECORDING_ID, "state": "not_started", "session": null, "next": null})
    );
    assert!(!traffic_e2e::internal_runtime::root(root).exists());

    configure(root);
    let run = || {
        // The directory has no sealed manifest. Launch must record a setup
        // failure without trying to run Docker, even if API counts also fail.
        let output = command(root, &["run", "--run-key", "custom"]);
        assert!(!output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "missing run JSON: {error}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        });
        assert_eq!(result["session"]["passed"], false);
        assert!(result["session"]["error"].is_string());
        assert_eq!(result["next"]["action"], "inspect_session_setup");
        assert!(result["next"]["report"].is_null());
        assert!(result["api_counts_error"].is_string());
        result
    };
    let first = run();
    let second = run();
    let first_attempt = first["session"]["attempt_id"].as_str().unwrap();
    assert_ne!(
        first["session"]["attempt_id"],
        second["session"]["attempt_id"]
    );

    // Status continues to expose the saved attempt even if current launch
    // configuration has been removed.
    fs::remove_file(root.join(".traffic-e2e/policy.yaml")).unwrap();
    let latest = successful(command(root, &["status", "--run-key", "custom"]));
    assert_eq!(latest["state"], "failed");
    assert_eq!(latest["session"], second["session"]);
    assert_eq!(latest["next"], second["next"]);

    let history = successful(command(
        root,
        &[
            "--recording-run-id",
            RECORDING_ID,
            "status",
            "--run-key",
            "custom",
            "--attempt-id",
            first_attempt,
        ],
    ));
    assert_eq!(history["recording_id"], RECORDING_ID);
    assert_eq!(history["state"], "failed");
    assert_eq!(history["session"], first["session"]);
    assert_eq!(history["next"], first["next"]);
    assert_eq!(
        successful(command(root, &["status"]))["state"],
        "not_started"
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
async fn flat_events_and_plan_query_the_recording_without_starting_replay() {
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

    let findings = root.join("findings.json");
    fs::write(
        &findings,
        r#"[{"root_cause":"fixture","summary":"Source startup path",
             "kind":"target","basis":"source_proven","sequences":[2],
             "code_paths":["src/main.rs"]}]"#,
    )
    .unwrap();
    let plan = successful(command(
        root,
        &[
            "plan",
            "--findings",
            findings.to_str().unwrap(),
            "--recording-run-id",
            RECORDING_ID,
        ],
    ));
    assert_eq!(plan["implementers"][0]["root_cause"], "fixture");
    assert_eq!(plan["waiting"], json!([]));
    assert!(!traffic_e2e::internal_runtime::root(root).exists());
}
