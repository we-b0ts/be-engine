use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use traffic_recording_store::writer::{JsonlBufferSettings, JsonlWriterPool, LedgerFiles};

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
async fn status_starts_a_new_round_on_approval_and_preserves_attempt_history() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let recording = recording_dir(root);
    seal_events(&recording).await;
    let not_started = successful(command(root, &["status"]));
    assert_eq!(not_started["action"]["kind"], "select_recording");
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
        confirm["action"]["commands"]["run"],
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
        pending["action"]["commands"]["switch"],
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
    let output = command(root, args);
    assert!(!output.status.success());
    serde_json::from_slice::<Value>(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "missing run result: {error}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    })["session"]
        .clone()
}

#[tokio::test]
async fn first_unmatched_group_advances_replay_while_other_work_keeps_its_assignment() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let recording = recording_dir(root);
    seal_events(&recording).await;
    // Run up to the sealed input check and simulate the matching engine's
    // published failures. This exercises real CLI and Git without Docker.
    fs::write(recording.join("events.tsv"), b"broken\n").unwrap();
    let failed_run = |args: &[&str]| run_attempt_with_invalid_source(root, args);
    let initial = failed_run(&["run", "--user-confirm", "--recording-run-id", RECORDING_ID]);
    publish_mismatch(initial.clone(), 5);
    let attempt_id = initial["attempt_id"].as_str().unwrap();
    let status = || successful(command(root, &["status"]));
    let failure = status();
    assert_eq!(
        failure["failure"],
        json!({"seq":5,"expected":{"kind":"request","dependency_sequence":5},
            "reason":"fixture mismatch","target_observation_id":uuid::Uuid::from_u128(2)})
    );
    assert_eq!(failure["action"]["kind"], "analysis_required");
    assert_eq!(failure["action"]["details"]["role"], "issue-analyst");
    assert_eq!(failure["phase"], "replaying");
    assert_eq!(failure["progress"], json!({"apis":"1/3","events":"4/9"}));
    let plan_command = &failure["action"]["commands"];
    assert_eq!(plan_command.as_object().unwrap().len(), 1);
    assert_eq!(
        plan_command["plan"],
        json!([
            "plan",
            "--attempt-id",
            attempt_id,
            "--findings",
            "<findings.json>"
        ])
    );
    let blocked = command(root, &["run"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("submit reviewed findings"));
    assert_eq!(status(), failure);

    let findings = recording.join("findings.json");
    let submit_findings = |attempt_id: &str, findings_value: Value| {
        fs::write(&findings, serde_json::to_vec(&findings_value).unwrap()).unwrap();
        command(
            root,
            &[
                "plan",
                "--attempt-id",
                attempt_id,
                "--findings",
                findings.to_str().unwrap(),
            ],
        )
    };
    let later = json!({"root_cause":"later", "summary":"Independent Source dependency",
        "scope":"job:sync_users", "sequences":[3,7]});
    let first = json!({"root_cause":"first", "summary":"First Source dependency",
        "scope":"api:GET /users/{id}", "sequences":[5]});
    let missing_first = submit_findings(attempt_id, json!({"others":[later]}));
    assert!(!missing_first.status.success());
    for (field, value) in [
        ("code_paths", json!(["first.txt"])),
        ("blocked_by", json!(["later"])),
    ] {
        let mut obsolete = first.clone();
        obsolete[field] = value;
        let rejected = submit_findings(attempt_id, json!({"first_unmatched":obsolete}));
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("unknown field"));
    }
    assert_eq!(status(), failure);
    let initial_plan = successful(submit_findings(
        attempt_id,
        json!({"first_unmatched":first}),
    ));
    assert_eq!(initial_plan["implementers"].as_array().unwrap().len(), 1);
    let planned = successful(submit_findings(attempt_id, json!({"others":[later]})));
    assert_eq!(planned["implementers"].as_array().unwrap().len(), 2);
    assert_eq!(planned["implementers"][0]["root_cause"], "first");
    assert_eq!(planned["implementers"][0]["scope"], "api:GET /users/{id}");
    assert!(planned["implementers"][0].get("evidence").is_none());
    assert_eq!(planned["action"]["details"]["first_unmatched"], "first");
    assert_eq!(status()["action"]["kind"], "implementation_required");

    seal_events(&recording.with_file_name(OTHER_RECORDING_ID)).await;
    let switched = successful(command(root, &["switch-recording-id", OTHER_RECORDING_ID]));
    assert_eq!(switched["state"], "not_started");
    assert!(switched["session"].is_null());
    let restored = successful(command(root, &["switch-recording-id", RECORDING_ID]));
    assert_eq!(restored["action"], planned["action"]);

    let branch = git(root, &["branch", "--show-current"]);
    let first_commit = fixture_fix(root, "worker-first", "first.txt", &branch);
    let later_commit = fixture_fix(root, "worker-later", "later.txt", &branch);
    let receipt = recording.join("receipt.json");
    let report = |receipt_value: Value| {
        fs::write(&receipt, serde_json::to_vec(&receipt_value).unwrap()).unwrap();
        command(root, &["report", "--file", receipt.to_str().unwrap()])
    };
    let deliver = |attempt_id: &str, cause: &str, commit: &str| {
        successful(report(
            json!({"kind":"fixes", "attempt_id":attempt_id, "fixes":[{
                "root_cause":cause, "commit":commit, "checks":["focused checks passed"]
            }]}),
        ))
    };
    let candidate = |attempt_id: &str, head: &str, commit: &str| {
        json!({"kind":"candidate", "attempt_id":attempt_id, "commit":head,
            "included_fixes":[commit], "checks":["integration checks passed"]})
    };
    let fixes = deliver(attempt_id, "first", &first_commit);
    assert_eq!(fixes["action"]["kind"], "integration_required");
    assert_eq!(
        fixes["action"]["details"]["fixes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(status()["action"], fixes["action"]);
    assert!(
        !report(candidate(attempt_id, &first_commit, &first_commit))
            .status
            .success()
    );
    git(root, &["merge", "--ff-only", &first_commit]);
    let unrelated_attempt = uuid::Uuid::new_v4().to_string();
    assert!(
        !report(candidate(&unrelated_attempt, &first_commit, &first_commit))
            .status
            .success()
    );
    let registered = successful(report(candidate(attempt_id, &first_commit, &first_commit)));
    assert_eq!(registered["action"]["kind"], "advance_required");
    assert_eq!(status()["action"], registered["action"]);

    let second = failed_run(&["run"]);
    assert_eq!(second["target_commit"], first_commit);
    let second_id = second["attempt_id"].as_str().unwrap();
    assert_ne!(second_id, attempt_id);
    assert_eq!(status()["action"]["kind"], "setup_required");
    publish_mismatch(second.clone(), 7);
    assert_eq!(status()["action"]["kind"], "analysis_required");
    assert_eq!(status()["failure"]["seq"], 7);

    let late_delivery = deliver(attempt_id, "later", &later_commit);
    assert_eq!(late_delivery["action"]["kind"], "analysis_required");
    let planned = successful(submit_findings(second_id, json!({"first_unmatched":later})));
    let integration = &planned["action"];
    assert_eq!(integration["kind"], "integration_required");
    assert_eq!(integration["details"]["fixes"][0]["attempt_id"], attempt_id);
    assert_eq!(integration["details"]["fixes"][0]["commit"], later_commit);

    git(root, &["cherry-pick", &later_commit]);
    let head = git(root, &["rev-parse", "HEAD"]);
    let registered = successful(report(candidate(second_id, &head, &later_commit)));
    assert_eq!(registered["action"]["kind"], "advance_required");
    let mut passed = failed_run(&["run"]);
    assert_eq!(passed["target_commit"], head);
    passed["passed"] = json!(true);
    passed["error"] = Value::Null;
    passed["phase"] = json!("complete");
    passed["events"] = json!({"complete":true,"total":6,"matched":6,"last_sequence":8});
    persist_attempt(&passed);
    let verified = status();
    assert_eq!(verified["state"], "passed");
    assert_eq!(verified["progress"]["events"], "9/9");
    assert_eq!(verified["action"]["kind"], "complete");
    assert!(verified.get("failure").is_none());
    fs::write(root.join("later.txt"), "new unverified input").unwrap();
    let changed = status();
    assert_eq!(changed["state"], "candidate_changed");
    assert_eq!(changed["action"]["kind"], "advance_required");
}

#[tokio::test]
async fn an_assigned_implementer_can_escalate_the_first_unmatched_group() {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    configure(root);
    let recording = recording_dir(root);
    seal_events(&recording).await;
    fs::write(recording.join("events.tsv"), b"broken\n").unwrap();
    let run = run_attempt_with_invalid_source(
        root,
        &["run", "--user-confirm", "--recording-run-id", RECORDING_ID],
    );
    publish_mismatch(run.clone(), 5);

    let findings = recording.join("findings.json");
    fs::write(
        &findings,
        json!({"first_unmatched":{
            "root_cause":"first", "summary":"Missing interaction", "scope":"startup", "sequences":[5]
        }})
        .to_string(),
    )
    .unwrap();
    let plan = |attempt: &Value| {
        successful(command(
            root,
            &[
                "plan",
                "--attempt-id",
                attempt["attempt_id"].as_str().unwrap(),
                "--findings",
                findings.to_str().unwrap(),
            ],
        ))
    };
    let assigned = plan(&run);
    assert_eq!(assigned["action"]["kind"], "implementation_required");
    assert_eq!(assigned["implementers"][0]["scope"], "startup");

    let file = recording.join("engine-gap.json");
    fs::write(
        &file,
        json!({"kind":"engine_gap", "attempt_id":run["attempt_id"], "root_cause":"first",
            "evidence":"Source seq 5 and the Target observation show the same request."})
        .to_string(),
    )
    .unwrap();
    let reported = successful(command(root, &["report", "--file", file.to_str().unwrap()]));
    assert_eq!(reported["action"]["kind"], "setup_required");
    assert_eq!(
        successful(command(root, &["status"]))["action"],
        reported["action"]
    );

    let retry = run_attempt_with_invalid_source(root, &["run"]);
    assert_ne!(retry["attempt_id"], run["attempt_id"]);
    assert_eq!(retry["target_commit"], run["target_commit"]);
    publish_mismatch(retry.clone(), 5);
    assert_eq!(plan(&retry)["action"]["kind"], "implementation_required");
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
