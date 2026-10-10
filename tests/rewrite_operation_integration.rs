use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

fn command(target: &std::path::Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_backend-rewrite"))
        .arg("--target-root")
        .arg(target)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn configured_target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    fs::create_dir_all(target.path().join("config")).unwrap();
    fs::write(
        target.path().join(".traffic-e2e/project.yaml"),
        include_str!("manual/readonly/project.yaml"),
    )
    .unwrap();
    fs::write(
        target
            .path()
            .join(".traffic-e2e/source-traffic-policy.yaml"),
        include_str!("manual/readonly/source-traffic-policy.yaml"),
    )
    .unwrap();
    fs::write(
        target.path().join("config/verification.example.yaml"),
        include_str!("../config/verification.example.yaml"),
    )
    .unwrap();
    for args in [
        vec!["init", "-q", "-b", "dev-migration"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "fixture",
        ],
        vec!["switch", "-qc", "feature"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    target
}

#[test]
fn detached_cli_operation_publishes_failure_and_status_does_not_restart_it() {
    let target = configured_target();
    let runtime = target.path().join(".traffic-e2e/local/runtime/rewrite");
    fs::create_dir_all(&runtime).unwrap();
    fs::write(
        runtime.join("state.json"),
        serde_json::to_vec(&serde_json::json!({
            "version": 1, "revision": 1, "workflow_id": "rewrite-route-fixture",
            "recording_run_id": "recording-fixture", "phase": "api_pending",
            "api": "GET /api", "source_route": "/api", "attempts": [],
            "e2e_current": false,
            "api_inventory": [{"api": "GET /api", "status": "active", "source_route": "/api"}],
            "current_api_index": 0
        }))
        .unwrap(),
    )
    .unwrap();
    // Deliberately fail Next's source-route validation before target execution.
    // This exercises the real sibling traffic-e2e child and its launch handoff;
    // quality receipt admission itself is synchronous and no longer launches one.
    let launched = command(
        target.path(),
        &["next", "--api", "/api", "--source-route", "/wrong-route"],
    );
    assert_eq!(launched["schema_version"], 35);
    assert_eq!(
        launched["pending"],
        if launched["action"]["kind"] == "wait_required" {
            1
        } else {
            0
        }
    );
    assert!(matches!(
        launched["action"]["kind"].as_str(),
        Some("wait_required" | "execution_failed")
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    let failed = loop {
        let status = command(target.path(), &["status"]);
        if status["action"]["kind"] == "execution_failed" {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "operation did not finish: {status}"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(failed["pending"], 0);
    assert_eq!(failed["terminal_allowed"], false);
    assert!(
        failed["action"]["summary"]
            .as_str()
            .unwrap()
            .contains("requires its canonical source route")
    );
    let again = command(target.path(), &["status"]);
    assert_eq!(
        again["action"]["details"]["operation_id"],
        failed["action"]["details"]["operation_id"]
    );
    assert_eq!(again["action"]["commands"]["retry"]["argv"][3], "operation");
}

#[test]
fn detached_unscoped_next_activates_idle_revalidation_while_an_api_is_blocked() {
    let target = configured_target();
    let runtime = target.path().join(".traffic-e2e/local/runtime/rewrite");
    fs::create_dir_all(&runtime).unwrap();
    // A versioned engine fixture with a recorded dynamic pattern but no legacy
    // source-route binding. Activation must adopt the pattern and proceed until
    // the deliberately absent recording fixture stops execution.
    let state = serde_json::json!({
        "version": 1, "revision": 1, "workflow_id": "rewrite-idle-fixture",
        "recording_run_id": "recording-fixture", "phase": "system_repair_required",
        "api": "GET /repair", "source_route": "/repair", "attempts": [],
        "e2e_current": false,
        "active_issue": {
            "id": "fixture-issue", "kind": "dependency", "owner": "traffic_e2e_system",
            "summary": "fixture external repair", "observed_target_fingerprint": "old-target", "attempt": 1
        },
        "route": {
            "kind": "replay_capability_gap", "repair_id": "fixture-repair",
            "evidence_id": "fixture-evidence", "source_ref": "src/replay.rs:1",
            "required_change": "fixture system repair"
        },
        "api_inventory": [
            {"api": "GET /repair", "status": "active", "source_route": "/repair"},
            {"api": "GET /revalidate/*", "status": "revalidation_pending"}
        ], "current_api_index": 0
    });
    fs::write(
        runtime.join("state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    let before = command(target.path(), &["status"]);
    assert_eq!(before["pending"], 1);
    assert_eq!(
        before["action"]["commands"]["advance"]["argv"][5],
        "/revalidate/*"
    );
    let launched = command(target.path(), &["next"]);
    assert_eq!(launched["action"]["kind"], "wait_required");
    assert_eq!(launched["pending"], 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = command(target.path(), &["status"]);
        if status["action"]["kind"] == "execution_failed" {
            assert!(
                status["action"]["summary"]
                    .as_str()
                    .unwrap()
                    .contains("recording-fixture")
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "idle revalidation did not advance: {status}"
        );
        assert_ne!(status["action"]["kind"], "input_required", "{status}");
        std::thread::sleep(Duration::from_millis(50));
    }
    let saved: Value =
        serde_json::from_slice(&fs::read(runtime.join("state.json")).unwrap()).unwrap();
    assert_eq!(saved["api"], "GET /revalidate/*");
    assert_eq!(saved["phase"], "api_pending");
    assert_eq!(saved["source_route"], "/revalidate/*");
    assert_eq!(saved["api_inventory"][1]["source_route"], "/revalidate/*");
    assert_eq!(
        saved["parked_slices"]["GET /repair"]["route"],
        state["route"]
    );
    assert_eq!(
        saved["api_inventory"][0]["status"],
        "system_repair_required"
    );
    let waited = command(target.path(), &["wait", "--seconds", "1"]);
    assert_eq!(waited["action"]["kind"], "worker_events_required");
    assert_eq!(waited["action"]["commands"]["status"]["argv"][3], "status");
}

#[test]
fn cli_status_returns_purpose_and_confirmation_enters_an_engine_named_branch() {
    let target = configured_target();
    let switch_base = || {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(["switch", "-q", "dev-migration"])
                .status()
                .unwrap()
                .success()
        )
    };
    switch_base();
    let first = command(target.path(), &["status"]);
    assert_eq!(first["action"]["kind"], "purpose_required");
    let confirmed = command(
        target.path(),
        &[
            "purpose",
            "confirm",
            "--purpose",
            "record",
            "--user-approved",
            "--active-agent-count",
            "0",
            "--runtime-query-command",
            "test_runtime.list_current_session_agents",
            "--runtime-query-at",
            "2026-09-12T09:00:00Z",
        ],
    );
    let branch = confirmed["work_branch"].as_str().unwrap();
    assert!(branch.starts_with("record/"));
    assert!(branch.ends_with("-1"));
    let current = Command::new("git")
        .arg("-C")
        .arg(target.path())
        .args(["branch", "--show-current"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(current.stdout).unwrap().trim(), branch);
    assert_eq!(confirmed["next"]["action"]["kind"], "input_required");
    assert_eq!(
        command(target.path(), &["status"])["action"]["kind"],
        "input_required"
    );
    switch_base();
    assert_eq!(
        command(target.path(), &["status"])["action"]["kind"],
        "purpose_required"
    );
}
