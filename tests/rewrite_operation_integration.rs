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

#[test]
fn detached_cli_operation_publishes_failure_and_status_does_not_restart_it() {
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
    // Deliberately fail before target execution: the workflow has no state.
    // This exercises the real sibling traffic-e2e child and its launch handoff.
    let launched = command(
        target.path(),
        &["target-quality", "run", "invalid-gate", "--api", "GET /api"],
    );
    assert_eq!(launched["schema_version"], 26);
    assert_eq!(launched["pending"], 0);
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
            .contains("not initialized")
    );
    let again = command(target.path(), &["status"]);
    assert_eq!(
        again["action"]["details"]["operation_id"],
        failed["action"]["details"]["operation_id"]
    );
    assert_eq!(again["action"]["commands"]["retry"]["argv"][3], "operation");
}
