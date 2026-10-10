use std::process::Command;

use super::*;

#[test]
fn comparison_skips_the_probe_that_releases_its_listener() {
    assert!(ManagedRuntimeOperation::Preflight.requires_listener_preflight());
    assert!(!ManagedRuntimeOperation::Comparison.requires_listener_preflight());
}

#[test]
fn comparison_readiness_returns_the_child_failure_without_waiting_for_timeout() {
    let temp = tempfile::tempdir().unwrap();
    let readiness = temp.path().join("readiness");
    let comparison = temp.path().join("comparison");
    let harness = temp.path().join("harness.sh");
    write_asset(&readiness, "#!/usr/bin/env bash\nsleep 30\n", 0o700).unwrap();
    write_asset(&comparison, "#!/usr/bin/env bash\nexit 23\n", 0o700).unwrap();
    let readiness_function = MANAGER
        .split_once("wait_for_comparison_ready() {")
        .unwrap()
        .1
        .split_once("\n}\n\nwait_for_comparison_exit()")
        .unwrap()
        .0;
    let script = format!(
        "#!/usr/bin/env bash\nset -Eeuo pipefail\n\
         TRAFFIC_E2E_BIN=$1\ncomparison_pid=\"\"\n\
         wait_for_comparison_ready() {{{readiness_function}\n}}\n\
         \"$2\" &\ncomparison_pid=$!\nset +e\n\
         wait_for_comparison_ready /tmp/missing-comparison-control.sock\n\
         status=$?\nset -e\n[[ \"$status\" == 23 ]]\n[[ -z \"$comparison_pid\" ]]\n"
    );
    write_asset(&harness, &script, 0o700).unwrap();

    let status = Command::new("timeout")
        .args(["2", "bash"])
        .arg(&harness)
        .arg(&readiness)
        .arg(&comparison)
        .status()
        .unwrap();

    assert!(status.success());
}

fn check_comparison_exit(comparison: &str, input: Option<&str>, assertions: &str) {
    let temp = tempfile::tempdir().unwrap();
    let harness = temp.path().join("harness.sh");
    let function = MANAGER
        .split_once("wait_for_comparison_exit() {")
        .unwrap()
        .1
        .split_once("\n}\n\nrun_comparison_recording()")
        .unwrap()
        .0;
    let input_start = input.map_or(String::new(), |command| {
        format!("( {command} ) &\ninput_pid=$!\nchildren+=(\"$input_pid\")\n")
    });
    let script = format!(
        "#!/usr/bin/env bash\nset -Eeuo pipefail\n\
         children=()\ninput_pid=\"\"\n\
         trap 'for child in \"${{children[@]}}\"; do kill -TERM \"$child\" 2>/dev/null || true; wait \"$child\" 2>/dev/null || true; done' EXIT\n\
         wait_for_comparison_exit() {{{function}\n}}\n\
         ( {comparison} ) &\ncomparison_pid=$!\nchildren+=(\"$comparison_pid\")\n\
         {input_start}\nstatus=0\nwait_for_comparison_exit || status=$?\n\
         {assertions}\n"
    );
    write_asset(&harness, &script, 0o700).unwrap();
    let output = Command::new("timeout")
        .args(["3", "bash"])
        .arg(&harness)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn comparison_input_failure_returns_immediately_and_retains_comparison_for_cleanup() {
    check_comparison_exit(
        "exec sleep 30",
        Some("exit 23"),
        "[[ $status == 23 ]]; [[ -z $input_pid ]]; kill -0 \"$comparison_pid\"",
    );
}

#[test]
fn completed_input_still_waits_for_comparison_publication_and_returns_its_status() {
    check_comparison_exit(
        "sleep 0.3; exit 17",
        Some("exit 0"),
        "[[ $status == 17 ]]; [[ -z $comparison_pid ]]",
    );
}

#[test]
fn comparison_without_managed_input_can_finish_normally() {
    check_comparison_exit(
        "sleep 0.1; exit 0",
        None,
        "[[ $status == 0 ]]; [[ -z $comparison_pid ]]",
    );
}

#[test]
fn comparison_failure_does_not_wait_for_running_input() {
    check_comparison_exit(
        "exit 19",
        Some("exec sleep 30"),
        "[[ $status == 19 ]]; [[ -z $comparison_pid ]]; kill -0 \"$input_pid\"",
    );
}
