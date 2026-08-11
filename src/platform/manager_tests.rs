use std::process::Command;

use super::*;

#[test]
fn comparison_skips_the_probe_that_releases_its_listener() {
    assert!(
        ManagedRuntimeOperation::Recording(ManagedRecordingOperation::Record)
            .requires_listener_preflight()
    );
    assert!(ManagedRuntimeOperation::Preflight.requires_listener_preflight());
    assert!(
        !ManagedRuntimeOperation::Recording(ManagedRecordingOperation::RecordComparison)
            .requires_listener_preflight()
    );
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
        .split_once("\n}\n\nrun_comparison_recording()")
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
