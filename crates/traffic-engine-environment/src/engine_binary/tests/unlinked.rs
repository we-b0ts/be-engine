//! Exercise Linux's real deleted-executable behavior with a private test link.
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Stdio,
    time::Duration,
};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const STAGE: &str = "TRAFFIC_E2E_UNLINKED_EXECUTABLE_TEST";
const INODE: &str = "TRAFFIC_E2E_UNLINKED_EXECUTABLE_INODE";
const TEST: &str =
    "engine_binary::tests::unlinked::running_engine_can_spawn_after_atomic_replacement";

#[tokio::test]
async fn running_engine_can_spawn_after_atomic_replacement() {
    match std::env::var(STAGE).as_deref() {
        Ok("verify") => {
            let inode = fs::metadata("/proc/self/exe").unwrap().ino();
            assert_eq!(inode.to_string(), std::env::var(INODE).unwrap());
            return;
        }
        Ok("probe") => {
            println!("\nprobe_ready");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let current = std::env::current_exe().unwrap();
            assert_eq!(current.file_name().unwrap(), "traffic-e2e (deleted)");
            let executable = crate::engine_binary::executable().unwrap();
            assert_eq!(
                executable,
                std::path::PathBuf::from(format!("/proc/{}/exe", std::process::id()))
            );
            let output = std::process::Command::new(executable)
                .args(["--exact", TEST, "--nocapture"])
                .env(STAGE, "verify")
                .env(
                    INODE,
                    fs::metadata("/proc/self/exe").unwrap().ino().to_string(),
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "reexec failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        _ => {}
    }

    let current = std::env::current_exe().unwrap();
    let root = tempfile::tempdir_in(current.parent().unwrap()).unwrap();
    let executable = root.path().join("traffic-e2e");
    // Avoid a writable executable descriptor being inherited by another test's
    // concurrent fork. Only this private link is replaced; the test binary stays.
    fs::hard_link(current, &executable).unwrap();
    let mut child = tokio::process::Command::new(&executable)
        .args(["--exact", TEST, "--nocapture"])
        .env(STAGE, "probe")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("probe exited early");
            if line == "probe_ready" {
                break;
            }
        }
    })
    .await
    .expect("probe did not start");
    // A new executable now occupies the installed path. Reexec must retain the
    // running engine's inode instead of launching this different replacement.
    let replacement = root.path().join("replacement");
    fs::write(&replacement, "#!/bin/sh\nexit 91\n").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(replacement, executable).unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"continue\n")
        .await
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("probe did not finish")
        .unwrap();
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
