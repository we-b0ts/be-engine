use std::time::Duration;
use std::{path::Path, path::PathBuf};

use anyhow::Result;

use super::model::RunStatus;

pub(super) fn status_label(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Successful => "passed",
        RunStatus::Failed => "failed",
        RunStatus::Interrupted => "interrupted",
        RunStatus::Running => "running",
        RunStatus::Finalizing => "finalizing",
    }
}

pub(super) fn api_directory(api_key: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in api_key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("api-{hash:016x}")
}

pub(super) fn allocate_replay_report(
    case_source: &Path,
    run_key: &str,
    attempt: &str,
) -> Result<PathBuf> {
    let report_dir = case_source
        .join(".replay/e2e-runs")
        .join(run_key)
        .join(format!("{attempt}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&report_dir)?;
    Ok(report_dir.join("replay-report.json"))
}

pub(super) fn allocate_control_socket() -> PathBuf {
    #[cfg(unix)]
    let temporary_root = PathBuf::from("/tmp");
    #[cfg(not(unix))]
    let temporary_root = std::env::temp_dir();

    temporary_root.join(format!("trp-e2e-{}.sock", uuid::Uuid::new_v4().simple()))
}

pub(super) async fn wait_for_pid_exit(pid: u32) {
    if wait_until_pid_exits(pid, 100).await {
        return;
    }
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(pid) {
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
    }
    if wait_until_pid_exits(pid, 40).await {
        return;
    }
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(pid) {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = wait_until_pid_exits(pid, 20).await;
}

async fn wait_until_pid_exits(pid: u32, attempts: usize) -> bool {
    for _ in 0..attempts {
        if !process_exists(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    !process_exists(pid)
}

pub(super) fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        let result = unsafe { libc::kill(pid, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_directory_is_stable_and_path_safe() {
        assert_eq!(
            api_directory("GET /api/widgets/*"),
            api_directory("GET /api/widgets/*")
        );
        assert_ne!(
            api_directory("GET /api/widgets/*"),
            api_directory("POST /api/widgets")
        );
        assert!(!api_directory("GET /api/widgets/*").contains('/'));
    }

    #[test]
    fn replay_report_uses_the_canonical_discoverable_filename() {
        let temporary = tempfile::tempdir().unwrap();
        let report = allocate_replay_report(temporary.path(), "run", "round-000001").unwrap();

        assert_eq!(
            report.file_name().and_then(|name| name.to_str()),
            Some("replay-report.json")
        );
        assert!(report.parent().unwrap().is_dir());
        assert!(report.starts_with(temporary.path().join(".replay/e2e-runs/run")));
    }

    #[cfg(unix)]
    #[test]
    fn control_socket_stays_below_unix_path_limit() {
        use std::os::unix::ffi::OsStrExt;

        let socket = allocate_control_socket();

        assert!(socket.starts_with("/tmp"));
        assert!(socket.as_os_str().as_bytes().len() < 100);
    }
}
