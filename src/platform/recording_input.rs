use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use tracing::{info, warn};

use crate::config::DEFAULT_BODY_LIMIT_BYTES;
use crate::recorded_request::RecordedHttpClient;

const MAX_REQUEST_FILES: usize = 1_000;
const REQUEST_INTERVAL: Duration = Duration::from_millis(100);
const MAX_LOGGED_ERRORS: usize = 10;

#[derive(Debug, Clone)]
pub struct ManagedRecordingInputOptions {
    pub case_source: PathBuf,
    pub origin: String,
    pub request_timeout: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRecordingInputResult {
    pub request_templates: usize,
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
}

pub async fn drive_managed_recording_input(
    options: ManagedRecordingInputOptions,
) -> Result<ManagedRecordingInputResult> {
    let case_source = std::fs::canonicalize(&options.case_source).with_context(|| {
        format!(
            "failed to resolve managed recording input {}",
            options.case_source.display()
        )
    })?;
    let requests = discover_requests(&case_source)?;
    ensure!(
        !requests.is_empty(),
        "managed recording input contains no request.json files"
    );
    let client = RecordedHttpClient::new_recording_input(
        options.origin,
        options.request_timeout,
        DEFAULT_BODY_LIMIT_BYTES,
    );
    let mut attempted = 0_usize;
    let mut succeeded = 0_usize;
    let mut failed = 0_usize;
    let mut logged_errors = 0_usize;
    let request_templates = requests.len();
    let mut pending = VecDeque::from(requests);
    let shutdown = super::shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        let Some(request_path) = pending.pop_front() else {
            shutdown.as_mut().await?;
            break;
        };
        attempted = attempted.saturating_add(1);
        let response = tokio::select! {
            signal = &mut shutdown => {
                signal?;
                break;
            }
            response = client.send(&request_path) => response,
        };
        match response {
            Ok(_) => succeeded = succeeded.saturating_add(1),
            Err(error) => {
                failed = failed.saturating_add(1);
                pending.push_back(request_path);
                if logged_errors < MAX_LOGGED_ERRORS {
                    warn!(%error, "managed recording request input failed");
                    logged_errors += 1;
                }
            }
        }
        tokio::select! {
            signal = &mut shutdown => {
                signal?;
                break;
            }
            () = tokio::time::sleep(REQUEST_INTERVAL) => {}
        }
    }
    ensure!(
        succeeded > 0,
        "managed recording input did not deliver any request successfully"
    );
    info!(
        attempted,
        succeeded, failed, "managed recording input stopped"
    );
    Ok(ManagedRecordingInputResult {
        request_templates,
        attempted,
        succeeded,
        failed,
    })
}

fn discover_requests(case_source: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![case_source.to_path_buf()];
    let mut requests = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .with_context(|| format!("failed to read case directory {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "managed recording input must not contain symlinks: {}",
                path.display()
            );
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && path.file_name().is_some_and(|name| name == "request.json")
            {
                requests.push(path);
                ensure!(
                    requests.len() <= MAX_REQUEST_FILES,
                    "managed recording input exceeds {MAX_REQUEST_FILES} request templates"
                );
            }
        }
    }
    requests.sort();
    Ok(requests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_requests_in_stable_order_and_rejects_unbounded_inputs() {
        let root = tempfile::tempdir().unwrap();
        for name in ["case-b", "case-a"] {
            let case = root.path().join(name);
            std::fs::create_dir_all(&case).unwrap();
            std::fs::write(case.join("request.json"), b"{}").unwrap();
            std::fs::write(case.join("expected-response.json"), b"{}").unwrap();
        }

        let requests = discover_requests(root.path()).unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0] < requests[1]);
    }
}
