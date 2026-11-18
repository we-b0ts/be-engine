#[cfg(any(test, feature = "test-support"))]
use std::collections::BTreeSet;
#[cfg(any(test, feature = "test-support"))]
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(any(test, feature = "test-support"))]
use anyhow::ensure;
use anyhow::{Context, Result};
use serde_json::Value;

use super::model::*;
use traffic_recording_store::source::store::check_cancelled;
#[cfg(test)]
pub(super) use traffic_recording_store::source::store::file_cache_directory;
pub use traffic_recording_store::source::store::{
    cache_directory, private_directory, read_json, write_json,
};

/// The same completed standard-run boundary for all indexed protocol queries.
pub fn recording_files(source: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    if let Some(root) = super::recording::root(source) {
        return super::recording::cases(&root);
    }
    #[cfg(not(any(test, feature = "test-support")))]
    anyhow::bail!(
        "recording requires the current central dependency manifest; old recording semantics are unsupported"
    );
    #[cfg(any(test, feature = "test-support"))]
    {
        let source = fs::canonicalize(source)?;
        let root = source
            .ancestors()
            .find(|p| p.join("recording-run.json").is_file())
            .context("cross-case requires a recording-run.json boundary")?
            .to_path_buf();
        let manifest: Value = serde_json::from_slice(&fs::read(root.join("recording-run.json"))?)?;
        ensure!(
            manifest["status"] == "completed",
            "cross-case requires a completed standard recording run"
        );
        let mut pending = vec![root.clone()];
        let mut files = Vec::new();
        while let Some(dir) = pending.pop() {
            if dir != root && dir.join("recording-run.json").exists() {
                continue;
            }
            let file = dir.join("dependencies.jsonl");
            if file.is_file() {
                FileStamp::read(&file)?;
                files.push(file);
                continue;
            }
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with('.') && !matches!(&*name, "failed" | "staging") {
                    pending.push(entry.path());
                }
            }
        }
        files.sort();
        let mut ids = BTreeSet::new();
        for file in &files {
            ensure!(ids.insert(case_id(file)?), "duplicate cross-case case id");
        }
        Ok((root, files))
    }
}

#[cfg(any(test, feature = "test-support"))]
fn case_id(path: &Path) -> Result<String> {
    Ok(path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .context("dependency file has no case identity")?
        .into())
}

pub fn load_file(path: &Path) -> Result<FileIndex> {
    load_file_cancellable(path, &std::sync::atomic::AtomicBool::new(false))
}

fn load_file_cancellable(
    path: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<FileIndex> {
    traffic_recording_store::source::index::load_file(
        path,
        cancelled,
        crate::protocols::default_providers().evidence(),
        super::proof::is_evidence,
    )
}

pub fn prepare(
    source: &Path,
    validate: fn(&Value) -> Result<()>,
) -> Result<(RunIndex, DependencyIndexReport)> {
    prepare_cancellable(source, &std::sync::atomic::AtomicBool::new(false), validate)
}

fn prepare_cancellable(
    source: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
    validate: fn(&Value) -> Result<()>,
) -> Result<(RunIndex, DependencyIndexReport)> {
    check_cancelled(cancelled)?;
    let (root, files) = recording_files(source)?;
    traffic_recording_store::source::index::prepare_run(
        &root,
        &files,
        cancelled,
        crate::protocols::default_providers().evidence(),
        super::proof::is_evidence,
        validate,
    )
}

/// Dropping this future cancels the blocking builder, including lock waits.
pub async fn prepare_with_timeout(
    source: std::path::PathBuf,
    seconds: u64,
    validate: fn(&Value) -> Result<()>,
) -> Result<DependencyIndexReport> {
    struct Cancel(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let cancel = Cancel(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        false,
    )));
    let flag = cancel.0.clone();
    let task = tokio::task::spawn_blocking(move || {
        prepare_cancellable(&source, &flag, validate).map(|(_, report)| report)
    });
    let report = tokio::time::timeout(std::time::Duration::from_secs(seconds), task)
        .await
        .with_context(|| {
            format!(
                "dependency index preparation exceeded {seconds}s; Replay readiness has not started"
            )
        })?
        .context("dependency index builder failed")??;
    tracing::info!(
        status = report.status,
        files = report.files,
        source_bytes = report.source_bytes,
        "dependency index ready"
    );
    Ok(report)
}
