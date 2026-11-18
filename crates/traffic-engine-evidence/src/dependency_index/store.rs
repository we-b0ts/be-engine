#[cfg(any(test, feature = "test-support"))]
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::model::*;
#[cfg(test)]
pub(super) use traffic_recording_store::source::store::file_cache_directory;
pub(super) use traffic_recording_store::source::store::{Lock, check_cancelled};
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
    let global = root.join("global-dependencies.jsonl");
    let global_bytes = if super::scoped::exists(&global) {
        super::global::load_global_index_cancellable(&global, validate, cancelled)?;
        super::scoped::selected_bytes(&global)?
    } else {
        0
    };
    let run: Value = serde_json::from_slice(&fs::read(root.join("recording-run.json"))?)?;
    let run_id = run["run_id"].as_str().unwrap_or_default().to_owned();
    let storage = cache_directory(&root);
    private_directory(&storage)?;
    let _lock = Lock::acquire(&storage.join("build.lock"), cancelled)?;
    let output = storage.join("manifest.json");
    if let Ok(index) = read_json::<RunIndex>(&output)
        && valid_run(&root, &files, &run_id, &index)?
    {
        let mut report = report("reused", &output, &index);
        report.global_source_bytes = global_bytes;
        return Ok((index, report));
    }
    let started = Instant::now();
    let file_bytes = files
        .iter()
        .map(|p| super::scoped::selected_bytes(p))
        .collect::<Result<Vec<_>>>()?;
    let total_bytes = file_bytes.iter().sum::<u64>();
    let mut index = RunIndex {
        version: VERSION,
        run_id,
        files: Vec::new(),
        source_bytes: total_bytes,
    };
    let mut prepared_bytes = 0;
    tracing::info!(
        total_files = files.len(),
        total_bytes,
        "preparing dependency index"
    );
    for ((position, path), selected_bytes) in files.iter().enumerate().zip(file_bytes) {
        let file_index = load_file_cancellable(path, cancelled)?;
        prepared_bytes += selected_bytes;
        index.files.push(IndexedFile {
            path: path.strip_prefix(&root)?.into(),
            case_id: case_id(path)?,
            index: file_index,
        });
        if position % 100 == 0 || position + 1 == files.len() {
            tracing::info!(
                prepared_files = position + 1,
                total_files = files.len(),
                prepared_bytes,
                total_bytes,
                elapsed_seconds = started.elapsed().as_secs(),
                "preparing dependency index"
            );
        }
    }
    ensure!(
        valid_run(&root, &files, &index.run_id, &index)?,
        "recording changed during dependency index preparation"
    );
    check_cancelled(cancelled)?;
    write_json(&output, &index)?;
    let mut report = report("built", &output, &index);
    report.global_source_bytes = global_bytes;
    Ok((index, report))
}

fn report(status: &'static str, path: &Path, index: &RunIndex) -> DependencyIndexReport {
    DependencyIndexReport {
        status,
        files: index.files.len(),
        source_bytes: index.source_bytes,
        index_path: path.into(),
        global_source_bytes: 0,
    }
}

fn valid_run(root: &Path, files: &[PathBuf], run_id: &str, index: &RunIndex) -> Result<bool> {
    if index.version != VERSION || index.run_id != run_id || index.files.len() != files.len() {
        return Ok(false);
    }
    for (file, indexed) in files.iter().zip(&index.files) {
        if indexed
            .path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
            || root.join(&indexed.path) != *file
            || indexed.index.version != VERSION
            || indexed.index.stamp != FileStamp::read(file)?
        {
            return Ok(false);
        }
    }
    Ok(true)
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
