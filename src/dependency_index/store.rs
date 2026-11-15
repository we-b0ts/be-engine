#[cfg(test)]
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::build::build_file;
use super::model::*;
pub(super) use traffic_recording::source::store::{
    Lock, check_cancelled, decode_json, file_cache_directory,
};
pub(crate) use traffic_recording::source::store::{
    cache_directory, private_directory, read_json, write_json,
};

/// The same completed standard-run boundary for all indexed protocol queries.
pub(crate) fn recording_files(source: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    if let Some(root) = super::recording::root(source) {
        return super::recording::cases(&root);
    }
    #[cfg(not(test))]
    anyhow::bail!(
        "recording requires the current central dependency manifest; old recording semantics are unsupported"
    );
    #[cfg(test)]
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

pub(crate) fn load_file(path: &Path) -> Result<FileIndex> {
    load_file_cancellable(path, &std::sync::atomic::AtomicBool::new(false))
}

fn load_file_cancellable(
    path: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<FileIndex> {
    check_cancelled(cancelled)?;
    let source = super::scoped::resolve(path)?;
    let stamp = FileStamp::read_native(&source.path)?;
    if let Some(index) = super::case_recording::load(&source, &stamp) {
        check_cancelled(cancelled)?;
        return Ok(index);
    }
    let fragment = path
        .parent()
        .context("dependency file has no parent")?
        .join(FRAGMENT);
    if source.view.is_none()
        && let Ok(index) = read_json::<FileIndex>(&fragment)
        && index.version == VERSION
        && index.stamp == stamp
    {
        return Ok(index);
    }
    let cache = file_cache_directory(path, &source)?;
    private_directory(&cache)?;
    let _lock = Lock::acquire(&cache.join("build.lock"), cancelled)?;
    let output = cache.join("file.json");
    if let Ok(index) = read_json::<FileIndex>(&output)
        && index.version == VERSION
        && index.stamp == stamp
    {
        if source.view.is_some() {
            source.validate()?;
            ensure!(
                FileStamp::read_native(&source.path)? == stamp,
                "dependency ledger changed while loading its scope index"
            );
        }
        return Ok(index);
    }
    let index = build_file(path, cancelled)?;
    source.validate()?;
    check_cancelled(cancelled)?;
    write_json(&output, &index)?;
    Ok(index)
}

/// Only configured API-origin MySQL discovery requests this optional extension.
pub(crate) fn load_mysql_file(path: &Path) -> Result<FileIndex> {
    let base = load_file(path)?;
    // New Recorder summaries already contain SQL-free MySQL metadata. Legacy
    // fragments alone need the optional extension pass over their original file.
    if base.mysql.is_some() {
        return Ok(base);
    }
    let stamp = base.stamp.clone();
    let directory = cache_directory(path);
    private_directory(&directory)?;
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let _lock = Lock::acquire(&directory.join("build.lock"), &cancelled)?;
    let cache = directory.join("file-mysql-v5.json");
    if let Ok(index) = read_json::<FileIndex>(&cache)
        && index.version == VERSION
        && index.stamp == stamp
        && index.mysql.is_some()
    {
        return Ok(index);
    }
    let index = super::mysql::extend(path, base)?;
    write_json(&cache, &index)?;
    Ok(index)
}

pub(crate) fn prepare(
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
pub(crate) async fn prepare_with_timeout(
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
