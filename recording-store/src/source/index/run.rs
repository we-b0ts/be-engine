//! Disposable aggregate index for a selected recording inventory.
use super::{FileIndex, VERSION};
use crate::source::store::{
    Lock, cache_directory, check_cancelled, private_directory, read_json, write_json,
};
use crate::source::{FileStamp, scoped};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use traffic_protocol::evidence::EvidenceRegistry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedFile {
    pub path: PathBuf,
    pub case_id: String,
    pub index: FileIndex,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunIndex {
    pub version: u32,
    pub run_id: String,
    pub files: Vec<IndexedFile>,
    pub source_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyIndexReport {
    pub status: &'static str,
    pub files: usize,
    pub source_bytes: u64,
    pub index_path: PathBuf,
    pub global_source_bytes: u64,
}

pub fn prepare_run(
    root: &Path,
    files: &[PathBuf],
    cancelled: &AtomicBool,
    evidence: &EvidenceRegistry,
    select_proof: fn(&Value) -> bool,
    validate: fn(&Value) -> Result<()>,
) -> Result<(RunIndex, DependencyIndexReport)> {
    check_cancelled(cancelled)?;
    let global = root.join("global-dependencies.jsonl");
    let global_bytes = if scoped::exists(&global) {
        super::global::load_global_index_with_evidence(&global, validate, cancelled, evidence)?;
        scoped::selected_bytes(&global)?
    } else {
        0
    };
    let run: Value = serde_json::from_slice(&fs::read(root.join("recording-run.json"))?)?;
    let run_id = run["run_id"].as_str().unwrap_or_default().to_owned();
    let storage = cache_directory(root);
    private_directory(&storage)?;
    let _lock = Lock::acquire(&storage.join("build.lock"), cancelled)?;
    let output = storage.join("manifest.json");
    if let Ok(index) = read_json::<RunIndex>(&output)
        && valid_run(root, files, &run_id, &index)?
    {
        let mut report = report("reused", &output, &index);
        report.global_source_bytes = global_bytes;
        return Ok((index, report));
    }
    let started = Instant::now();
    let file_bytes = files
        .iter()
        .map(|p| scoped::selected_bytes(p))
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
        let file_index = super::load_file(path, cancelled, evidence, select_proof)?;
        prepared_bytes += selected_bytes;
        index.files.push(IndexedFile {
            path: path.strip_prefix(root)?.into(),
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
        valid_run(root, files, &index.run_id, &index)?,
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

fn case_id(path: &Path) -> Result<String> {
    Ok(path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .context("dependency file has no case identity")?
        .into())
}
