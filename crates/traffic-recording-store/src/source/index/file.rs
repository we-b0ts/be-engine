use super::{FRAGMENT, FileIndex, VERSION, build_file};
use crate::source::store::{
    Lock, check_cancelled, file_cache_directory, private_directory, read_json, write_json,
};
use crate::source::{FileStamp, scoped};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{path::Path, sync::atomic::AtomicBool};
use traffic_protocol::evidence::EvidenceRegistry;

pub fn load_file(
    path: &Path,
    cancelled: &AtomicBool,
    evidence: &EvidenceRegistry,
    select_proof: fn(&Value) -> bool,
) -> Result<FileIndex> {
    check_cancelled(cancelled)?;
    let source = scoped::resolve(path)?;
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
    let index = build_file(path, cancelled, evidence, select_proof)?;
    source.validate()?;
    check_cancelled(cancelled)?;
    write_json(&output, &index)?;
    Ok(index)
}

pub fn load_file_with_proofs(
    path: &Path,
    evidence: &EvidenceRegistry,
    select_proof: fn(&Value) -> bool,
) -> Result<FileIndex> {
    let cancelled = AtomicBool::new(false);
    let index = load_file(path, &cancelled, evidence, select_proof)?;
    if index.proof_records.is_some() {
        return Ok(index);
    }

    let root = crate::source::store::cache_directory(path);
    private_directory(&root)?;
    let cache = root.join("file-proof-v1.json");
    if let Ok(cached) = read_json::<FileIndex>(&cache)
        && cached.stamp == index.stamp
        && cached.version == index.version
        && cached.proof_records.is_some()
    {
        return Ok(cached);
    }
    let built = build_file(path, &cancelled, evidence, select_proof)?;
    write_json(&cache, &built)?;
    Ok(built)
}
