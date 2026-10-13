//! Persistent, disposable origin indexes. Status never invokes this builder.
use super::{
    OriginIndex,
    evidence::{EvidenceFile, build},
    request,
};
use crate::{config::BackgroundDependencyRuleConfig, dependency_index::FileStamp};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const VERSION: u32 = 2;
#[derive(Serialize, Deserialize)]
struct Envelope {
    checksum: String,
    payload: Cache,
}

#[derive(Serialize, Deserialize)]
struct Cache {
    version: u32,
    rules_sha256: String,
    stamps: BTreeMap<PathBuf, FileStamp>,
    index: OriginIndex,
}

pub(crate) fn load(source: &Path, rules: &[BackgroundDependencyRuleConfig]) -> Result<OriginIndex> {
    let rules: Vec<_> = rules
        .iter()
        .filter(|rule| rule.trigger_source().is_some())
        .cloned()
        .collect();
    if rules.is_empty() {
        return Ok(OriginIndex::default());
    }
    let (root, files) = crate::dependency_index::recording_files(source)?;
    ensure!(
        files.len() <= 100_000,
        "API trigger case inventory exceeds limit"
    );
    let mut stamps = BTreeMap::new();
    stamps.insert(
        root.join("recording-run.json"),
        FileStamp::read(&root.join("recording-run.json"))?,
    );
    for file in &files {
        stamps.insert(file.clone(), FileStamp::read(file)?);
        let request = file.with_file_name("request.json");
        stamps.insert(request.clone(), FileStamp::read(&request)?);
    }
    let rules_sha256 = digest(&serde_json::to_vec(&rules)?);
    let directory = crate::dependency_index::store::cache_directory(&root);
    private_directory(&directory)?;
    let cache = directory.join(format!("api-origins-{rules_sha256}.json"));
    // Multiple focused API operations share one cold build, across processes.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("api-origins.lock"))?;
    lock.lock()?;
    if let Ok(raw) = fs::read(&cache)
        && let Ok(mut envelope) = serde_json::from_slice::<Envelope>(&raw)
        && digest(&serde_json::to_vec(&envelope.payload)?) == envelope.checksum
        && envelope.payload.version == VERSION
        && envelope.payload.rules_sha256 == rules_sha256
        && envelope.payload.stamps == stamps
    {
        ensure!(stamps.iter().all(|(path, expected)| FileStamp::read(path).is_ok_and(|stamp| stamp == *expected)),
            "recording changed while reading API origin cache");
        envelope.payload.index.cache_reused = true;
        return Ok(envelope.payload.index);
    }
    let pointers: std::collections::BTreeSet<_> = rules
        .iter()
        .filter_map(|r| r.trigger_source())
        .flat_map(|source| source.request_body_json.keys().cloned())
        .collect();
    let mut evidence = Vec::new();
    for path in files {
        let Some(request) = request::read(&path.with_file_name("request.json"), &pointers)? else {
            continue;
        };
        evidence.push(EvidenceFile {
            request,
            index: crate::dependency_index::load_file(&path)?,
            path,
        });
    }
    let mut index = build(&evidence, &rules)?;
    index.evidence_fingerprint = digest(&serde_json::to_vec(&(VERSION, &rules_sha256, &stamps))?);
    ensure!(
        stamps
            .iter()
            .all(|(path, expected)| FileStamp::read(path).is_ok_and(|stamp| stamp == *expected)),
        "recording changed while building API origin index"
    );
    let saved = Cache {
        version: VERSION,
        rules_sha256,
        stamps,
        index,
    };
    let envelope = Envelope {
        checksum: digest(&serde_json::to_vec(&saved)?),
        payload: saved,
    };
    let bytes = serde_json::to_vec(&envelope)?;
    if cache.exists() {
        crate::config::edit::write_atomic(&cache, &bytes)?;
    } else {
        crate::config::edit::create_atomic(&cache, &bytes)?;
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o600))?;
    Ok(envelope.payload.index)
}

fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "refusing linked API origin cache directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(super) fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
