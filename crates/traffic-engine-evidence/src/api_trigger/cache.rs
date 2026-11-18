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

const VERSION: u32 = 14;
pub const FRAGMENT: &str = ".mysql-ownership.json";
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

pub fn load(source: &Path, rules: &[BackgroundDependencyRuleConfig]) -> Result<OriginIndex> {
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
    let global = root.join("global-dependencies.jsonl");
    if crate::dependency_index::scoped::exists(&global) {
        stamps.insert(global.clone(), FileStamp::read(&global)?);
    }
    let stamps: BTreeMap<_, _> = stamps
        .into_iter()
        .map(|(path, stamp)| Ok((path.strip_prefix(&root)?.to_owned(), stamp)))
        .collect::<Result<_>>()?;
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
    for path in [&cache, &root.join(FRAGMENT)] {
        if let Ok(raw) = fs::read(path)
            && let Ok(mut envelope) = serde_json::from_slice::<Envelope>(&raw)
            && digest(&serde_json::to_vec(&envelope.payload)?) == envelope.checksum
            && envelope.payload.version == VERSION
            && envelope.payload.rules_sha256 == rules_sha256
            && envelope.payload.stamps == stamps
        {
            ensure!(
                stamps
                    .iter()
                    .all(|(path, expected)| FileStamp::read(&root.join(path))
                        .is_ok_and(|stamp| stamp == *expected)),
                "recording changed while reading API origin cache"
            );
            if path != &cache {
                persist(&cache, &raw)?;
            }
            paths(&mut envelope.payload.index, &root, false)?;
            envelope.payload.index.cache_reused = true;
            return Ok(envelope.payload.index);
        }
    }
    let pointers: std::collections::BTreeSet<_> = rules
        .iter()
        .filter_map(|r| r.trigger_source())
        .flat_map(|source| source.request_body_json.keys().cloned())
        .collect();
    let mysql = rules
        .iter()
        .any(|r| matches!(r, BackgroundDependencyRuleConfig::Mysql { .. }));
    let transactions = mysql
        .then(|| crate::dependency_index::mysql_transactions::load(&root, &files))
        .transpose()?;
    let transaction_files: BTreeMap<_, _> = transactions
        .as_ref()
        .into_iter()
        .flat_map(|t| &t.files)
        .map(|file| (file.path.clone(), file))
        .collect();
    let mut evidence = Vec::new();
    for path in files {
        let Some(request) = request::read(&path.with_file_name("request.json"), &pointers)? else {
            continue;
        };
        let relative = path.strip_prefix(&root)?.to_owned();
        let mut index = crate::dependency_index::load_file(&path)?;
        if let Some(file) = transaction_files.get(&relative) {
            index.mysql = Some(file.records.clone());
        }
        evidence.push(EvidenceFile {
            request: Some(request),
            relative,
            index,
            path,
        });
    }
    if let Some(file) = transaction_files.get(Path::new("global-dependencies.jsonl")) {
        evidence.push(EvidenceFile {
            path: global,
            relative: file.path.clone(),
            request: None,
            index: file.index(),
        });
    }
    let mut index = build(&evidence, &rules, transactions.as_ref())?;
    index.evidence_fingerprint = digest(&serde_json::to_vec(&(VERSION, &rules_sha256, &stamps))?);
    ensure!(
        stamps
            .iter()
            .all(|(path, expected)| FileStamp::read(&root.join(path))
                .is_ok_and(|stamp| stamp == *expected)),
        "recording changed while building API origin index"
    );
    paths(&mut index, &root, true)?;
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
    let mut index = envelope.payload.index;
    paths(&mut index, &root, false)?;
    Ok(index)
}

fn paths(index: &mut OriginIndex, root: &Path, relative: bool) -> Result<()> {
    for witness in index
        .witnesses
        .values_mut()
        .chain(index.wire_witnesses.values_mut())
    {
        witness.dependencies_path = if relative {
            witness.dependencies_path.strip_prefix(root)?.to_owned()
        } else {
            ensure!(
                !witness.dependencies_path.is_absolute()
                    && witness
                        .dependencies_path
                        .components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                "invalid portable ownership path"
            );
            root.join(&witness.dependencies_path)
        };
    }
    Ok(())
}

pub fn seal(root: &Path, rules: &[BackgroundDependencyRuleConfig]) -> Result<()> {
    crate::dependency_index::mysql_transactions::seal(root)?;
    let rules: Vec<_> = rules
        .iter()
        .filter(|rule| rule.trigger_source().is_some())
        .cloned()
        .collect();
    if rules.is_empty() {
        return Ok(());
    }
    load(root, &rules)?;
    let path = crate::dependency_index::store::cache_directory(root).join(format!(
        "api-origins-{}.json",
        digest(&serde_json::to_vec(&rules)?)
    ));
    persist(&root.join(FRAGMENT), &fs::read(path)?)
}

fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        crate::config::edit::write_atomic(path, bytes)
    } else {
        crate::config::edit::create_atomic(path, bytes)
    }
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
