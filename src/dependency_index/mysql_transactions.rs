//! Rule-independent, source-bound MySQL transaction intervals. No SQL or row payloads.
use super::{FileIndex, FileStamp, model::IndexedMysqlRecord, store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const VERSION: u32 = 1;
pub(crate) const FRAGMENT: &str = ".mysql-transactions.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SourceFile {
    pub path: PathBuf,
    pub stamp: FileStamp,
    pub sha256: String,
    pub records: Vec<IndexedMysqlRecord>,
}

impl SourceFile {
    pub fn index(&self) -> FileIndex {
        FileIndex {
            version: super::model::VERSION,
            stamp: self.stamp.clone(),
            sha256: self.sha256.clone(),
            events: self.records.len(),
            endpoints: vec![],
            metadata: vec![],
            http: vec![],
            redis: vec![],
            mysql: Some(self.records.clone()),
            redis_lanes: Default::default(),
            proof_records: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Member {
    pub file: usize,
    pub record: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Transaction {
    pub connection: String,
    pub known_start: bool,
    pub closed: bool,
    pub members: Vec<Member>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Facts {
    version: u32,
    stamps: BTreeMap<PathBuf, FileStamp>,
    pub files: Vec<SourceFile>,
    pub transactions: Vec<Transaction>,
    pub ambiguous_connections: usize,
}

/// Files are the complete sorted Case inventory, not the selected Replay slice.
pub(crate) fn load(root: &Path, cases: &[PathBuf]) -> Result<Facts> {
    let mut paths = cases.to_vec();
    let global = root.join("global-dependencies.jsonl");
    if crate::dependency_index::scoped::exists(&global) {
        paths.push(global);
    }
    let mut stamps = BTreeMap::new();
    stamps.insert(
        PathBuf::from("recording-run.json"),
        FileStamp::read(&root.join("recording-run.json"))?,
    );
    for path in &paths {
        stamps.insert(path.strip_prefix(root)?.to_owned(), FileStamp::read(path)?);
    }
    let directory = store::cache_directory(root);
    store::private_directory(&directory)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("mysql-transactions.lock"))?;
    lock.lock()?;
    let output = directory.join("mysql-transactions-v1.json");
    for path in [&output, &root.join(FRAGMENT)] {
        if let Ok(facts) = store::read_json::<Facts>(path)
            && facts.version == VERSION
            && facts.stamps == stamps
        {
            if path != &output {
                store::write_json(&output, &facts)?;
            }
            tracing::debug!(
                transactions = facts.transactions.len(),
                "reused MySQL transaction facts"
            );
            return Ok(facts);
        }
    }
    let started = std::time::Instant::now();
    let mut files = Vec::new();
    for path in paths {
        let relative = path.strip_prefix(root)?.to_owned();
        let (sha256, records) = if relative == Path::new("global-dependencies.jsonl") {
            // The paged Global index excludes large notification bodies and keeps
            // original offsets. Never rescan the multi-gigabyte JSONL here.
            let (index, base) = super::global::load_global_index(&path, |_| Ok(()))?;
            let mut records = Vec::new();
            let pages = super::global::global_records(&index, &base)?;
            for page in 0..pages.pages() {
                for entry in pages.read_page(page)? {
                    if let Some(record) = super::mysql::record(entry.location, &entry.record) {
                        records.push(record);
                    }
                }
            }
            (index.sha256, records)
        } else {
            let index = store::load_mysql_file(&path)?;
            (index.sha256, index.mysql.unwrap_or_default())
        };
        files.push(SourceFile {
            path: relative.clone(),
            stamp: stamps[&relative].clone(),
            sha256,
            records,
        });
    }
    ensure!(
        stamps
            .iter()
            .all(|(path, stamp)| FileStamp::read(&root.join(path)).is_ok_and(|s| s == *stamp)),
        "Source changed during MySQL transaction analysis"
    );
    let (transactions, ambiguous_connections) = intervals(&files);
    let facts = Facts {
        version: VERSION,
        stamps,
        files,
        transactions,
        ambiguous_connections,
    };
    store::write_json(&output, &facts)?;
    tracing::info!(
        transactions = facts.transactions.len(),
        ambiguous_connections,
        elapsed_ms = started.elapsed().as_millis(),
        "built MySQL transaction facts"
    );
    Ok(facts)
}

pub(crate) fn seal(root: &Path) -> Result<()> {
    let (root, cases) = store::recording_files(root)?;
    let facts = load(&root, &cases)?;
    store::write_json(&root.join(FRAGMENT), &facts)
}

fn intervals(files: &[SourceFile]) -> (Vec<Transaction>, usize) {
    let mut connections = BTreeMap::<String, BTreeMap<u64, Member>>::new();
    let mut ambiguous = BTreeSet::new();
    for (file, source) in files.iter().enumerate() {
        for (record, entry) in source.records.iter().enumerate() {
            let summary = &entry.summary;
            let Some(connection) = summary["connection_id"].as_str() else {
                continue;
            };
            let Some(sequence) = summary["query_sequence"].as_u64() else {
                ambiguous.insert(connection.to_owned());
                continue;
            };
            if connections
                .entry(connection.into())
                .or_default()
                .insert(sequence, Member { file, record })
                .is_some()
            {
                ambiguous.insert(connection.to_owned());
            }
        }
    }
    let mut transactions = Vec::new();
    for (connection, entries) in connections {
        if ambiguous.contains(&connection) {
            continue;
        }
        let mut group = Vec::new();
        let mut known_start = false;
        let mut previous: Option<(u64, Option<u64>, Member)> = None;
        for (sequence, member) in entries {
            let current = &files[member.file].records[member.record].summary;
            let before = current["server_status_before"].as_u64();
            let after = current["server_status_after"].as_u64();
            let consecutive = previous.is_some_and(|(seq, flags, prior)| {
                let prior = &files[prior.file].records[prior.record].summary;
                seq.checked_add(1) == Some(sequence)
                    && flags
                        .zip(before)
                        .is_some_and(|(a, b)| a & 0x200b == b & 0x200b)
                    && ["target_host", "target_port", "database", "username"]
                        .iter()
                        .all(|key| prior[*key] == current[*key])
            });
            let start =
                before.is_some_and(|s| s & 0x2009 == 0) && after.is_some_and(|s| s & 0x2009 == 1);
            if (!consecutive || start) && !group.is_empty() {
                transactions.push(Transaction {
                    connection: connection.clone(),
                    known_start,
                    closed: false,
                    members: std::mem::take(&mut group),
                });
                known_start = false;
            }
            if start {
                known_start = true;
            }
            if start || !group.is_empty() || before.is_some_and(|s| s & 0x2009 == 1) {
                group.push(member);
            }
            if after.is_some_and(|s| s & 0x2009 == 0) && !group.is_empty() {
                // Retain the immediate following control as a candidate too;
                // the protocol proof still decides whether it is cleanup.
                transactions.push(Transaction {
                    connection: connection.clone(),
                    known_start,
                    closed: true,
                    members: std::mem::take(&mut group),
                });
                known_start = false;
            }
            previous = Some((sequence, after, member));
        }
        if !group.is_empty() {
            transactions.push(Transaction {
                connection,
                known_start,
                closed: false,
                members: group,
            });
        }
    }
    (transactions, ambiguous.len())
}

#[cfg(test)]
mod tests;
