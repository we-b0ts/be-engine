//! Rule-independent, source-bound MySQL transaction intervals. No SQL or row payloads.
use crate::dependency_index::{
    FileIndex, FileStamp, IndexedRecord, RecordLocation, global, scoped, store,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use traffic_protocol_mysql::source_intervals::Transaction;
use traffic_recording_store::source::index::VERSION as FILE_INDEX_VERSION;

const VERSION: u32 = 1;
pub const FRAGMENT: &str = ".mysql-transactions.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedMysqlRecord {
    pub location: RecordLocation,
    pub summary: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: PathBuf,
    pub stamp: FileStamp,
    pub sha256: String,
    pub records: Vec<IndexedMysqlRecord>,
}

impl SourceFile {
    pub fn index(&self) -> FileIndex {
        let mut index = FileIndex {
            version: FILE_INDEX_VERSION,
            stamp: self.stamp.clone(),
            sha256: self.sha256.clone(),
            scope_membership_sha256: None,
            events: self.records.len(),
            endpoints: vec![],
            metadata: vec![],
            indexes: Default::default(),
            proof_records: None,
        };
        self.project_into(&mut index);
        index
    }

    pub fn project_into(&self, index: &mut FileIndex) {
        index.indexes.insert(
            "mysql".into(),
            self.records
                .iter()
                .map(|record| IndexedRecord {
                    location: record.location.clone(),
                    summary: record.summary.clone(),
                    key: String::new(),
                    connection_id: None,
                })
                .collect(),
        );
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Facts {
    version: u32,
    stamps: BTreeMap<PathBuf, FileStamp>,
    pub files: Vec<SourceFile>,
    pub transactions: Vec<Transaction>,
    pub ambiguous_connections: usize,
}

/// Files are the complete sorted Case inventory, not the selected Replay slice.
pub fn load(root: &Path, cases: &[PathBuf]) -> Result<Facts> {
    let mut paths = cases.to_vec();
    let global = root.join("global-dependencies.jsonl");
    if scoped::exists(&global) {
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
            let (index, base) = global::load_global_index(&path, |_| Ok(()))?;
            let mut records = Vec::new();
            let pages = global::global_records(&index, &base)?;
            for page in 0..pages.pages() {
                for entry in pages.read_page(page)? {
                    let projection = crate::protocols::default_providers()
                        .evidence()
                        .lookup_projection(&entry.record)?;
                    records.extend(
                        projection
                            .lookups
                            .into_iter()
                            .filter(|lookup| lookup.index == "mysql")
                            .map(|lookup| IndexedMysqlRecord {
                                location: entry.location.clone(),
                                summary: lookup.summary,
                            }),
                    );
                }
            }
            (index.sha256, records)
        } else {
            let index = store::load_file(&path)?;
            let records = index
                .records("mysql")
                .iter()
                .map(|record| IndexedMysqlRecord {
                    location: record.location.clone(),
                    summary: record.summary.clone(),
                })
                .collect();
            (index.sha256, records)
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

pub fn seal(root: &Path) -> Result<()> {
    let (root, cases) = store::recording_files(root)?;
    let facts = load(&root, &cases)?;
    store::write_json(&root.join(FRAGMENT), &facts)
}

fn intervals(files: &[SourceFile]) -> (Vec<Transaction>, usize) {
    traffic_protocol_mysql::source_intervals::intervals(
        &files
            .iter()
            .map(|file| file.records.iter().map(|record| &record.summary).collect())
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests;
