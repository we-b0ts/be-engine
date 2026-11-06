use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(super) const VERSION: u32 = 5;
pub(crate) const FRAGMENT: &str = ".dependency-index.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FileStamp {
    pub size: u64,
    pub device: u64,
    pub inode: u64,
    pub modified: (i64, i64),
    pub changed: (i64, i64),
}

impl FileStamp {
    /// Linux filesystems can reuse ctime within a clock tick. Only trust a
    /// stamp as a content seal if it was already old when validation began.
    pub(crate) fn stable_before(&self, validation: std::time::SystemTime) -> bool {
        use std::time::{Duration, UNIX_EPOCH};

        let Ok(seconds) = u64::try_from(self.changed.0) else {
            return false;
        };
        let Ok(nanos) = u32::try_from(self.changed.1) else {
            return false;
        };
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanos))
            .and_then(|changed| validation.duration_since(changed).ok())
            .is_some_and(|age| age >= Duration::from_secs(2))
    }

    pub(crate) fn read(path: &std::path::Path) -> anyhow::Result<Self> {
        let source = super::scoped::resolve(path)?;
        Self::read_native(&source.path)
    }
    pub(crate) fn read_native(path: &std::path::Path) -> anyhow::Result<Self> {
        use anyhow::ensure;
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path)?;
        ensure!(
            m.is_file() && !m.file_type().is_symlink(),
            "dependency evidence must be a regular unlinked file: {}",
            path.display()
        );
        Ok(Self {
            size: m.len(),
            device: m.dev(),
            inode: m.ino(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RecordLocation {
    pub line: usize,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IndexedRecord {
    pub location: RecordLocation,
    pub key: String,
    pub connection_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IndexedMysqlRecord {
    pub location: RecordLocation,
    /// Compact endpoint, SQL fingerprint and prefilter facts, without query text or rows.
    pub summary: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Endpoint {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FileIndex {
    pub version: u32,
    pub stamp: FileStamp,
    pub sha256: String,
    pub events: usize,
    pub endpoints: Vec<Endpoint>,
    pub metadata: Vec<(usize, serde_json::Value)>,
    pub http: Vec<IndexedRecord>,
    pub redis: Vec<IndexedRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql: Option<Vec<IndexedMysqlRecord>>,
    pub redis_lanes: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_records: Option<Vec<ProofRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProofRecord {
    pub location: RecordLocation,
    pub selector: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IndexedFile {
    pub path: PathBuf,
    pub case_id: String,
    pub index: FileIndex,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RunIndex {
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
