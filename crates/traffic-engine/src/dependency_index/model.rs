use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(super) const VERSION: u32 = 5;
pub const FRAGMENT: &str = ".dependency-index.json";

pub use traffic_recording_store::source::{FileStamp, RecordLocation};

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
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndex {
    pub version: u32,
    pub stamp: FileStamp,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_membership_sha256: Option<String>,
    pub events: usize,
    pub endpoints: Vec<Endpoint>,
    pub metadata: Vec<(usize, serde_json::Value)>,
    pub(crate) http: Vec<IndexedRecord>,
    pub(crate) redis: Vec<IndexedRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mysql: Option<Vec<IndexedMysqlRecord>>,
    pub redis_lanes: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_records: Option<Vec<ProofRecord>>,
}

impl FileIndex {
    pub(crate) fn register_endpoint(&mut self, host: String, port: u16, protocol: String) {
        let endpoint = Endpoint {
            host,
            port,
            protocol,
        };
        if !self.endpoints.contains(&endpoint) {
            self.endpoints.push(endpoint);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRecord {
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
