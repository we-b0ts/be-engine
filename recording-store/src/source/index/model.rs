use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 6;
pub const FRAGMENT: &str = ".dependency-index.json";

use crate::source::{FileStamp, RecordLocation};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedRecord {
    pub location: RecordLocation,
    pub key: String,
    pub connection_id: Option<String>,
    #[serde(default)]
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
    pub indexes: BTreeMap<String, Vec<IndexedRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_records: Option<Vec<ProofRecord>>,
}

impl FileIndex {
    pub fn records(&self, index: &str) -> &[IndexedRecord] {
        self.indexes
            .get(index)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
    pub fn register_endpoint(&mut self, host: String, port: u16, protocol: String) {
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
