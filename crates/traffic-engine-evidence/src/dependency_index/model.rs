use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use traffic_recording_store::source::index::{FRAGMENT, FileIndex, IndexedRecord, VERSION};
pub use traffic_recording_store::source::{FileStamp, RecordLocation};

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
