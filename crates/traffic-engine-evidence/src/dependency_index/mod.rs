//! Disposable locations into immutable semantic dependency evidence.
//! This module never authorizes matching, sharing, consumption or responses.
mod build;
pub mod case_recording;
pub mod evidence;
pub mod global;
#[cfg(test)]
mod global_tests;
mod model;
mod pages;
#[cfg(test)]
mod projection_tests;
pub mod proof;
mod reader;
pub mod reconciliation;
pub mod recording;
mod reference;
pub mod scoped;
pub mod store;
mod stream;
#[cfg(test)]
mod tests;

pub use build::Builder;
pub use model::DependencyIndexReport;
pub use model::{FRAGMENT, FileIndex, FileStamp, IndexedRecord, RecordLocation};
pub use pages::{PageManifest, PageWriter, Paged};
pub use reader::RecordReader;
pub use reference::{RecordRef, RecordSource};
pub use store::{load_file, load_file_for_replay, recording_files};
pub use stream::RecordStream;
pub use traffic_recording_store::source::index::recorded_case_for_replay;

#[cfg(test)]
pub use build::http_key;
