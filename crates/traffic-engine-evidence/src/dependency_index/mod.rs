//! Disposable locations into immutable semantic dependency evidence.
//! This module never authorizes matching, sharing, consumption or responses.
mod build;
pub mod case_recording;
pub mod evidence;
pub mod global;
#[cfg(test)]
mod global_tests;
mod model;
mod mysql;
pub mod mysql_transactions;
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
pub use model::{FRAGMENT, FileIndex, FileStamp, RecordLocation};
pub use pages::{PageManifest, PageWriter, Paged};
pub use reader::RecordReader;
pub use reference::{RecordRef, RecordSource};
pub use store::{load_file, recording_files};
pub use stream::RecordStream;

#[cfg(test)]
pub use build::http_key;
