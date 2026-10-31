//! Disposable locations into immutable semantic dependency evidence.
//! This module never authorizes matching, sharing, consumption or responses.
mod build;
pub(crate) mod evidence;
pub(crate) mod global;
#[cfg(test)]
mod global_tests;
mod model;
mod mysql;
pub(crate) mod mysql_transactions;
mod pages;
pub(crate) mod proof;
mod reader;
pub(crate) mod reconciliation;
pub(crate) mod recording;
mod reference;
pub(crate) mod scoped;
pub(crate) mod store;
mod stream;
#[cfg(test)]
mod tests;

pub(crate) use build::{Builder, http_key, redis_key};
pub use model::DependencyIndexReport;
pub(crate) use model::{FRAGMENT, FileIndex, FileStamp, RecordLocation};
pub(crate) use pages::{PageManifest, PageWriter, Paged};
pub(crate) use reader::RecordReader;
pub(crate) use reference::{RecordRef, RecordSource};
pub(crate) use store::{load_file, recording_files};
pub(crate) use stream::RecordStream;
