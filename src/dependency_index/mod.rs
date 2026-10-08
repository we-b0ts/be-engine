//! Disposable locations into immutable semantic dependency evidence.
//! This module never authorizes matching, sharing, consumption or responses.
mod build;
mod model;
mod reader;
pub(crate) mod store;
#[cfg(test)]
mod tests;

pub(crate) use build::{Builder, http_key, redis_key};
pub use model::DependencyIndexReport;
pub(crate) use model::{FRAGMENT, FileIndex, FileStamp, RecordLocation};
pub(crate) use reader::RecordReader;
pub(crate) use store::{load_file, recording_files};

pub fn prepare_dependency_index(source: &std::path::Path) -> anyhow::Result<DependencyIndexReport> {
    store::prepare(source).map(|(_, report)| report)
}
