//! Provider composition for shared recording-store scope indexes.
use anyhow::Result;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

pub use traffic_recording_store::source::index::global::*;

#[cfg(test)]
mod portable_tests;

pub fn seal_recording_scopes(run: &Path, validate: impl Fn(&Value) -> Result<()>) -> Result<()> {
    seal_recording_scopes_with_evidence(
        run,
        validate,
        crate::protocols::default_providers().evidence(),
    )
}

pub fn load_global_index(
    path: &Path,
    validate: impl Fn(&Value) -> Result<()>,
) -> Result<(GlobalIndex, PathBuf)> {
    load_global_index_cancellable(path, validate, &AtomicBool::new(false))
}

pub fn load_global_index_cancellable(
    path: &Path,
    validate: impl Fn(&Value) -> Result<()>,
    cancelled: &AtomicBool,
) -> Result<(GlobalIndex, PathBuf)> {
    load_global_index_with_evidence(
        path,
        validate,
        cancelled,
        crate::protocols::default_providers().evidence(),
    )
}
