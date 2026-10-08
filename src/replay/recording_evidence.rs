//! Bounded traversal restricted to one completed standard recording.
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(in crate::replay) fn files(source: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    crate::dependency_index::recording_files(source)
}

pub(in crate::replay) fn case_id(file: &Path) -> Result<String> {
    Ok(file
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .context("recorded case has no identity")?
        .to_string())
}
