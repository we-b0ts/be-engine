//! Resolve and verify the payloads referenced by one compact dependency row.
use crate::format::{DEPENDENCIES, DependencyRow, PayloadRef};
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub(super) fn is_compact(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == DEPENDENCIES)
}

pub(super) fn decode(path: &Path, row: &[u8]) -> Result<Vec<u8>> {
    let root = path
        .parent()
        .context("compact dependency has no recording root")?;
    let record = DependencyRow::decode(row, |reference| {
        ensure!(
            std::fs::symlink_metadata(root.join("payload"))?.is_dir(),
            "dependency payload directory must be a real directory"
        );
        let path = root.join(PayloadRef::path(reference.segment));
        let stamp = super::FileStamp::read_native(&path)?;
        ensure!(
            reference
                .offset
                .checked_add(reference.length)
                .is_some_and(|end| end <= stamp.size),
            "dependency payload range escapes its segment"
        );
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(reference.offset))?;
        let mut bytes = vec![0; usize::try_from(reference.length)?];
        file.read_exact(&mut bytes)?;
        ensure!(
            super::digest(&bytes) == reference.sha256,
            "dependency payload checksum mismatch"
        );
        Ok(bytes)
    })?;
    let mut bytes = serde_json::to_vec(&record)?;
    bytes.push(b'\n');
    Ok(bytes)
}
