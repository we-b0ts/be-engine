//! HTTP event traversal within immutable recording evidence.
use super::*;
pub(super) use crate::replay::recording_evidence::{case_id, files};
use std::path::Path;

impl RecordedHttpExchange {
    pub(in crate::replay) fn decrypt_request_headers(&mut self, file: &Path) -> Result<()> {
        self.protected_request_headers =
            crate::request_headers::decrypt_dependency_headers(&mut self.request_headers, file)
                .context("failed to decrypt recorded HTTP dependency headers")?;
        Ok(())
    }
}

/// Read only records addressed by exact endpoint selectors. The index is a
/// locator; full HTTP deserialization and header decryption remain here.
pub(super) fn visit_matching(
    file: &Path,
    keys: &std::collections::BTreeSet<String>,
    reader: &mut crate::dependency_index::RecordReader,
    mut visitor: impl FnMut(usize, RecordedHttpExchange) -> Result<()>,
) -> Result<()> {
    let index = crate::dependency_index::load_file(file)?;
    for entry in index.http.iter().filter(|entry| keys.contains(&entry.key)) {
        let raw = reader.read(file, &index.stamp, &entry.location)?;
        let mut record: RecordedHttpExchange = serde_json::from_slice(&raw)?;
        record.decrypt_request_headers(file)?;
        visitor(entry.location.line, record)?;
    }
    Ok(())
}

/// Protocol planners that require all HTTP witnesses still avoid unrelated bodies.
pub(super) fn visit(
    file: &Path,
    mut visitor: impl FnMut(usize, RecordedHttpExchange) -> Result<()>,
) -> Result<()> {
    let index = crate::dependency_index::load_file(file)?;
    let mut reader = crate::dependency_index::RecordReader::new(0);
    for entry in &index.http {
        let raw = reader.read(file, &index.stamp, &entry.location)?;
        let mut record: RecordedHttpExchange = serde_json::from_slice(&raw)?;
        record.decrypt_request_headers(file)?;
        visitor(entry.location.line, record)?;
    }
    Ok(())
}
