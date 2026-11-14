//! HTTP event traversal within immutable recording evidence.
use super::*;
#[cfg(test)]
mod tests;
pub(super) use crate::replay::recording_evidence::{case_id, files};
use std::path::Path;

impl RecordedHttpExchange {
    pub(crate) fn decrypt_request_headers(&mut self, file: &Path) -> Result<()> {
        self.protected_request_headers = crate::request_headers::decrypt_dependency_headers(
            &mut self.native.request_headers,
            file,
        )
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
    visitor: impl FnMut(usize, RecordedHttpExchange) -> Result<()>,
) -> Result<()> {
    visit_matching_or_all(file, Some(keys), reader, visitor)
}

pub(super) fn visit_matching_or_all(
    file: &Path,
    keys: Option<&std::collections::BTreeSet<String>>,
    reader: &mut crate::dependency_index::RecordReader,
    mut visitor: impl FnMut(usize, RecordedHttpExchange) -> Result<()>,
) -> Result<()> {
    let index = crate::dependency_index::load_file(file)?;
    for entry in index
        .http
        .iter()
        .filter(|entry| keys.is_none_or(|keys| keys.contains(&entry.key)))
    {
        let raw = reader.read(file, &index.stamp, &entry.location)?;
        let mut record: RecordedHttpExchange = serde_json::from_slice(&raw)?;
        record.decrypt_request_headers(file)?;
        visitor(entry.location.line, record)?;
    }
    Ok(())
}
impl super::ReplayHttpExchange {
    pub(in crate::replay) fn run_owned(&self) -> bool {
        self.source.is_run_owned()
    }
    pub(in crate::replay) fn recorded_owner(
        &self,
    ) -> Option<traffic_model::attribution::DependencyOwner> {
        Some(self.record.native.capture.as_ref()?.attribution.clone())
    }
    pub(in crate::replay) fn run_sequence(&self) -> Option<u64> {
        (self.source.is_run_owned()
            && self.shared_origin.is_none()
            && !self.is_repeatable_preflight_probe())
        .then(|| self.recorded_sequence())
        .flatten()
    }
    pub(in crate::replay) fn recorded_sequence(&self) -> Option<u64> {
        let capture = self.record.native.capture.as_ref()?;
        (capture.semantic_required
            && self.shared_origin.is_none()
            && !self.is_repeatable_preflight_probe())
        .then_some(capture.sequence)
    }
}
