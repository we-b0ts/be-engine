//! HTTP event traversal within immutable recording evidence.
use super::*;
pub(super) use crate::replay::recording_evidence::{case_id, files};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
};

pub(super) fn visit(
    file: &Path,
    mut visitor: impl FnMut(usize, RecordedHttpExchange) -> Result<()>,
) -> Result<()> {
    for (line, raw) in BufReader::new(fs::File::open(file)?).lines().enumerate() {
        let raw = raw?;
        if raw.trim().is_empty() {
            continue;
        }
        // Inspect only the event tag before deserializing HTTP evidence.
        #[derive(Deserialize)]
        struct Tag {
            event_type: String,
        }
        let tag: Tag = serde_json::from_str(&raw).context("invalid dependency event")?;
        if tag.event_type != "http_exchange" {
            continue;
        }
        let mut record: RecordedHttpExchange =
            serde_json::from_str(&raw).context("invalid recorded HTTP exchange")?;
        record.decrypt_request_headers(file)?;
        visitor(line + 1, record)?;
    }
    Ok(())
}

impl RecordedHttpExchange {
    pub(in crate::replay) fn decrypt_request_headers(&mut self, file: &Path) -> Result<()> {
        self.protected_request_headers =
            crate::request_headers::decrypt_dependency_headers(&mut self.request_headers, file)
                .context("failed to decrypt recorded HTTP dependency headers")?;
        Ok(())
    }
}
