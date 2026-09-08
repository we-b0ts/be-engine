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
        let record = serde_json::from_str(&raw).context("invalid recorded HTTP exchange")?;
        visitor(line + 1, record)?;
    }
    Ok(())
}
