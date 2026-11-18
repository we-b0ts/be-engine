#[cfg(test)]
use super::FileIndex;
#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use std::path::Path;

pub use traffic_recording_store::source::index::Builder;

#[cfg(test)]
pub use traffic_protocol_http::index::key as http_key;

#[cfg(test)]
pub fn build_file(path: &Path, cancelled: &std::sync::atomic::AtomicBool) -> Result<FileIndex> {
    traffic_recording_store::source::index::build_file(
        path,
        cancelled,
        crate::protocols::default_providers().evidence(),
        super::proof::is_evidence,
    )
}
