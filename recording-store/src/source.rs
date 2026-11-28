//! Protocol-independent authenticated access to immutable recording evidence.
mod compact;
pub mod index;
mod model;
pub mod pages;
pub mod reader;
pub mod recording;
pub mod reference;
pub mod scoped;
pub(crate) mod segment_window;
pub mod store;
pub mod stream;
pub use model::{FileStamp, RecordLocation};
pub use pages::{PageManifest, PageWriter, Paged};
pub use reader::RecordReader;
pub use reference::{RecordRef, RecordSource};
pub use stream::RecordStream;

pub fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn materialize_session_row(
    root: &std::path::Path,
    recording_id: uuid::Uuid,
    cells: &[u8],
) -> anyhow::Result<serde_json::Value> {
    compact::Reader::open(&root.join(crate::session::FILE), recording_id)?.read(cells)
}

mod sealed;
pub use sealed::SourceRecord;
