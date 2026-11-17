//! Protocol-independent authenticated access to immutable recording evidence.
mod model;
pub mod pages;
pub mod reader;
pub mod recording;
pub mod reference;
pub mod scoped;
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

mod sealed;
pub use sealed::SourceRecord;
