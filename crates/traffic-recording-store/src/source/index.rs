//! Rebuildable indexes over a recording's immutable physical records.
mod build;
mod case_recording;
mod file;
pub mod global;
mod model;
mod run;

pub use build::{Builder, build_file};
pub use case_recording::seal as seal_case_indexes;
pub use file::{load_file, load_file_with_proofs};
pub use model::{FRAGMENT, FileIndex, IndexedRecord, VERSION};
pub use run::{DependencyIndexReport, RunIndex, prepare_run};
