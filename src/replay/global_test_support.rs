use crate::dependency_index::global::{global_records, load_global_index};
use crate::dependency_index::{RecordReader, RecordRef, RecordSource};
use serde_json::Value;
use std::sync::{Arc, Mutex};

pub(super) fn indexed(records: &[Value]) -> (tempfile::TempDir, Vec<(Value, RecordRef)>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("global-dependencies.jsonl");
    std::fs::write(
        &path,
        records.iter().map(|v| format!("{v}\n")).collect::<String>(),
    )
    .unwrap();
    let (index, root) = load_global_index(
        &path,
        crate::protocols::replay::source::validate_index_record,
    )
    .unwrap();
    // Force every response to exceed the cache budget. Session consumption must
    // still be finite when the same immutable bytes are loaded again.
    let source = RecordSource::new(
        &path,
        index.stamp.clone(),
        Arc::new(Mutex::new(RecordReader::new(1))),
    );
    let pages = global_records(&index, &root).unwrap();
    let mut result = Vec::new();
    for page in 0..pages.pages() {
        result.extend(
            pages
                .read_page(page)
                .unwrap()
                .into_iter()
                .map(|entry| (entry.record, source.reference(entry.location))),
        );
    }
    (dir, result)
}
