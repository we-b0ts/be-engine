//! Complete metadata selection followed by authenticated reads of original records.
use super::{FileIndex, FileStamp, Paged, RecordReader, store};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::path::Path;
#[cfg(test)]
mod tests;

pub fn selector(value: &Value) -> Value {
    crate::protocols::default_providers()
        .evidence()
        .proof_selector(value)
}

pub fn capture_complete(value: &Value) -> bool {
    crate::protocols::default_providers()
        .evidence()
        .capture_complete(value)
}

pub fn is_evidence(value: &Value) -> bool {
    let tag = value["event_type"].as_str().unwrap_or_default();
    value["capture"]["semantic_required"] == true
        || tag.ends_with("_exchange")
        || matches!(
            tag,
            "dependency_connect_failure"
                | "kafka_produce"
                | "kafka_fetch"
                | "kafka_delivery"
                | "redis_pub_sub_push"
                | "tcp_gateway_connection"
        )
}

pub fn visit(
    path: &Path,
    mut selected: impl FnMut(&Value) -> Result<bool>,
    mut visitor: impl FnMut(&Value) -> Result<()>,
) -> Result<u64> {
    let mut reader = RecordReader::new(16 * 1024 * 1024);
    if path
        .file_name()
        .is_some_and(|name| name == "global-dependencies.jsonl")
    {
        let (index, root) = super::global::load_global_index(path, |_| Ok(()))?;
        let pages = Paged::<super::global::GlobalEntry>::restore(index.records.resolve(&root)?)?;
        for page in 0..pages.pages() {
            for entry in pages.read_page(page)? {
                if selected(&entry.record)? {
                    read(
                        path,
                        &index.stamp,
                        &entry.location,
                        &mut reader,
                        &mut visitor,
                    )?;
                }
            }
        }
    } else {
        let mut index = super::load_file(path)?;
        if index.proof_records.is_none() {
            let root = store::cache_directory(path);
            store::private_directory(&root)?;
            let cache = root.join("file-proof-v1.json");
            index = match store::read_json::<FileIndex>(&cache) {
                Ok(cached)
                    if cached.stamp == index.stamp
                        && cached.version == index.version
                        && cached.proof_records.is_some() =>
                {
                    cached
                }
                _ => {
                    let built =
                        super::build::build_file(path, &std::sync::atomic::AtomicBool::new(false))?;
                    store::write_json(&cache, &built)?;
                    built
                }
            };
        }
        for record in index.proof_records.as_ref().expect("proof index") {
            if selected(&record.selector)? {
                read(
                    path,
                    &index.stamp,
                    &record.location,
                    &mut reader,
                    &mut visitor,
                )?;
            }
        }
    }
    Ok(reader.source_bytes)
}

fn read(
    path: &Path,
    stamp: &FileStamp,
    location: &super::RecordLocation,
    reader: &mut RecordReader,
    visitor: &mut impl FnMut(&Value) -> Result<()>,
) -> Result<()> {
    ensure!(
        location.length <= crate::dependency::http_limits::MAX_RECORD_BYTES as u64,
        "Source rule record exceeds the supported HTTP capture envelope bound"
    );
    let bytes = reader.read(path, stamp, location)?;
    let event = crate::json_value::parse_with_limit(
        &bytes,
        crate::dependency::http_limits::MAX_RECORD_BYTES,
    )
    .ok_or_else(|| anyhow::anyhow!("Source rule record must be complete unique-member JSON"))?;
    visitor(&event)
}
