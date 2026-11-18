//! Optional SQL locations reuse the ordinary index and skip response payloads.
use super::{build::digest, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

pub(super) fn record(location: RecordLocation, value: &Value) -> Option<IndexedMysqlRecord> {
    traffic_protocol_mysql::index::summary(value)
        .map(|summary| IndexedMysqlRecord { location, summary })
}

pub(super) fn extend(path: &Path, mut index: FileIndex) -> Result<FileIndex> {
    index.set_mysql_records(Vec::new());
    if !index.endpoints.iter().any(|e| e.protocol == "mysql") {
        return Ok(index);
    }
    let mut input = BufReader::new(File::open(path)?);
    let mut raw = Vec::new();
    let mut offset = 0;
    let mut line = 0;
    while input.read_until(b'\n', &mut raw)? != 0 {
        line += 1;
        if !raw.iter().all(u8::is_ascii_whitespace)
            && let Some(summary) = traffic_protocol_mysql::index::summary_from_raw(&raw)
                .with_context(|| {
                    format!("invalid SQL index evidence {} line {line}", path.display())
                })?
        {
            index
                .indexes
                .get_mut("mysql")
                .expect("optional SQL index")
                .push(IndexedRecord {
                    key: String::new(),
                    connection_id: None,
                    location: RecordLocation {
                        line,
                        offset,
                        length: raw.len() as u64,
                        sha256: digest(&raw),
                    },
                    summary,
                });
        }
        offset += raw.len() as u64;
        raw.clear();
    }
    ensure!(
        offset == index.stamp.size && FileStamp::read(path)? == index.stamp,
        "dependency file changed while extending SQL index"
    );
    Ok(index)
}
