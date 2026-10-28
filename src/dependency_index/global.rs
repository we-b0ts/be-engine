//! Portable Global record metadata and notification locations, without response payloads.
#[cfg(test)]
mod portable_tests;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{FileStamp, PageManifest, PageWriter, Paged, RecordLocation, RecordStream, store};

pub(crate) const GLOBAL_FRAGMENT: &str = ".global-replay-index.json";
const VERSION: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GlobalEntry {
    pub(crate) location: RecordLocation,
    pub(crate) record: Value,
    pub(crate) mysql_row_shape: Option<(usize, bool)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NotificationEntry {
    pub(crate) location: RecordLocation,
    pub(crate) duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) ordinal: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) adapter_echo: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) adapter_request: Option<(Vec<u8>, crate::redis::socketio_rpc::Identity)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NotificationLane {
    pub(crate) record: Value,
    pub(crate) kind: u8,
    pub(crate) subject: Vec<u8>,
    pub(crate) pages: PageManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GlobalIndex {
    pub(crate) version: u32,
    pub(crate) stamp: FileStamp,
    pub(crate) sha256: String,
    pub(crate) records: PageManifest,
    pub(crate) notifications: Vec<NotificationLane>,
}

struct LaneBuilder {
    record: Value,
    kind: u8,
    subject: Vec<u8>,
    writer: PageWriter<NotificationEntry>,
}

pub(crate) struct GlobalBuilder {
    root: PathBuf,
    stamp: FileStamp,
    records: PageWriter<GlobalEntry>,
    lanes: BTreeMap<(String, u64), LaneBuilder>,
    notification_count: usize,
    offset: u64,
    hash: Sha256,
}

impl GlobalBuilder {
    pub(crate) fn new(root: &Path, stamp: FileStamp) -> Result<Self> {
        Ok(Self {
            root: root.to_owned(),
            stamp,
            records: PageWriter::new_in(&root.join(".global-replay-pages"))?,
            lanes: BTreeMap::new(),
            notification_count: 0,
            offset: 0,
            hash: Sha256::new(),
        })
    }

    pub(crate) fn observe(
        &mut self,
        location: RecordLocation,
        raw: &[u8],
        record: Option<Value>,
    ) -> Result<()> {
        self.hash.update(raw);
        self.offset += raw.len() as u64;
        let Some(mut record) = record else {
            return Ok(());
        };
        if self.notification(&record, &location)? {
            return Ok(());
        }
        let mysql_row_shape = if record["event_type"] == "mysql_exchange" {
            let columns = record["response"]["columns"].as_array().map_or(0, Vec::len);
            let shape = record["response"]["rows"].as_array().map(|rows| {
                (
                    rows.len(),
                    rows.iter()
                        .all(|row| row.as_array().is_some_and(|row| row.len() == columns)),
                )
            });
            if let Some(rows) = record.pointer_mut("/response/rows") {
                *rows = Value::Array(Vec::new());
            }
            shape
        } else {
            None
        };
        match record["event_type"].as_str() {
            Some("redis_exchange")
                if !matches!(
                    record["command"].as_str(),
                    Some(
                        "SUBSCRIBE"
                            | "PSUBSCRIBE"
                            | "SSUBSCRIBE"
                            | "UNSUBSCRIBE"
                            | "PUNSUBSCRIBE"
                            | "SUNSUBSCRIBE"
                    )
                ) =>
            {
                erase_data(&mut record["response"])
            }
            Some("memcached_exchange") => {
                if let Some(frames) = record["response_frames"].as_array_mut() {
                    for frame in frames {
                        erase_data(frame);
                    }
                }
            }
            Some("motan_exchange") => erase_data(&mut record["response"]),
            Some("http_exchange") => erase_data(&mut record["response_body"]),
            Some("kafka_produce" | "kafka_delivery") => {
                let captures = [&record["key"], &record["value"]].into_iter().chain(
                    record["headers"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|header| &header["value"]),
                );
                if captures.into_iter().all(safe_capture) {
                    record["key"] = Value::Null;
                    record["value"] = Value::Null;
                    record["headers"] = Value::Array(Vec::new());
                }
            }
            Some("redis_pub_sub_push") => erase_data(&mut record["response"]),
            _ => {}
        }
        self.records.push(GlobalEntry {
            location,
            record,
            mysql_row_shape,
        })
    }

    fn notification(&mut self, record: &Value, location: &RecordLocation) -> Result<bool> {
        if record["event_type"] != "redis_pub_sub_push"
            || !record["rpc_request"].is_null()
            || record["replay_safe"] != true
            || record["response"]["truncated"] == true
        {
            return Ok(false);
        }
        let (Some(connection), Some(sequence), Some(duration_ms)) = (
            record["connection_id"].as_str(),
            record["subscription_sequence"].as_u64(),
            record["duration_ms"].as_u64(),
        ) else {
            return Ok(false);
        };
        if sequence == 0 {
            return Ok(false);
        }
        let capture = &record["response"];
        let Some(data) = capture["data"].as_str() else {
            return Ok(false);
        };
        let raw = match capture["encoding"].as_str() {
            Some("base64") => match base64::engine::general_purpose::STANDARD.decode(data) {
                Ok(raw) => raw,
                Err(_) => return Ok(false),
            },
            Some("utf8") => data.as_bytes().to_vec(),
            _ => return Ok(false),
        };
        if raw.len() > 64 * 1024 * 1024 {
            return Ok(false);
        }
        let frame = match crate::redis::parse_pubsub_push(&raw) {
            Ok(Some(frame)) => frame,
            _ => return Ok(false),
        };
        let kind = match frame.subscription_kind {
            crate::redis::RedisSubscriptionKind::Channel => 0,
            crate::redis::RedisSubscriptionKind::Pattern => 1,
            crate::redis::RedisSubscriptionKind::ShardChannel => 2,
        };
        let key = (connection.to_owned(), sequence);
        if !self.lanes.contains_key(&key) {
            let mut header = record.clone();
            erase_data(&mut header["response"]);
            header["duration_ms"] = 0.into();
            self.lanes.insert(
                key.clone(),
                LaneBuilder {
                    record: header,
                    kind,
                    subject: frame.subject.clone(),
                    writer: PageWriter::new_in(&self.root.join(".global-replay-pages"))?,
                },
            );
        }
        let lane = self.lanes.get_mut(&key).unwrap();
        let identity = ["target_host", "target_port", "database", "username"];
        if lane.kind != kind
            || lane.subject != frame.subject
            || identity
                .iter()
                .any(|field| lane.record[field] != record[field])
        {
            return Ok(false);
        }
        lane.writer.push(NotificationEntry {
            location: location.clone(),
            duration_ms,
            timestamp: record
                .get("timestamp")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?
                .flatten(),
            ordinal: self.notification_count,
            adapter_echo: crate::redis::socketio_rpc::echo_digest(&frame.channel, &frame.payload),
            adapter_request: crate::redis::socketio_rpc::notification_request(
                &frame.channel,
                &frame.payload,
            )
            .map(|identity| (frame.channel, identity)),
        })?;
        self.notification_count += 1;
        Ok(true)
    }

    pub(crate) fn finish(self) -> Result<GlobalIndex> {
        ensure!(
            self.offset == self.stamp.size,
            "Global index did not traverse the complete source"
        );
        let mut notifications = Vec::new();
        for lane in self.lanes.into_values() {
            notifications.push(NotificationLane {
                record: lane.record,
                kind: lane.kind,
                subject: lane.subject,
                pages: lane.writer.finish()?.persist().relative_to(&self.root)?,
            });
        }
        Ok(GlobalIndex {
            version: VERSION,
            stamp: self.stamp,
            sha256: format!("{:x}", self.hash.finalize()),
            records: self.records.finish()?.persist().relative_to(&self.root)?,
            notifications,
        })
    }
}

fn erase_data(capture: &mut Value) {
    if safe_capture(capture)
        && let Some(data) = capture.get_mut("data")
    {
        *data = Value::String(String::new());
    }
}

fn safe_capture(capture: &Value) -> bool {
    if capture.is_null() {
        return true;
    }
    if capture["truncated"] == true {
        return false;
    }
    match (capture["encoding"].as_str(), capture["data"].as_str()) {
        (Some("utf8"), Some(_)) => true,
        (Some("base64"), Some(data)) => base64::engine::general_purpose::STANDARD
            .decode(data)
            .is_ok(),
        _ => false,
    }
}

pub(crate) fn load_global_index(
    path: &Path,
    validate: fn(&Value) -> Result<()>,
) -> Result<(GlobalIndex, PathBuf)> {
    load_global_index_cancellable(path, validate, &AtomicBool::new(false))
}

fn load_sealed_index(
    path: &Path,
    parent: &Path,
    stamp: &FileStamp,
    cancelled: &AtomicBool,
) -> Result<Option<GlobalIndex>> {
    let Ok(mut index) = store::read_json::<GlobalIndex>(&parent.join(GLOBAL_FRAGMENT)) else {
        return Ok(None);
    };
    // Completed recordings are immutable trusted artifacts. A normal copy keeps
    // source length and nanosecond mtime while changing inode, device and ctime.
    if index.version != VERSION
        || index.stamp.size != stamp.size
        || index.stamp.modified != stamp.modified
        || index.stamp.device == stamp.device
            && index.stamp.inode == stamp.inode
            && index.stamp != *stamp
    {
        return Ok(None);
    }
    store::check_cancelled(cancelled)?;
    ensure!(
        FileStamp::read(path)? == *stamp,
        "Global evidence changed while loading sealed index"
    );
    index.stamp = stamp.clone();
    Ok(Some(index))
}

pub(crate) fn load_global_index_cancellable(
    path: &Path,
    validate: fn(&Value) -> Result<()>,
    cancelled: &AtomicBool,
) -> Result<(GlobalIndex, PathBuf)> {
    store::check_cancelled(cancelled)?;
    let stamp = FileStamp::read(path)?;
    let parent = path
        .parent()
        .context("Global dependency file has no parent")?;
    if let Some(index) = load_sealed_index(path, parent, &stamp, cancelled)? {
        return Ok((index, parent.to_owned()));
    }
    let root = store::cache_directory(path).join("global-v3");
    store::private_directory(&root)?;
    let _lock = store::Lock::acquire(&root.join("build.lock"), cancelled)?;
    let fragment = root.join("index.json");
    if let Ok(index) = store::read_json::<GlobalIndex>(&fragment)
        && index.version == VERSION
        && index.stamp == stamp
    {
        return Ok((index, root));
    }
    let mut input = RecordStream::open(path)?;
    let mut builder = GlobalBuilder::new(&root, stamp.clone())?;
    let started = Instant::now();
    let mut next_progress = 64 * 1024 * 1024;
    tracing::info!(
        source_bytes = stamp.size,
        "preparing Global dependency index"
    );
    while let Some((location, raw)) = input.next()? {
        store::check_cancelled(cancelled)?;
        let record = if raw.iter().all(u8::is_ascii_whitespace) {
            None
        } else {
            let value = serde_json::from_slice(raw)?;
            validate(&value).with_context(|| {
                format!(
                    "invalid Global dependency {} line {}",
                    path.display(),
                    location.line
                )
            })?;
            Some(value)
        };
        builder.observe(location, raw, record)?;
        if builder.offset >= next_progress {
            tracing::info!(
                prepared_bytes = builder.offset,
                source_bytes = stamp.size,
                elapsed_seconds = started.elapsed().as_secs(),
                "preparing Global dependency index"
            );
            next_progress = builder.offset + 64 * 1024 * 1024;
        }
    }
    ensure!(
        FileStamp::read(path)? == stamp,
        "Global evidence changed during index construction"
    );
    store::check_cancelled(cancelled)?;
    let index = builder.finish()?;
    store::write_json(&fragment, &index)?;
    Ok((index, root))
}

pub(crate) fn global_records(index: &GlobalIndex, root: &Path) -> Result<Paged<GlobalEntry>> {
    Paged::restore(index.records.clone().resolve(root)?)
}
