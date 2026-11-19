//! Portable Global record metadata and notification locations, without response payloads.
mod recording;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::source::{
    FileStamp, PageManifest, PageWriter, Paged, RecordLocation, RecordStream, scoped, store,
};
pub use recording::seal_recording_scopes_with_evidence;

pub const GLOBAL_FRAGMENT: &str = ".global-replay-index.json";
const VERSION: u32 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalEntry {
    pub location: RecordLocation,
    pub record: Value,
    #[serde(default)]
    pub native: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationEntry {
    pub location: RecordLocation,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub ordinal: usize,
    #[serde(default)]
    pub native: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationLane {
    pub record: Value,
    pub identity: Value,
    pub pages: PageManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalIndex {
    pub version: u32,
    pub stamp: FileStamp,
    pub sha256: String,
    pub records: PageManifest,
    pub notifications: Vec<NotificationLane>,
    pub providers: BTreeMap<String, String>,
}

struct LaneBuilder {
    record: Value,
    identity: Value,
    writer: PageWriter<NotificationEntry>,
}

pub struct GlobalBuilder {
    root: PathBuf,
    stamp: FileStamp,
    records: PageWriter<GlobalEntry>,
    lanes: BTreeMap<Vec<u8>, LaneBuilder>,
    evidence: traffic_protocol::evidence::EvidenceRegistry,
    notification_count: usize,
    offset: u64,
    hash: Sha256,
    scoped: bool,
}

impl GlobalBuilder {
    pub fn with_evidence(
        root: &Path,
        stamp: FileStamp,
        evidence: traffic_protocol::evidence::EvidenceRegistry,
    ) -> Result<Self> {
        Ok(Self {
            evidence,
            root: root.to_owned(),
            stamp,
            records: PageWriter::new_in(&root.join(".global-replay-pages"))?,
            lanes: BTreeMap::new(),
            notification_count: 0,
            offset: 0,
            hash: Sha256::new(),
            scoped: false,
        })
    }

    pub fn observe(
        &mut self,
        location: RecordLocation,
        raw: &[u8],
        record: Option<Value>,
    ) -> Result<()> {
        self.hash.update(raw);
        self.offset += location.length;
        let Some(record) = record else {
            return Ok(());
        };
        let owner = self.evidence.owner(&record).map(ToOwned::to_owned);
        let projection = self.evidence.index_projection(&record)?;
        if let Some(stream) = projection.stream {
            let key = serde_json::to_vec(&(owner, &stream.identity))?;
            if !self.lanes.contains_key(&key) {
                self.lanes.insert(
                    key.clone(),
                    LaneBuilder {
                        record: projection.record,
                        identity: stream.identity,
                        writer: PageWriter::new_in(&self.root.join(".global-replay-pages"))?,
                    },
                );
            }
            self.lanes
                .get_mut(&key)
                .expect("inserted native lane")
                .writer
                .push(NotificationEntry {
                    location,
                    duration_ms: stream.duration_ms,
                    timestamp: stream.timestamp,
                    ordinal: self.notification_count,
                    native: stream.metadata,
                })?;
            self.notification_count += 1;
            return Ok(());
        }
        self.records.push(GlobalEntry {
            location,
            record: projection.record,
            native: projection.metadata,
        })
    }

    pub fn set_scoped(&mut self) {
        self.scoped = true;
    }

    pub fn finish(self) -> Result<GlobalIndex> {
        ensure!(
            self.scoped || self.offset == self.stamp.size,
            "Global index did not traverse the complete source"
        );
        let mut notifications = Vec::new();
        for lane in self.lanes.into_values() {
            notifications.push(NotificationLane {
                record: lane.record,
                identity: lane.identity,
                pages: lane.writer.finish()?.persist().relative_to(&self.root)?,
            });
        }
        Ok(GlobalIndex {
            version: VERSION,
            stamp: self.stamp,
            sha256: format!("{:x}", self.hash.finalize()),
            records: self.records.finish()?.persist().relative_to(&self.root)?,
            notifications,
            providers: self
                .evidence
                .revisions()
                .into_iter()
                .map(|(name, revision)| (name.to_owned(), revision.to_owned()))
                .collect(),
        })
    }
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

pub fn load_global_index_with_evidence(
    path: &Path,
    validate: impl Fn(&Value) -> Result<()>,
    cancelled: &AtomicBool,
    evidence: &traffic_protocol::evidence::EvidenceRegistry,
) -> Result<(GlobalIndex, PathBuf)> {
    let revisions: BTreeMap<String, String> = evidence
        .revisions()
        .into_iter()
        .map(|(name, revision)| (name.to_owned(), revision.to_owned()))
        .collect();
    store::check_cancelled(cancelled)?;
    let source = scoped::resolve(path)?;
    let stamp = FileStamp::read_native(&source.path)?;
    let parent = path
        .parent()
        .context("Global dependency file has no parent")?;
    if let Some(sealed) = recording::load(path, &stamp)
        && sealed.0.providers == revisions
    {
        store::check_cancelled(cancelled)?;
        return Ok(sealed);
    }
    if scoped::view_path(path).is_none()
        && let Some(index) = load_sealed_index(path, parent, &stamp, cancelled)?
        && index.providers == revisions
    {
        return Ok((index, parent.to_owned()));
    }
    let root = store::file_cache_directory(path, &source)?.join("global-v3");
    store::private_directory(&root)?;
    let _lock = store::Lock::acquire(&root.join("build.lock"), cancelled)?;
    let fragment = root.join("index.json");
    if let Ok(index) = store::read_json::<GlobalIndex>(&fragment)
        && index.version == VERSION
        && index.stamp == stamp
        && index.providers == revisions
    {
        source.validate()?;
        ensure!(
            FileStamp::read_native(&source.path)? == stamp,
            "Global evidence changed while loading its scope index"
        );
        return Ok((index, root));
    }
    let index = build_index_with_evidence(path, &root, &stamp, &validate, cancelled, evidence)?;
    source.validate()?;
    store::write_json(&fragment, &index)?;
    Ok((index, root))
}

fn build_index_with_evidence(
    path: &Path,
    root: &Path,
    stamp: &FileStamp,
    validate: &dyn Fn(&Value) -> Result<()>,
    cancelled: &AtomicBool,
    evidence: &traffic_protocol::evidence::EvidenceRegistry,
) -> Result<GlobalIndex> {
    let mut input = RecordStream::open(path)?;
    let mut builder = GlobalBuilder::with_evidence(root, stamp.clone(), evidence.clone())?;
    if scoped::view_path(path).is_some() {
        builder.set_scoped();
    }
    let started = Instant::now();
    let mut next_progress = 64 * 1024 * 1024;
    let source_bytes = scoped::selected_bytes(path)?;
    tracing::info!(source_bytes, "preparing Global dependency index");
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
                source_bytes,
                elapsed_seconds = started.elapsed().as_secs(),
                "preparing Global dependency index"
            );
            next_progress = builder.offset + 64 * 1024 * 1024;
        }
    }
    scoped::validate_stamp(path, stamp)?;
    store::check_cancelled(cancelled)?;
    builder.finish()
}

pub fn global_records(index: &GlobalIndex, root: &Path) -> Result<Paged<GlobalEntry>> {
    Paged::restore(index.records.clone().resolve(root)?)
}
