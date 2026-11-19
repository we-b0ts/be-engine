//! Shared schemas and repeated recording metadata, authenticated with the ledger.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Read,
    path::Path,
};
use traffic_model::recording::identity::IdentityKind;
use traffic_model::recording::{MANIFEST_FILE, RecordingManifest};
use traffic_protocol::capture::{RecordingLayout, RecordingScalar};
use uuid::Uuid;

use crate::source::FileStamp;

pub(crate) const FILE: &str = "dependency-terms.tsv";
const MAX_TERMS: usize = 4096;
const MAX_TERM_BYTES: usize = 1024;
const MAX_TABLE_BYTES: usize = 256 * 1024;
const LAYOUT: &[u8] = b"layout\t";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Layout {
    pub protocol: String,
    pub variant: String,
    pub event_type: String,
    pub fields: Vec<(String, RecordingScalar)>,
}

impl From<RecordingLayout> for Layout {
    fn from(layout: RecordingLayout) -> Self {
        Self {
            protocol: layout.protocol.into(),
            variant: layout.variant.into(),
            event_type: layout.event_type.into(),
            fields: layout
                .fields
                .iter()
                .map(|&(key, kind)| (key.into(), kind))
                .collect(),
        }
    }
}

pub(crate) struct WriteTerms {
    anchor: DateTime<Utc>,
    recording_id: Uuid,
    values: HashMap<Vec<u8>, usize>,
    layouts: BTreeMap<String, BTreeMap<String, Layout>>,
    bytes: usize,
    pending: Vec<u8>,
}

impl WriteTerms {
    pub(crate) fn new(anchor: DateTime<Utc>, recording_id: Uuid) -> Self {
        let pending = format!("{}\n", timestamp(anchor)).into_bytes();
        Self {
            anchor,
            recording_id,
            values: HashMap::new(),
            layouts: BTreeMap::new(),
            bytes: pending.len(),
            pending,
        }
    }

    pub(crate) fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    pub(crate) fn recording_id(&self) -> Uuid {
        self.recording_id
    }

    pub(crate) fn declare(&mut self, declared: RecordingLayout) -> Result<()> {
        let variants = self.layouts.entry(declared.protocol.into()).or_default();
        if let Some(layout) = variants.get(declared.variant) {
            ensure!(
                layout.event_type == declared.event_type
                    && layout
                        .fields
                        .iter()
                        .map(|(key, kind)| (key.as_str(), *kind))
                        .eq(declared.fields.iter().copied()),
                "recording layout changed in one run"
            );
            return Ok(());
        }
        let layout = Layout::from(declared);
        let bytes = serde_json::to_vec(&layout)?;
        ensure!(
            bytes.len() <= MAX_TERM_BYTES
                && self.bytes + bytes.len() + LAYOUT.len() < MAX_TABLE_BYTES,
            "dependency layout exceeds table capacity"
        );
        self.bytes += LAYOUT.len() + bytes.len() + 1;
        self.pending.extend_from_slice(LAYOUT);
        self.pending.extend_from_slice(&bytes);
        self.pending.push(b'\n');
        variants.insert(layout.variant.clone(), layout);
        Ok(())
    }

    pub(crate) fn intern(&mut self, value: &[u8]) -> Option<usize> {
        if let Some(&id) = self.values.get(value) {
            return Some(id);
        }
        if self.values.len() >= MAX_TERMS
            || value.len() > MAX_TERM_BYTES
            || self.bytes + value.len() >= MAX_TABLE_BYTES
        {
            return None;
        }
        let id = self.values.len() + 1;
        self.pending.extend_from_slice(value);
        self.pending.push(b'\n');
        self.bytes += value.len() + 1;
        self.values.insert(value.to_vec(), id);
        Some(id)
    }

    pub(crate) fn relative(&self, key: &str, value: &Value) -> Option<i64> {
        if !matches!(key, "started_at" | "timestamp" | "request_started_at") {
            return None;
        }
        let original = value.as_str()?;
        let time = original.parse::<DateTime<Utc>>().ok()?;
        if time.timestamp_subsec_nanos() >= 1_000_000_000 || timestamp(time) != original {
            return None;
        }
        time.signed_duration_since(self.anchor).num_nanoseconds()
    }
}

#[derive(Debug)]
pub(crate) struct ReadTerms {
    anchor: DateTime<Utc>,
    values: Vec<Value>,
    layouts: BTreeMap<String, BTreeMap<String, Layout>>,
}

#[derive(Debug)]
pub(crate) struct TermsStamp {
    file: FileStamp,
    sha256: String,
    sealed: bool,
}

impl TermsStamp {
    pub(crate) fn validate(&self, path: &Path) -> Result<()> {
        let current = FileStamp::read_native(path)?;
        if current == self.file {
            return Ok(());
        }
        ensure!(
            !self.sealed
                && current.size > self.file.size
                && current.device == self.file.device
                && current.inode == self.file.inode,
            "dependency term table changed during traversal"
        );
        // Published live scopes keep using the authenticated prefix as other
        // traffic introduces new dictionary entries.
        let mut prefix = vec![0; usize::try_from(self.file.size)?];
        fs::File::open(path)?.read_exact(&mut prefix)?;
        ensure!(
            self.sha256 == crate::source::digest(&prefix),
            "dependency term table prefix changed during traversal"
        );
        Ok(())
    }
}

impl ReadTerms {
    pub(crate) fn open(root: &Path) -> Result<(Self, TermsStamp)> {
        let path = root.join(FILE);
        let stamp = FileStamp::read_native(&path)?;
        ensure!(
            stamp.size <= MAX_TABLE_BYTES as u64,
            "dependency term table is too large"
        );
        let mut bytes = vec![0; usize::try_from(stamp.size)?];
        fs::File::open(&path)?.read_exact(&mut bytes)?;
        let sha256 = crate::source::digest(&bytes);
        let manifest = root.join(MANIFEST_FILE);
        let sealed = manifest.is_file();
        if sealed {
            let manifest: RecordingManifest = serde_json::from_slice(&fs::read(manifest)?)?;
            let identity = manifest
                .files
                .iter()
                .find(|entry| entry.path == FILE)
                .context("recording seal omits dependency terms")?;
            ensure!(
                identity.length == stamp.size && identity.sha256 == sha256,
                "sealed dependency term table changed"
            );
        }
        let stamp = TermsStamp {
            file: stamp,
            sha256,
            sealed,
        };
        stamp.validate(&path)?;
        Ok((Self::decode(&bytes)?, stamp))
    }

    pub(crate) fn open_for_replay(root: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        fs::File::open(root.join(FILE))?
            .take(MAX_TABLE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_TABLE_BYTES,
            "dependency term table is too large"
        );
        Self::decode(&bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut rows = bytes
            .strip_suffix(b"\n")
            .context("incomplete dependency term table")?
            .split(|byte| *byte == b'\n');
        let anchor = std::str::from_utf8(rows.next().context("missing dependency clock anchor")?)?
            .parse()?;
        let mut values = Vec::new();
        let mut layouts = BTreeMap::<String, BTreeMap<String, Layout>>::new();
        for row in rows {
            if let Some(row) = row.strip_prefix(LAYOUT) {
                ensure!(
                    row.len() <= MAX_TERM_BYTES,
                    "dependency layout is too large"
                );
                let layout: Layout = serde_json::from_slice(row)?;
                let variants = layouts.entry(layout.protocol.clone()).or_default();
                ensure!(
                    variants.insert(layout.variant.clone(), layout).is_none(),
                    "duplicate dependency layout"
                );
            } else {
                ensure!(
                    row.len() <= MAX_TERM_BYTES && values.len() < MAX_TERMS,
                    "dependency term table exceeds its bounds"
                );
                values.push(serde_json::from_slice(row)?);
            }
        }
        Ok(Self {
            anchor,
            values,
            layouts,
        })
    }

    pub(crate) fn layout(&self, protocol: &str, variant: &str) -> Result<&Layout> {
        self.layouts
            .get(protocol)
            .and_then(|variants| variants.get(variant))
            .context("undeclared dependency layout")
    }

    pub(crate) fn term(&self, index: usize) -> Result<Value> {
        index
            .checked_sub(1)
            .and_then(|index| self.values.get(index))
            .cloned()
            .context("dependency term reference is out of range")
    }

    pub(crate) fn clock(&self, delta: i64) -> Result<Value> {
        let time = self
            .anchor
            .checked_add_signed(TimeDelta::nanoseconds(delta))
            .context("dependency clock offset is out of range")?;
        Ok(Value::String(timestamp(time)))
    }
}

pub(crate) fn display_id(kind: IdentityKind, recording_id: Uuid, id: Uuid) -> String {
    kind.display(recording_id, id)
}

pub(crate) fn parse_id(kind: IdentityKind, recording_id: Uuid, text: &str) -> Result<Uuid> {
    kind.parse(recording_id, text)
        .context("invalid recording-local ID")
}

fn timestamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}
