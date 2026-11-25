//! Shared schemas and repeated recording metadata, authenticated with the ledger.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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
const RESPONSE_LITERAL: &[u8] = b"literal\t";

pub(crate) fn valid_response_literal_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseLiteral {
    event_type: String,
    fields: Map<String, Value>,
}

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
    process_epoch: String,
    values: HashMap<Vec<u8>, usize>,
    layouts: BTreeMap<String, BTreeMap<String, Layout>>,
    response_literals: HashMap<&'static str, ResponseLiteral>,
    bytes: usize,
    pending: Vec<u8>,
}

impl WriteTerms {
    pub(crate) fn new(anchor: DateTime<Utc>, recording_id: Uuid, process_epoch: Uuid) -> Self {
        let process_epoch = process_epoch.to_string();
        let pending = format!("{}\t{process_epoch}\n", timestamp(anchor)).into_bytes();
        Self {
            anchor,
            recording_id,
            process_epoch,
            values: HashMap::new(),
            layouts: BTreeMap::new(),
            response_literals: HashMap::new(),
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

    pub(crate) fn process_epoch(&self) -> &str {
        &self.process_epoch
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
        if self.values.len() + self.response_literals.len() >= MAX_TERMS
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

    pub(crate) fn declare_response_literal(
        &mut self,
        name: &'static str,
        event_type: &str,
        fields: &Map<String, Value>,
    ) -> Result<bool> {
        ensure!(
            valid_response_literal_name(name),
            "invalid response literal name"
        );
        ensure!(
            !event_type.is_empty() && !fields.is_empty(),
            "response literal requires an event type and response fields"
        );
        if let Some(literal) = self.response_literals.get(name) {
            return Ok(literal.event_type == event_type && &literal.fields == fields);
        }
        let literal = ResponseLiteral {
            event_type: event_type.into(),
            fields: fields.clone(),
        };
        let bytes = serde_json::to_vec(&literal)?;
        let row_len = RESPONSE_LITERAL.len() + name.len() + bytes.len() + 2;
        if self.values.len() + self.response_literals.len() >= MAX_TERMS
            || bytes.len() > MAX_TERM_BYTES
            || self.bytes + row_len > MAX_TABLE_BYTES
        {
            return Ok(false);
        }
        self.pending.extend_from_slice(RESPONSE_LITERAL);
        self.pending.extend_from_slice(name.as_bytes());
        self.pending.push(b'\t');
        self.pending.extend_from_slice(&bytes);
        self.pending.push(b'\n');
        self.bytes += row_len;
        self.response_literals.insert(name, literal);
        Ok(true)
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
    process_epoch: String,
    values: Vec<Value>,
    layouts: BTreeMap<String, BTreeMap<String, Layout>>,
    response_literals: HashMap<String, ResponseLiteral>,
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
        ensure!(
            bytes.len() <= MAX_TABLE_BYTES,
            "dependency term table is too large"
        );
        let mut rows = bytes
            .strip_suffix(b"\n")
            .context("incomplete dependency term table")?
            .split(|byte| *byte == b'\n');
        let (anchor, process_epoch) =
            std::str::from_utf8(rows.next().context("missing dependency terms header")?)?
                .split_once('\t')
                .context("missing dependency process epoch")?;
        let mut values = Vec::new();
        let mut layouts = BTreeMap::<String, BTreeMap<String, Layout>>::new();
        let mut response_literals = HashMap::new();
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
            } else if let Some(row) = row.strip_prefix(RESPONSE_LITERAL) {
                let (name, literal) = std::str::from_utf8(row)?
                    .split_once('\t')
                    .context("missing response literal value")?;
                ensure!(
                    valid_response_literal_name(name),
                    "invalid response literal name"
                );
                ensure!(
                    literal.len() <= MAX_TERM_BYTES
                        && values.len() + response_literals.len() < MAX_TERMS,
                    "dependency term table exceeds its bounds"
                );
                let literal: ResponseLiteral = serde_json::from_str(literal)?;
                ensure!(
                    !literal.event_type.is_empty() && !literal.fields.is_empty(),
                    "response literal requires an event type and response fields"
                );
                ensure!(
                    response_literals.insert(name.into(), literal).is_none(),
                    "duplicate response literal"
                );
            } else {
                ensure!(
                    row.len() <= MAX_TERM_BYTES
                        && values.len() + response_literals.len() < MAX_TERMS,
                    "dependency term table exceeds its bounds"
                );
                values.push(serde_json::from_slice(row)?);
            }
        }
        Ok(Self {
            anchor: anchor.parse()?,
            process_epoch: process_epoch.parse::<Uuid>()?.to_string(),
            values,
            layouts,
            response_literals,
        })
    }

    pub(crate) fn process_epoch(&self) -> &str {
        &self.process_epoch
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

    pub(crate) fn response_literal(
        &self,
        name: &str,
        event_type: &str,
    ) -> Result<Map<String, Value>> {
        let literal = self
            .response_literals
            .get(name)
            .context("undeclared response literal")?;
        ensure!(
            literal.event_type == event_type,
            "response literal belongs to a different event type"
        );
        Ok(literal.fields.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn named_response_terms_preserve_numbered_terms_and_event_type() -> Result<()> {
        let mut write = WriteTerms::new(Utc::now(), Uuid::nil(), Uuid::nil());
        let fields = Map::from_iter([("response".into(), json!({"status":"ok"}))]);
        assert_eq!(write.intern(br#"["before"]"#), Some(1));
        assert!(write.declare_response_literal("mysql.ok0", "mysql_exchange", &fields)?);
        assert!(write.declare_response_literal("mysql.ok0", "mysql_exchange", &fields)?);
        assert!(!write.declare_response_literal("mysql.ok0", "different_event", &fields)?);
        let other = Map::from_iter([("response".into(), json!({"status":"error"}))]);
        assert!(!write.declare_response_literal("mysql.ok0", "mysql_exchange", &other)?);
        let too_long = Map::from_iter([("response".into(), json!("x".repeat(MAX_TERM_BYTES)))]);
        assert!(!write.declare_response_literal("mysql.large", "mysql_exchange", &too_long)?);
        assert_eq!(write.intern(br#"["after"]"#), Some(2));

        let bytes = write.take_pending();
        let read = ReadTerms::decode(&bytes)?;
        assert_eq!(read.term(2)?, json!(["after"]));
        assert_eq!(
            read.response_literal("mysql.ok0", "mysql_exchange")?,
            fields
        );
        assert!(
            read.response_literal("mysql.ok0", "different_event")
                .is_err()
        );
        assert!(
            read.response_literal("mysql.large", "mysql_exchange")
                .is_err()
        );

        let mut duplicate = bytes.clone();
        let definition = bytes
            .split_inclusive(|byte| *byte == b'\n')
            .find(|row| row.starts_with(RESPONSE_LITERAL))
            .context("missing test literal")?;
        duplicate.extend_from_slice(definition);
        assert!(ReadTerms::decode(&duplicate).is_err());
        Ok(())
    }
}
