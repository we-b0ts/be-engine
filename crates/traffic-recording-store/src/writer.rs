//! Write and seal the physical dependency ledger for one recording.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use traffic_model::{
    recording::LedgerFileIdentity,
    trace::{CaptureEvent, RecordedEvent},
};

use crate::format::{self, DependencyRow};
use crate::source::RecordLocation;

mod buffer;
mod event_order;
mod segments;

pub use buffer::{BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool};

pub struct LedgerFiles {
    root: PathBuf,
    dependencies: FileDigest,
    events: FileDigest,
    records: usize,
    last_event: u64,
    unordered_events: bool,
    payloads: segments::PayloadSegments,
}

#[derive(Default)]
struct FileDigest {
    length: u64,
    hash: Sha256,
}

impl FileDigest {
    fn observe(&mut self, bytes: &[u8]) {
        self.length += bytes.len() as u64;
        self.hash.update(bytes);
    }

    fn identity(&self, path: &str) -> LedgerFileIdentity {
        LedgerFileIdentity {
            path: path.into(),
            length: self.length,
            sha256: format!("{:x}", self.hash.clone().finalize()),
        }
    }
}

impl LedgerFiles {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            dependencies: FileDigest::default(),
            events: FileDigest::default(),
            records: 0,
            last_event: 0,
            unordered_events: false,
            payloads: Default::default(),
        }
    }

    pub async fn initialize(root: &Path) -> Result<()> {
        for name in [format::DEPENDENCIES, format::EVENTS] {
            crate::storage::write(&root.join(name), b"").await?;
        }
        Ok(())
    }

    pub fn records(&self) -> usize {
        self.records
    }

    pub async fn append_event(
        &mut self,
        files: &mut JsonlWriterPool,
        event: &RecordedEvent<CaptureEvent>,
    ) -> Result<()> {
        let row = format::encode_event(event)?;
        files.append(&self.root.join(format::EVENTS), &row).await?;
        self.events.observe(&row);
        self.unordered_events |= event.sequence <= self.last_event;
        self.last_event = event.sequence;
        Ok(())
    }

    pub async fn append_dependency(
        &mut self,
        files: &mut JsonlWriterPool,
        record: Value,
    ) -> Result<RecordLocation> {
        let Value::Object(record) = record else {
            anyhow::bail!("recorded dependency is not an object");
        };
        let (mut row, payloads) = DependencyRow::split(record)?;
        for payload in payloads {
            let reference = self
                .payloads
                .append(&self.root, files, payload.bytes())
                .await?;
            row.link(payload, reference);
        }
        let bytes = row.encode()?;
        files
            .append(&self.root.join(format::DEPENDENCIES), &bytes)
            .await?;
        self.records += 1;
        let location = RecordLocation {
            line: self.records,
            offset: self.dependencies.length,
            length: bytes.len() as u64,
            sha256: crate::source::digest(&bytes),
        };
        self.dependencies.observe(&bytes);
        Ok(location)
    }

    pub async fn seal(&self, files: &mut JsonlWriterPool) -> Result<Vec<LedgerFileIdentity>> {
        // Empty runs also have an explicit dependency ledger identity.
        files
            .append(&self.root.join(format::DEPENDENCIES), b"")
            .await?;
        files.flush_all().await?;
        let events = if self.unordered_events {
            let root = self.root.clone();
            tokio::task::spawn_blocking(move || event_order::seal(&root))
                .await
                .context("dependency event ordering task failed")??
        } else {
            self.events.identity(format::EVENTS)
        };
        let mut identities = vec![self.dependencies.identity(format::DEPENDENCIES), events];
        identities.extend(self.payloads.identities());
        Ok(identities)
    }
}
