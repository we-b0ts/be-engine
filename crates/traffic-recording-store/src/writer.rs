//! Write and seal the physical dependency ledger for one recording.
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use traffic_model::{
    attribution::DependencyOwner,
    recording::LedgerFileIdentity,
    trace::{CaptureEvent, RecordedEvent},
};

use crate::event_index::{self, JOURNALS};
use crate::format::{self, DependencyRow};
use crate::partitions;
use crate::source::RecordLocation;

mod buffer;
mod event_order;
mod segments;
#[cfg(test)]
mod tests;

pub use buffer::{BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool};

pub struct LedgerFiles {
    root: PathBuf,
    dependencies: [FileDigest; partitions::FILES.len()],
    directory: FileDigest,
    dependency_bytes: u64,
    events: [EventFile; 2],
    messages: HashSet<u64>,
    records: usize,
    payloads: segments::PayloadSegments,
}

#[derive(Default)]
struct EventFile {
    digest: FileDigest,
    last: u64,
    unordered: bool,
}

#[derive(Default)]
pub(crate) struct FileDigest {
    length: u64,
    hash: Sha256,
}

impl FileDigest {
    pub(crate) fn observe(&mut self, bytes: &[u8]) {
        self.length += bytes.len() as u64;
        self.hash.update(bytes);
    }

    pub(crate) fn identity(&self, path: &str) -> LedgerFileIdentity {
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
            dependencies: Default::default(),
            directory: Default::default(),
            dependency_bytes: 0,
            events: Default::default(),
            messages: HashSet::new(),
            records: 0,
            payloads: Default::default(),
        }
    }

    pub async fn initialize(root: &Path) -> Result<()> {
        for name in partitions::FILES
            .into_iter()
            .chain([partitions::DIRECTORY])
            .chain(JOURNALS)
        {
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
        use CaptureEvent::*;
        let message = match &event.event {
            MessageStarted {
                dependency_sequence,
                ..
            } => {
                self.messages.insert(*dependency_sequence);
                true
            }
            Terminal {
                dependency_sequence,
                ..
            } => self.messages.remove(dependency_sequence),
            Started {
                dependency_sequence,
                ..
            }
            | Bound {
                dependency_sequence,
                ..
            }
            | OutputStarted {
                dependency_sequence,
                ..
            }
            | Output {
                dependency_sequence,
                ..
            } => self.messages.contains(dependency_sequence),
            PrimaryBoundary { .. } | Input { .. } | Sealed { .. } => false,
        };
        let partition = usize::from(message);
        let row = format::encode_event(event)?;
        files
            .append(&self.root.join(JOURNALS[partition]), &row)
            .await?;
        let file = &mut self.events[partition];
        file.digest.observe(&row);
        file.unordered |= event.sequence <= file.last;
        file.last = event.sequence;
        Ok(())
    }

    pub async fn append_dependency(
        &mut self,
        files: &mut JsonlWriterPool,
        record: Value,
        owner: &DependencyOwner,
        message: bool,
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
        let partition = partitions::partition(owner, message);
        let dependency = &mut self.dependencies[partition];
        let span = partitions::Span {
            logical: self.dependency_bytes,
            offset: dependency.length,
            length: bytes.len() as u64,
            partition,
        };
        files
            .append(&self.root.join(partitions::FILES[partition]), &bytes)
            .await?;
        dependency.observe(&bytes);
        let entry = span.encode();
        files
            .append(&self.root.join(partitions::DIRECTORY), &entry)
            .await?;
        self.directory.observe(&entry);
        self.dependency_bytes += span.length;
        self.records += 1;
        let location = RecordLocation {
            line: self.records,
            offset: span.logical,
            length: span.length,
            sha256: crate::source::digest(&bytes),
        };
        Ok(location)
    }

    pub async fn seal(&self, files: &mut JsonlWriterPool) -> Result<Vec<LedgerFileIdentity>> {
        for name in partitions::FILES
            .into_iter()
            .chain([partitions::DIRECTORY])
            .chain(JOURNALS)
        {
            if !self.root.join(name).exists() {
                files.append(&self.root.join(name), b"").await?;
            }
        }
        files.flush_all().await?;
        let mut identities = Vec::new();
        identities.push(self.directory.identity(partitions::DIRECTORY));
        for (name, dependency) in partitions::FILES.into_iter().zip(&self.dependencies) {
            identities.push(dependency.identity(name));
        }
        for (name, event) in JOURNALS.into_iter().zip(&self.events) {
            let identity = if event.unordered {
                let root = self.root.clone();
                tokio::task::spawn_blocking(move || event_order::seal(&root, name))
                    .await
                    .context("dependency event ordering task failed")??
            } else {
                event.digest.identity(name)
            };
            identities.push(identity);
        }
        let root = self.root.clone();
        identities.push(
            tokio::task::spawn_blocking(move || event_index::seal(&root))
                .await
                .context("dependency event index task failed")??,
        );
        identities.extend(self.payloads.identities());
        Ok(identities)
    }
}
