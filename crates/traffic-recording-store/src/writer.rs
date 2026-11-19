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

use crate::dependency_columns::{self, WriteTerms};
use crate::event_index::{self, JOURNALS};
use crate::format::PendingDependency;
pub use crate::format::RowLayout;
use crate::partitions;
pub use crate::partitions::RecordKind;
use crate::source::RecordLocation;

mod buffer;
mod event_order;
mod segments;
#[cfg(test)]
mod tests;

pub use buffer::{BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool};

pub struct LedgerFiles {
    root: PathBuf,
    recording_id: uuid::Uuid,
    dependencies: [FileDigest; partitions::FILES.len()],
    directory: FileDigest,
    terms: WriteTerms,
    terms_digest: FileDigest,
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
    pub async fn initialize(
        root: &Path,
        recording_id: uuid::Uuid,
        process_epoch: uuid::Uuid,
    ) -> Result<Self> {
        for name in partitions::FILES.into_iter().chain(JOURNALS) {
            crate::storage::write(&root.join(name), b"").await?;
        }
        let header = recording_id.as_bytes();
        crate::storage::write(&root.join(partitions::DIRECTORY), header).await?;
        let mut directory = FileDigest::default();
        directory.observe(header);
        let mut terms = WriteTerms::new(chrono::Utc::now(), recording_id, process_epoch);
        let term_header = terms.take_pending();
        crate::storage::write(&root.join(dependency_columns::FILE), &term_header).await?;
        let mut terms_digest = FileDigest::default();
        terms_digest.observe(&term_header);
        Ok(Self {
            root: root.into(),
            recording_id,
            dependencies: Default::default(),
            directory,
            terms,
            terms_digest,
            dependency_bytes: 0,
            events: Default::default(),
            messages: HashSet::new(),
            records: 0,
            payloads: Default::default(),
        })
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
            | OutputStarted {
                dependency_sequence,
                ..
            }
            | Output {
                dependency_sequence,
                ..
            } => self.messages.contains(dependency_sequence),
            Bound { .. } => anyhow::bail!("protocol bindings belong to dependency rows"),
            PrimaryBoundary { .. } | Input { .. } | Sealed => false,
        };
        let partition = usize::from(message);
        let row = crate::event_format::encode_event(event, self.recording_id)?;
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
        kind: RecordKind,
        layout: &RowLayout,
    ) -> Result<RecordLocation> {
        let Value::Object(record) = record else {
            anyhow::bail!("recorded dependency is not an object");
        };
        let (mut row, payloads) = PendingDependency::split(record, self.recording_id, layout)?;
        for payload in payloads {
            let reference = self
                .payloads
                .append(&self.root, files, payload.bytes())
                .await?;
            row.link(payload, reference);
        }
        let bytes = row.encode(&mut self.terms, layout)?;
        let additions = self.terms.take_pending();
        if !additions.is_empty() {
            files
                .append(&self.root.join(dependency_columns::FILE), &additions)
                .await?;
            self.terms_digest.observe(&additions);
        }
        let partition = partitions::partition(owner, kind);
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
        files.flush_all().await?;
        let mut identities = Vec::new();
        identities.push(self.directory.identity(partitions::DIRECTORY));
        identities.push(self.terms_digest.identity(dependency_columns::FILE));
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
        let recording_id = self.recording_id;
        identities.push(
            tokio::task::spawn_blocking(move || event_index::seal(&root, recording_id))
                .await
                .context("dependency event index task failed")??,
        );
        identities.extend(self.payloads.identities());
        Ok(identities)
    }
}
