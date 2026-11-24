//! Write and seal the physical dependency ledger for one recording.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use traffic_model::{
    attribution::DependencyOwner,
    recording::{LedgerFileIdentity, ScopeKind, ScopeRecordLocation},
    session::SessionEvent,
    trace::{CaptureEvent, OutputKind, RecordedEvent},
};

use crate::dependency_columns::{self, WriteTerms};
use crate::event_index::EventLocations;
use crate::format::PendingDependency;
pub use crate::format::RowLayout;
use crate::original_scope::OriginalScopes;
use crate::partitions;
pub use crate::partitions::RecordKind;
use crate::source::RecordLocation;

mod buffer;
mod segments;
#[cfg(test)]
mod tests;

pub use buffer::{BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool};

pub struct LedgerFiles {
    root: PathBuf,
    recording_id: uuid::Uuid,
    streams: [FileDigest; partitions::FILES.len()],
    last_sequence: u64,
    directory: FileDigest,
    terms: WriteTerms,
    terms_digest: FileDigest,
    dependency_bytes: u64,
    events: EventLocations,
    records: usize,
    payloads: segments::PayloadSegments,
    scopes: OriginalScopes,
    session: Option<FileDigest>,
}

#[derive(Debug, Clone, Copy)]
pub struct RowStamp {
    pub sequence: u64,
    pub offset_micros: u64,
}

#[derive(Default)]
pub(crate) struct FileDigest {
    length: u64,
    hash: Sha256,
}

impl FileDigest {
    pub(crate) fn length(&self) -> u64 {
        self.length
    }

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
        Self::initialize_for_mode(root, recording_id, process_epoch, false).await
    }

    pub async fn initialize_for_mode(
        root: &Path,
        recording_id: uuid::Uuid,
        process_epoch: uuid::Uuid,
        session: bool,
    ) -> Result<Self> {
        for (_, name) in partitions::files(session) {
            crate::storage::write(&root.join(name), b"").await?;
        }
        if session {
            crate::storage::write(&root.join(crate::session::FILE), b"").await?;
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
            streams: Default::default(),
            last_sequence: 0,
            directory,
            terms,
            terms_digest,
            dependency_bytes: 0,
            events: EventLocations::initialize(root).await?,
            records: 0,
            payloads: Default::default(),
            scopes: OriginalScopes::initialize(root, session).await?,
            session: session.then(FileDigest::default),
        })
    }

    pub fn records(&self) -> usize {
        self.records
    }

    pub async fn append_session_event(
        &mut self,
        files: &mut JsonlWriterPool,
        event: &RecordedEvent<SessionEvent>,
    ) -> Result<()> {
        let name = crate::session::FILE;
        self.ensure_next_sequence(name, event.sequence)?;
        let session = self
            .session
            .as_mut()
            .context("session capture is disabled")?;
        let bytes = crate::session::encode(event)?;
        files.append(&self.root.join(name), &bytes).await?;
        session.observe(&bytes);
        self.last_sequence = event.sequence;
        Ok(())
    }

    pub async fn append_original_scope(
        &mut self,
        files: &mut JsonlWriterPool,
        kind: ScopeKind,
        location: &ScopeRecordLocation,
    ) -> Result<()> {
        self.scopes.append(&self.root, files, kind, location).await
    }

    pub async fn append_event(
        &mut self,
        files: &mut JsonlWriterPool,
        event: &RecordedEvent<CaptureEvent>,
    ) -> Result<()> {
        use CaptureEvent::*;
        let dependency = event.event.dependency_sequence();
        let journal = if matches!(event.event, MessageStarted { .. }) {
            1
        } else {
            dependency
                .and_then(|id| self.events.journal(id))
                .unwrap_or(0)
        };
        let partition = if journal == 1 {
            partitions::PUSH
        } else {
            partitions::ORDINARY
        };
        // The successful wire end already gives Replay its completion boundary.
        // Close the trace at capture termination so post-output events survive.
        if let Terminal {
            dependency_sequence,
            outcome,
            capture_complete: true,
        } = &event.event
            && matches!(outcome.as_str(), "response" | "delivery")
            && self.events.has_wire_end(*dependency_sequence)
        {
            self.ensure_next_sequence(partitions::FILES[partition], event.sequence)?;
            self.events.finish(files, *dependency_sequence).await?;
            self.last_sequence = event.sequence;
            return Ok(());
        }
        let row = crate::event_format::encode_event(event, self.recording_id)?;
        let offset = self
            .append_row(files, partition, event.sequence, &row)
            .await?;
        if let Some(dependency) = dependency {
            self.events.append(
                journal,
                dependency,
                offset,
                row.len(),
                matches!(
                    event.event,
                    Output {
                        output: OutputKind::End,
                        ..
                    }
                ),
            )?;
            if matches!(event.event, Terminal { .. }) {
                self.events.finish(files, dependency).await?;
            }
        }
        Ok(())
    }

    fn ensure_next_sequence(&self, name: &str, sequence: u64) -> Result<()> {
        ensure!(
            sequence > self.last_sequence,
            "recording stream {name} received unordered sequence {sequence} after {}",
            self.last_sequence
        );
        Ok(())
    }

    async fn append_row(
        &mut self,
        files: &mut JsonlWriterPool,
        partition: usize,
        sequence: u64,
        bytes: &[u8],
    ) -> Result<u64> {
        self.ensure_next_sequence(partitions::FILES[partition], sequence)?;
        let stream = &mut self.streams[partition];
        let offset = stream.length;
        files
            .append(&self.root.join(partitions::FILES[partition]), bytes)
            .await?;
        stream.observe(bytes);
        self.last_sequence = sequence;
        Ok(offset)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn append_dependency(
        &mut self,
        files: &mut JsonlWriterPool,
        record: Value,
        owner: &DependencyOwner,
        kind: RecordKind,
        layout: &RowLayout,
        request_stamp: Option<RowStamp>,
        response_stamp: RowStamp,
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
        let (header, request, response) = compact_cells(&bytes)?;
        let dependency = header
            .split(|byte| *byte == b'\t')
            .next()
            .expect("nonempty header");
        let request_stamp =
            request_stamp.filter(|_| !matches!(kind, RecordKind::Observation) || request != b"-");
        ensure!(
            request_stamp.is_some() || request == b"-",
            "a dependency with request data requires a request stamp"
        );
        ensure!(
            request_stamp.is_none_or(|request| request.sequence < response_stamp.sequence),
            "dependency response sequence must follow its request data sequence"
        );
        let additions = self.terms.take_pending();
        if !additions.is_empty() {
            files
                .append(&self.root.join(dependency_columns::FILE), &additions)
                .await?;
            self.terms_digest.observe(&additions);
        }
        let partition = partitions::partition(owner, kind, self.session.is_some());
        let header_offset;
        let response_offset;
        if let Some(stamp) = request_stamp {
            let mut row = data_prefix(stamp, "request");
            let prefix = row.len() as u64;
            row.extend_from_slice(header);
            row.push(b'\t');
            row.extend_from_slice(request);
            row.push(b'\n');
            header_offset = self
                .append_row(files, partition, stamp.sequence, &row)
                .await?
                + prefix;

            let mut row = data_prefix(response_stamp, "response");
            row.extend_from_slice(dependency);
            row.push(b'\t');
            let prefix = row.len() as u64;
            row.extend_from_slice(response);
            row.push(b'\n');
            response_offset = self
                .append_row(files, partition, response_stamp.sequence, &row)
                .await?
                + prefix;
        } else {
            let kind = match kind {
                RecordKind::Observation => "observation",
                RecordKind::Message => "message",
                RecordKind::Exchange => "response",
            };
            let mut row = data_prefix(response_stamp, kind);
            let prefix = row.len() as u64;
            row.extend_from_slice(header);
            row.push(b'\t');
            row.extend_from_slice(response);
            row.push(b'\n');
            header_offset = self
                .append_row(files, partition, response_stamp.sequence, &row)
                .await?
                + prefix;
            response_offset = header_offset + header.len() as u64 + 1;
        }
        let span = partitions::Span {
            logical: self.dependency_bytes,
            header_offset,
            header_length: header.len() as u64,
            request_length: request_stamp.map_or(0, |_| request.len() as u64),
            response_offset,
            response_length: response.len() as u64,
            partition,
        };
        let length = span.length()?;
        let entry = span.encode();
        files
            .append(&self.root.join(partitions::DIRECTORY), &entry)
            .await?;
        self.directory.observe(&entry);
        self.dependency_bytes += length;
        self.records += 1;
        let location = RecordLocation {
            line: self.records,
            offset: span.logical,
            length,
            sha256: crate::source::digest(&bytes),
        };
        Ok(location)
    }

    pub async fn seal(&mut self, files: &mut JsonlWriterPool) -> Result<Vec<LedgerFileIdentity>> {
        files.flush_all().await?;
        let mut identities = Vec::new();
        identities.push(self.directory.identity(partitions::DIRECTORY));
        identities.push(self.terms_digest.identity(dependency_columns::FILE));
        for (index, name) in partitions::files(self.session.is_some()) {
            identities.push(self.streams[index].identity(name));
        }
        identities.extend(self.events.seal().await?);
        identities.extend(self.payloads.identities());
        identities.extend(self.scopes.identities());
        if let Some(session) = &self.session {
            identities.push(session.identity(crate::session::FILE));
        }
        Ok(identities)
    }
}

fn data_prefix(stamp: RowStamp, kind: &str) -> Vec<u8> {
    format!("{}\t{}\t{kind}\t", stamp.sequence, stamp.offset_micros).into_bytes()
}

fn compact_cells(row: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let row = row
        .strip_suffix(b"\n")
        .context("unterminated dependency row")?;
    let mut columns = row.rsplitn(3, |byte| *byte == b'\t');
    let response = columns.next().context("missing dependency response")?;
    let request = columns.next().context("missing dependency request")?;
    let header = columns.next().context("missing dependency metadata")?;
    Ok((header, request, response))
}
