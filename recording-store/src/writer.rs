//! Write and seal the physical dependency ledger for one recording.
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

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
pub(crate) mod tests;

pub use buffer::{BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool};

pub struct LedgerFiles {
    root: PathBuf,
    recording_id: uuid::Uuid,
    streams: [FileDigest; partitions::PARTITION_COUNT],
    last_sequence: u64,
    directory: FileDigest,
    terms: WriteTerms,
    terms_digest: FileDigest,
    dependency_bytes: u64,
    events: Option<EventLocations>,
    records: usize,
    payloads: segments::PayloadSegments,
    scopes: OriginalScopes,
    session: Option<SessionState>,
    session_chunks: Option<crate::session_integrity::Chunks>,
}

#[derive(Default)]
struct SessionState {
    wire_ends: HashSet<u64>,
    requests: HashMap<uuid::Uuid, u64>,
    summary: crate::session_summary::CaptureSummary,
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
            chunk_root: None,
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
        let header = recording_id.as_bytes();
        let mut directory = FileDigest::default();
        if !session {
            crate::storage::write(&root.join(partitions::DIRECTORY), header).await?;
            directory.observe(header);
        }
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
            events: if session {
                None
            } else {
                Some(EventLocations::initialize(root).await?)
            },
            records: 0,
            payloads: Default::default(),
            scopes: OriginalScopes::initialize(root, session).await?,
            session: session.then(SessionState::default),
            session_chunks: session.then(crate::session_integrity::Chunks::default),
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
        self.ensure_next_sequence(crate::session::FILE, event.sequence)?;
        let session = self
            .session
            .as_ref()
            .context("session capture is disabled")?;
        use SessionEvent::*;
        let request_sequence = match event.event {
            PrimaryRequest { exchange, .. } => {
                ensure!(
                    !session.requests.contains_key(&exchange),
                    "duplicate primary request exchange"
                );
                Some(event.sequence)
            }
            PrimaryResponseHeaders { exchange, .. }
            | PrimaryResponsePart { exchange, .. }
            | PrimaryResponseTrailers { exchange, .. }
            | PrimaryResponseEnd { exchange }
            | PrimaryCancel { exchange, .. } => Some(
                *session
                    .requests
                    .get(&exchange)
                    .context("primary response has no request")?,
            ),
            _ => None,
        };
        let (pending, payload) = crate::session::split(event, request_sequence)?;
        let reference = if let Some(payload) = payload {
            Some(self.payloads.append(&self.root, files, &payload).await?)
        } else {
            None
        };
        let row = pending.encode(reference.as_ref())?;
        self.append_row(files, partitions::SESSION, event.sequence, &row)
            .await?;
        let session = self.session.as_mut().expect("Session state");
        session.summary.observe(event.sequence, &event.event)?;
        match event.event {
            PrimaryRequest { exchange, .. } => {
                session.requests.insert(exchange, event.sequence);
            }
            PrimaryResponseEnd { exchange } | PrimaryCancel { exchange, .. } => {
                session.requests.remove(&exchange);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn note_successful_connection(&mut self) {
        if let Some(session) = &mut self.session {
            session.summary.successful_connections += 1;
        }
    }

    pub fn note_mandatory_protocol(&mut self, protocol: &str) {
        if let Some(session) = &mut self.session {
            *session
                .summary
                .mandatory_by_protocol
                .entry(protocol.to_owned())
                .or_default() += 1;
        }
    }

    pub fn note_unscheduled_admission(&mut self, sequence: u64) {
        if let Some(session) = &mut self.session {
            session.summary.unscheduled_admissions.insert(sequence);
        }
    }

    pub fn note_session_target(
        &mut self,
        protocol: &str,
        endpoint: traffic_protocol::connection::Endpoint,
    ) {
        if let Some(session) = &mut self.session {
            session
                .summary
                .targets
                .insert(crate::session_summary::SessionTarget {
                    host: endpoint.host,
                    port: endpoint.port,
                    protocol: protocol.to_owned(),
                });
        }
    }

    pub async fn publish_session_summary(&self) -> Result<()> {
        if let Some(session) = &self.session {
            crate::session_summary::publish_live(&self.root, &session.summary).await?;
        }
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
        let wire_end = matches!(
            event.event,
            Output {
                output: OutputKind::End,
                ..
            }
        );
        let terminal = if let Terminal {
            dependency_sequence,
            outcome,
            capture_complete,
        } = &event.event
        {
            Some((
                *dependency_sequence,
                *capture_complete && matches!(outcome.as_str(), "response" | "delivery"),
            ))
        } else {
            None
        };
        if let Some(session) = &self.session {
            let delivered = terminal.is_some_and(|(dependency, complete)| {
                complete && session.wire_ends.contains(&dependency)
            });
            if delivered {
                self.ensure_next_sequence(crate::session::FILE, event.sequence)?;
                self.last_sequence = event.sequence;
            } else {
                let row = crate::event_format::encode_event(event, self.recording_id)?;
                self.append_row(files, partitions::SESSION, event.sequence, &row)
                    .await?;
            }
            let session = self.session.as_mut().expect("Session state");
            if let OutputCancelled {
                started_sequence, ..
            } = event.event
            {
                ensure!(
                    session
                        .summary
                        .cancelled_output_starts
                        .insert(started_sequence),
                    "duplicate Session output cancellation"
                );
            }
            if let Some((dependency, _)) = terminal {
                session.wire_ends.remove(&dependency);
            } else if wire_end && let Some(dependency) = dependency {
                session.wire_ends.insert(dependency);
            }
            return Ok(());
        }
        let events = self.events.as_ref().expect("non-Session event locations");
        let journal = if matches!(event.event, MessageStarted { .. }) {
            1
        } else {
            dependency.and_then(|id| events.journal(id)).unwrap_or(0)
        };
        let partition = if journal == 1 {
            partitions::PUSH
        } else {
            partitions::ORDINARY
        };
        // The successful wire end already gives Replay its completion boundary.
        // Close the trace at capture termination so post-output events survive.
        if let Some((dependency, true)) = terminal
            && events.has_wire_end(dependency)
        {
            self.ensure_next_sequence(partitions::FILES[partition], event.sequence)?;
            self.events
                .as_mut()
                .expect("non-Session event locations")
                .finish(files, dependency)
                .await?;
            self.last_sequence = event.sequence;
            return Ok(());
        }
        let row = crate::event_format::encode_event(event, self.recording_id)?;
        let offset = self
            .append_row(files, partition, event.sequence, &row)
            .await?;
        if let Some(dependency) = dependency {
            let events = self.events.as_mut().expect("non-Session event locations");
            events.append(journal, dependency, offset, row.len(), wire_end)?;
            if terminal.is_some() {
                events.finish(files, dependency).await?;
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
        let name = partitions::file(partition).expect("known recording partition");
        self.ensure_next_sequence(name, sequence)?;
        let stream = &mut self.streams[partition];
        let offset = stream.length;
        files.append(&self.root.join(name), bytes).await?;
        stream.observe(bytes);
        if partition == partitions::SESSION
            && let Some(chunks) = &mut self.session_chunks
        {
            chunks.observe(bytes);
        }
        if partition == partitions::SESSION
            && let Some(session) = &mut self.session
        {
            session.summary.physical_events += 1;
        }
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
        let session = self.session.is_some();
        let (mut row, payloads) = if session {
            PendingDependency::split_with_payload_refs(
                record,
                self.recording_id,
                layout,
                &mut self.terms,
            )?
        } else {
            PendingDependency::split(record, self.recording_id, layout)?
        };
        for payload in payloads {
            let (index, bytes) = row.resolve_payload(payload)?;
            let reference = self.payloads.append(&self.root, files, &bytes).await?;
            row.link(index, reference);
        }
        let bytes = row.encode(&mut self.terms, layout)?;
        let additions = self.terms.take_pending();
        if !additions.is_empty() {
            files
                .append(&self.root.join(dependency_columns::FILE), &additions)
                .await?;
            self.terms_digest.observe(&additions);
        }
        let partition = partitions::partition(owner, kind, session);
        if session {
            let kind = match kind {
                RecordKind::Exchange => "dependency",
                RecordKind::Message => "notification",
                RecordKind::Observation => "observation",
            };
            let mut row = data_prefix(response_stamp, kind);
            let prefix = row.len() as u64;
            row.extend_from_slice(&bytes);
            let offset = self
                .append_row(files, partition, response_stamp.sequence, &row)
                .await?;
            self.records += 1;
            return Ok(RecordLocation {
                line: self.records,
                offset: offset + prefix,
                length: bytes.len() as u64,
                sha256: crate::source::digest(&bytes),
            });
        }
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
        self.seal_with_schedule(files, Vec::new()).await
    }

    pub async fn seal_with_schedule(
        &mut self,
        files: &mut JsonlWriterPool,
        decisions: Vec<traffic_protocol::connection::SessionDecision>,
    ) -> Result<Vec<LedgerFileIdentity>> {
        files.flush_all().await?;
        let mut identities = Vec::new();
        if let Some(session) = &self.session {
            let bytes = session.summary.bytes()?;
            let path = crate::session_summary::FILE;
            crate::storage::write(&self.root.join(path), &bytes).await?;
            let mut digest = FileDigest::default();
            digest.observe(&bytes);
            identities.push(digest.identity(path));
            crate::session_summary::remove_live(&self.root).await?;
            identities.extend(crate::session_schedule::seal(&self.root, decisions).await?);
        } else {
            identities.push(self.directory.identity(partitions::DIRECTORY));
        }
        identities.push(self.terms_digest.identity(dependency_columns::FILE));
        for (index, name) in partitions::files(self.session.is_some()) {
            let mut identity = self.streams[index].identity(name);
            if index == partitions::SESSION
                && let Some(chunks) = &mut self.session_chunks
            {
                identities.push(
                    chunks
                        .seal(&self.root, crate::session_integrity::INDEX, &mut identity)
                        .await?,
                );
            }
            identities.push(identity);
        }
        if let Some(events) = &mut self.events {
            identities.extend(events.seal().await?);
        }
        identities.extend(self.payloads.identities());
        identities.extend(self.scopes.identities());
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
