use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, ensure};
use bytes::Bytes;

use super::compact;
use super::digest;
use super::model::{FileStamp, RecordLocation};

/// Byte-bounded immutable source records. Consumption never belongs to this cache.
#[derive(Debug)]
pub struct RecordReader {
    verify: bool,
    map_payloads: bool,
    capacity: usize,
    bytes: usize,
    records: HashMap<RecordKey, CachedRecord>,
    order: VecDeque<(RecordKey, u64)>,
    generation: u64,
    source: Option<(PathBuf, super::scoped::Source)>,
    partitions: Option<(PathBuf, FileStamp, crate::partitions::Reader)>,
    compact: Option<(PathBuf, FileStamp, compact::Reader)>,
    response_cell: Vec<u8>,
    pub source_bytes: u64,
    pub hits: usize,
}

type RecordKey = (PathBuf, u64, String);
type CachedRecord = (Arc<Vec<u8>>, u64);

impl RecordReader {
    pub fn new(capacity: usize) -> Self {
        Self {
            verify: true,
            map_payloads: false,
            capacity,
            bytes: 0,
            records: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
            source: None,
            partitions: None,
            compact: None,
            response_cell: Vec::new(),
            source_bytes: 0,
            hits: 0,
        }
    }

    /// Open dependency records from a sealed recording during Replay. File and
    /// payload ranges are still enforced by the underlying readers.
    pub fn for_replay(capacity: usize) -> Self {
        Self {
            verify: false,
            ..Self::new(capacity)
        }
    }

    /// Enable mapped payload slices for an immutable Session recording.
    ///
    /// # Safety
    ///
    /// Sealed segment files must remain unchanged while a returned slice is live.
    pub unsafe fn for_session_replay(capacity: usize) -> Self {
        Self {
            map_payloads: true,
            ..Self::for_replay(capacity)
        }
    }

    pub(super) fn verifies(&self) -> bool {
        self.verify
    }

    pub(super) fn read_metadata(
        &mut self,
        path: &Path,
        stamp: &FileStamp,
        location: &RecordLocation,
    ) -> Result<serde_json::Value> {
        if !crate::partitions::is_directory(path) {
            return Ok(serde_json::from_slice(&self.read(path, stamp, location)?)?);
        }
        let mut bytes = Vec::new();
        let verify = self.verify;
        let reader = self.partition_reader(path, stamp)?;
        let expected = (location.offset, location.length);
        if verify {
            reader.read(location.line, Some(expected), &mut bytes)?;
            ensure!(
                digest(&bytes) == location.sha256,
                "indexed dependency record checksum mismatch"
            );
        } else {
            reader.read_header(location.line, expected, &mut bytes)?;
        }
        let recording_id = reader.recording_id;
        self.source_bytes += bytes.len() as u64;
        let compact = self.compact_reader(path, stamp, recording_id)?;
        compact.validate()?;
        let metadata = compact.read_header(&bytes)?;
        if verify {
            compact.validate()?;
            ensure!(
                FileStamp::read_native(path)? == *stamp,
                "indexed dependency file changed during read"
            );
        }
        Ok(metadata)
    }

    pub(super) fn read_response_bytes(
        &mut self,
        path: &Path,
        stamp: &FileStamp,
        location: &RecordLocation,
    ) -> Result<Option<Bytes>> {
        if self.verify || !crate::partitions::is_directory(path) {
            return Ok(None);
        }
        let mut cell = std::mem::take(&mut self.response_cell);
        let result = self.read_response_cell(path, stamp, location, &mut cell);
        self.response_cell = cell;
        result
    }

    fn read_response_cell(
        &mut self,
        path: &Path,
        stamp: &FileStamp,
        location: &RecordLocation,
        cell: &mut Vec<u8>,
    ) -> Result<Option<Bytes>> {
        let reader = self.partition_reader(path, stamp)?;
        if !reader.read_response_cell(location.line, (location.offset, location.length), cell)? {
            return Ok(None);
        }
        let recording_id = reader.recording_id;
        let body = self
            .compact_reader(path, stamp, recording_id)?
            .read_response_bytes(cell)?;
        self.source_bytes += cell.len() as u64 + body.as_ref().map_or(0, |body| body.len() as u64);
        Ok(body)
    }

    fn partition_reader(
        &mut self,
        path: &Path,
        stamp: &FileStamp,
    ) -> Result<&mut crate::partitions::Reader> {
        if self
            .partitions
            .as_ref()
            .is_none_or(|(prior, verified, _)| prior != path || verified != stamp)
        {
            self.partitions = Some((
                path.to_owned(),
                stamp.clone(),
                crate::partitions::Reader::open(path)?,
            ));
        }
        Ok(&mut self
            .partitions
            .as_mut()
            .expect("opened dependency partitions")
            .2)
    }

    fn compact_reader(
        &mut self,
        path: &Path,
        stamp: &FileStamp,
        recording_id: uuid::Uuid,
    ) -> Result<&compact::Reader> {
        if self
            .compact
            .as_ref()
            .is_none_or(|(prior, verified, _)| prior != path || verified != stamp)
        {
            let reader = if self.verify {
                compact::Reader::open(path, recording_id)?
            } else if self.map_payloads {
                // SAFETY: `map_payloads` is only enabled by the Session
                // constructor, which requires sealed immutable input.
                unsafe { compact::Reader::open_for_session_replay(path, recording_id)? }
            } else {
                compact::Reader::open_for_replay(path, recording_id)?
            };
            self.compact = Some((path.to_owned(), stamp.clone(), reader));
        }
        Ok(&self.compact.as_ref().expect("opened compact reader").2)
    }

    pub fn read(
        &mut self,
        path: &Path,
        stamp: &FileStamp,
        location: &RecordLocation,
    ) -> Result<Arc<Vec<u8>>> {
        let source = self.resolve_source(path)?;
        self.read_source(&source, stamp, location)
    }

    pub(super) fn read_value(
        &mut self,
        path: &Path,
        stamp: &FileStamp,
        location: &RecordLocation,
    ) -> Result<serde_json::Value> {
        let source = self.resolve_source(path)?;
        self.read_record(
            &source,
            stamp,
            location,
            |bytes| Ok(serde_json::from_slice(&bytes)?),
            |record, _| Ok(record),
        )
    }

    fn resolve_source(&mut self, path: &Path) -> Result<super::scoped::Source> {
        Ok(match &self.source {
            Some((original, source)) if original == path => source.clone(),
            _ => {
                let mut source = super::scoped::resolve(path)?;
                // Record offsets already come from the prepared index. Retain
                // only the immutable file/view identity, never the full scope.
                source.locations = None;
                self.source = Some((path.to_owned(), source.clone()));
                source
            }
        })
    }

    pub fn read_source(
        &mut self,
        source: &super::scoped::Source,
        stamp: &FileStamp,
        location: &RecordLocation,
    ) -> Result<Arc<Vec<u8>>> {
        self.read_record(source, stamp, location, Ok, |record, mut bytes| {
            compact::encode_materialized(&record, &mut bytes)?;
            Ok(Arc::new(bytes))
        })
    }

    fn read_record<T>(
        &mut self,
        source: &super::scoped::Source,
        stamp: &FileStamp,
        location: &RecordLocation,
        json: impl FnOnce(Arc<Vec<u8>>) -> Result<T>,
        compact: impl FnOnce(serde_json::Value, Vec<u8>) -> Result<T>,
    ) -> Result<T> {
        let path = &source.path;
        if self.verify {
            source.validate()?;
            ensure!(
                FileStamp::read_native(path)? == *stamp,
                "indexed dependency file changed: {}",
                path.display()
            );
        }
        let key = (path.to_path_buf(), location.offset, location.sha256.clone());
        self.generation = self.generation.wrapping_add(1);
        if let Some((bytes, generation)) = self.records.get_mut(&key) {
            self.hits += 1;
            *generation = self.generation;
            let bytes = bytes.clone();
            self.order.push_back((key, self.generation));
            // Compact stale touches amortized, rather than linearly scanning
            // the entire hot set on every cache hit. Repeated hits stay bounded.
            if self.order.len() > self.records.len().saturating_mul(2) + 64 {
                self.order.retain(|(key, generation)| {
                    self.records
                        .get(key)
                        .is_some_and(|(_, current)| current == generation)
                });
            }
            if self.verify {
                source.validate()?;
            }
            return json(bytes);
        }
        let mut bytes = Vec::new();
        let recording_id = if crate::partitions::is_directory(path) {
            let reader = self.partition_reader(path, stamp)?;
            reader.read(
                location.line,
                Some((location.offset, location.length)),
                &mut bytes,
            )?;
            Some(reader.recording_id)
        } else {
            ensure!(
                location
                    .offset
                    .checked_add(location.length)
                    .is_some_and(|end| end <= stamp.size),
                "dependency index record range escapes source file"
            );
            let mut file = File::open(path)?;
            file.seek(SeekFrom::Start(location.offset))?;
            bytes.resize(usize::try_from(location.length)?, 0);
            file.read_exact(&mut bytes)?;
            super::compact::flat_recording_id(path)?
        };
        if self.verify {
            ensure!(
                digest(&bytes) == location.sha256,
                "indexed dependency record checksum mismatch"
            );
            ensure!(
                FileStamp::read_native(path)? == *stamp,
                "indexed dependency file changed during read"
            );
            source.validate()?;
        }
        self.source_bytes += location.length;
        if let Some(recording_id) = recording_id {
            let reader = self.compact_reader(path, stamp, recording_id)?;
            reader.validate()?;
            let record = compact(reader.read(&bytes)?, bytes)?;
            reader.validate()?;
            return Ok(record);
        }
        let bytes = Arc::new(bytes);
        if bytes.len() <= self.capacity {
            while self.bytes + bytes.len() > self.capacity {
                let Some((old, generation)) = self.order.pop_front() else {
                    break;
                };
                if self
                    .records
                    .get(&old)
                    .is_none_or(|(_, current)| *current != generation)
                {
                    continue;
                }
                if let Some((removed, _)) = self.records.remove(&old) {
                    self.bytes -= removed.len();
                }
            }
            self.bytes += bytes.len();
            self.order.push_back((key.clone(), self.generation));
            self.records.insert(key, (bytes.clone(), self.generation));
        }
        json(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::RecordSource;
    use crate::writer::{
        JsonlBufferSettings, JsonlWriterPool, LedgerFiles, RecordKind, RowLayout, RowStamp,
    };
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use traffic_model::attribution::DependencyOwner;
    use uuid::Uuid;

    #[tokio::test]
    async fn compact_values_restore_payloads_using_indexed_read_checks() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let recording_id = Uuid::new_v4();
        let process_epoch = Uuid::new_v4();
        let mut ledger =
            LedgerFiles::initialize_for_mode(root, recording_id, process_epoch, true).await?;
        let mut files = JsonlWriterPool::new(JsonlBufferSettings {
            capacity: 4096,
            flush_interval: std::time::Duration::from_secs(30),
        });
        let event = json!({
            "recording_id": recording_id,
            "capture": {"sequence":1,"process_epoch":process_epoch},
            "outcome": {"kind":"response"},
            "capture_complete": true,
            "response": {"value":"x".repeat(5000)},
        });
        let row_stamp = |sequence| RowStamp {
            sequence,
            offset_micros: sequence,
        };
        let location = ledger
            .append_dependency(
                &mut files,
                event.clone(),
                &DependencyOwner::Startup {
                    process_epoch,
                    initialization_unit: "test".into(),
                },
                RecordKind::Exchange,
                &RowLayout::default(),
                Some(row_stamp(1)),
                row_stamp(2),
            )
            .await?;
        ledger.seal(&mut files).await?;
        assert!(root.join("payload").is_dir());

        let path = crate::source::recording::dependency_path(root);
        let stamp = FileStamp::read(&path)?;
        let source = RecordSource::new(
            &path,
            stamp.clone(),
            Arc::new(Mutex::new(RecordReader::new(0))),
        );
        let reference = source.reference(location.clone());
        let value = reference.load_value()?;
        assert_eq!(value, reference.load::<Value>()?);
        assert_eq!(value["response"], event["response"]);
        let bad_digest = RecordLocation {
            sha256: String::new(),
            ..location.clone()
        };
        assert!(source.reference(bad_digest).load_value().is_err());

        let replay = RecordSource::new(
            &path,
            stamp,
            Arc::new(Mutex::new(RecordReader::for_replay(0))),
        );
        assert_eq!(replay.reference(location.clone()).load_value()?, value);
        let bad_range = RecordLocation {
            length: location.length + 1,
            ..location
        };
        assert!(replay.reference(bad_range).load_value().is_err());
        Ok(())
    }

    #[test]
    fn replay_reads_indexed_ranges_without_rechecking_the_file_or_record_digest() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("dependencies.jsonl");
        std::fs::write(&path, b"{\"id\":1}\n")?;
        let stamp = FileStamp::read_native(&path)?;
        let location = RecordLocation {
            line: 1,
            offset: 0,
            length: stamp.size,
            sha256: digest(b"{\"id\":1}\n"),
        };
        std::fs::write(&path, b"{\"id\":2}\n")?;

        assert!(RecordReader::new(0).read(&path, &stamp, &location).is_err());
        let mut reader = RecordReader::for_replay(0);
        assert_eq!(
            reader.read(&path, &stamp, &location)?.as_slice(),
            b"{\"id\":2}\n"
        );
        let invalid = RecordLocation {
            length: stamp.size + 1,
            ..location
        };
        assert!(reader.read(&path, &stamp, &invalid).is_err());
        Ok(())
    }
}
