use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, ensure};

use super::compact;
use super::digest;
use super::model::{FileStamp, RecordLocation};

/// Byte-bounded immutable source records. Consumption never belongs to this cache.
#[derive(Debug)]
pub struct RecordReader {
    verify: bool,
    capacity: usize,
    bytes: usize,
    records: HashMap<RecordKey, CachedRecord>,
    order: VecDeque<(RecordKey, u64)>,
    generation: u64,
    source: Option<(PathBuf, super::scoped::Source)>,
    partitions: Option<(PathBuf, FileStamp, crate::partitions::Reader)>,
    compact: Option<(PathBuf, FileStamp, compact::Reader)>,
    pub source_bytes: u64,
    pub hits: usize,
}

type RecordKey = (PathBuf, u64, String);
type CachedRecord = (Arc<Vec<u8>>, u64);

impl RecordReader {
    pub fn new(capacity: usize) -> Self {
        Self {
            verify: true,
            capacity,
            bytes: 0,
            records: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
            source: None,
            partitions: None,
            compact: None,
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
        let source = match &self.source {
            Some((original, source)) if original == path => source.clone(),
            _ => {
                let mut source = super::scoped::resolve(path)?;
                // Record offsets already come from the prepared index. Retain
                // only the immutable file/view identity, never the full scope.
                source.locations = None;
                self.source = Some((path.to_owned(), source.clone()));
                source
            }
        };
        self.read_source(&source, stamp, location)
    }

    pub fn read_source(
        &mut self,
        source: &super::scoped::Source,
        stamp: &FileStamp,
        location: &RecordLocation,
    ) -> Result<Arc<Vec<u8>>> {
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
            return Ok(bytes);
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
            let compact = self.compact_reader(path, stamp, recording_id)?;
            compact.validate()?;
            let record = compact.read(&bytes)?;
            compact::encode_materialized(&record, &mut bytes)?;
            compact.validate()?;
            return Ok(Arc::new(bytes));
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
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
