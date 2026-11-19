use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, ensure};

use super::digest;
use super::model::{FileStamp, RecordLocation};

/// Byte-bounded immutable source records. Consumption never belongs to this cache.
#[derive(Debug)]
pub struct RecordReader {
    capacity: usize,
    bytes: usize,
    records: HashMap<RecordKey, CachedRecord>,
    order: VecDeque<(RecordKey, u64)>,
    generation: u64,
    source: Option<(PathBuf, super::scoped::Source)>,
    partitions: Option<(PathBuf, FileStamp, crate::partitions::Reader)>,
    pub source_bytes: u64,
    pub hits: usize,
}

type RecordKey = (PathBuf, u64, String);
type CachedRecord = (Arc<Vec<u8>>, u64);

impl RecordReader {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            bytes: 0,
            records: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
            source: None,
            partitions: None,
            source_bytes: 0,
            hits: 0,
        }
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
        source.validate()?;
        let path = &source.path;
        ensure!(
            FileStamp::read_native(path)? == *stamp,
            "indexed dependency file changed: {}",
            path.display()
        );
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
            source.validate()?;
            return Ok(bytes);
        }
        let mut bytes = Vec::new();
        if crate::partitions::is_directory(path) {
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
            let (_, _, reader) = self
                .partitions
                .as_mut()
                .expect("opened dependency partitions");
            reader.read(
                location.line,
                Some((location.offset, location.length)),
                &mut bytes,
            )?;
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
        }
        ensure!(
            digest(&bytes) == location.sha256,
            "indexed dependency record checksum mismatch"
        );
        ensure!(
            FileStamp::read_native(path)? == *stamp,
            "indexed dependency file changed during read"
        );
        self.source_bytes += location.length;
        source.validate()?;
        if super::compact::is_compact(path) {
            return Ok(Arc::new(super::compact::decode(path, &bytes)?));
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
