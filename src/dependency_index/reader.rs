use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, ensure};

use super::build::digest;
use super::model::{FileStamp, RecordLocation};

/// Byte-bounded immutable source records. Consumption never belongs to this cache.
#[derive(Debug)]
pub(crate) struct RecordReader {
    capacity: usize,
    bytes: usize,
    records: HashMap<(PathBuf, u64, String), Arc<Vec<u8>>>,
    order: VecDeque<(PathBuf, u64, String)>,
    pub(crate) source_bytes: u64,
    pub(crate) hits: usize,
}

impl RecordReader {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            bytes: 0,
            records: HashMap::new(),
            order: VecDeque::new(),
            source_bytes: 0,
            hits: 0,
        }
    }

    pub(crate) fn read(
        &mut self,
        path: &Path,
        stamp: &FileStamp,
        location: &RecordLocation,
    ) -> Result<Arc<Vec<u8>>> {
        ensure!(
            FileStamp::read(path)? == *stamp,
            "indexed dependency file changed: {}",
            path.display()
        );
        let key = (path.to_path_buf(), location.offset, location.sha256.clone());
        if let Some(bytes) = self.records.get(&key) {
            self.hits += 1;
            self.order.retain(|entry| entry != &key);
            self.order.push_back(key);
            return Ok(bytes.clone());
        }
        ensure!(
            location
                .offset
                .checked_add(location.length)
                .is_some_and(|end| end <= stamp.size),
            "dependency index record range escapes source file"
        );
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(location.offset))?;
        let mut bytes = vec![0; usize::try_from(location.length)?];
        file.read_exact(&mut bytes)?;
        ensure!(
            digest(&bytes) == location.sha256,
            "indexed dependency record checksum mismatch"
        );
        ensure!(
            FileStamp::read(path)? == *stamp,
            "indexed dependency file changed during read"
        );
        self.source_bytes += location.length;
        let bytes = Arc::new(bytes);
        if bytes.len() <= self.capacity {
            while self.bytes + bytes.len() > self.capacity {
                let Some(old) = self.order.pop_front() else {
                    break;
                };
                if let Some(removed) = self.records.remove(&old) {
                    self.bytes -= removed.len();
                }
            }
            self.bytes += bytes.len();
            self.order.push_back(key.clone());
            self.records.insert(key, bytes.clone());
        }
        Ok(bytes)
    }
}
