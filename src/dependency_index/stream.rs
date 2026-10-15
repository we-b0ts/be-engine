//! Bounded working-set traversal of immutable JSONL evidence.
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::{FileStamp, RecordLocation, build::digest};

pub(crate) struct RecordStream {
    path: PathBuf,
    pub(crate) stamp: FileStamp,
    reader: BufReader<File>,
    buffer: Vec<u8>,
    offset: u64,
    line: usize,
}

impl RecordStream {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let stamp = FileStamp::read(path)?;
        Ok(Self {
            path: path.to_owned(),
            stamp,
            reader: BufReader::new(File::open(path)?),
            buffer: Vec::new(),
            offset: 0,
            line: 0,
        })
    }

    pub(crate) fn next(&mut self) -> Result<Option<(RecordLocation, &[u8])>> {
        self.buffer.clear();
        let length = self
            .reader
            .read_until(b'\n', &mut self.buffer)
            .with_context(|| {
                format!("failed to read dependency evidence {}", self.path.display())
            })?;
        if length == 0 {
            ensure!(
                self.offset == self.stamp.size && FileStamp::read(&self.path)? == self.stamp,
                "dependency file changed during traversal: {}",
                self.path.display()
            );
            return Ok(None);
        }
        self.line += 1;
        let location = RecordLocation {
            line: self.line,
            offset: self.offset,
            length: length as u64,
            sha256: digest(&self.buffer),
        };
        self.offset += length as u64;
        Ok(Some((location, &self.buffer)))
    }
}
