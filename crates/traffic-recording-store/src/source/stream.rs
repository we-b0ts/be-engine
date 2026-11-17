//! Bounded working-set traversal of immutable JSONL evidence.
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::{FileStamp, RecordLocation, digest};

pub struct RecordStream {
    path: PathBuf,
    pub stamp: FileStamp,
    reader: BufReader<File>,
    buffer: Vec<u8>,
    offset: u64,
    line: usize,
    source: super::scoped::Source,
    position: usize,
}

impl RecordStream {
    pub fn open(path: &Path) -> Result<Self> {
        let stamp = FileStamp::read(path)?;
        let source = super::scoped::resolve(path)?;
        Ok(Self {
            path: path.to_owned(),
            stamp,
            reader: BufReader::new(File::open(&source.path)?),
            buffer: Vec::new(),
            offset: 0,
            line: 0,
            source,
            position: 0,
        })
    }

    pub fn scope_membership_sha256(&self) -> Result<Option<String>> {
        self.source.membership_sha256()
    }

    // Each result borrows the cursor's reusable read buffer.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<(RecordLocation, &[u8])>> {
        self.buffer.clear();
        if let Some(locations) = &self.source.locations {
            let Some(location) = locations.get(self.position).cloned() else {
                self.source.validate()?;
                super::scoped::validate_stamp(&self.path, &self.stamp)?;
                return Ok(None);
            };
            self.reader.seek(SeekFrom::Start(location.offset))?;
            self.buffer.resize(usize::try_from(location.length)?, 0);
            self.reader.read_exact(&mut self.buffer)?;
            ensure!(
                digest(&self.buffer) == location.sha256,
                "central dependency record checksum mismatch"
            );
            self.position += 1;
            return Ok(Some((location, &self.buffer)));
        }
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
