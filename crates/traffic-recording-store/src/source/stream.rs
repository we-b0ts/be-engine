//! Bounded working-set traversal of immutable dependency records.
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::{FileStamp, RecordLocation, digest};

pub struct RecordStream {
    path: PathBuf,
    pub stamp: FileStamp,
    reader: Input,
    buffer: Vec<u8>,
    offset: u64,
    line: usize,
    source: super::scoped::Source,
    position: usize,
}

enum Input {
    Flat(BufReader<File>),
    Partitioned(Box<crate::partitions::Reader>),
}

impl RecordStream {
    pub fn open(path: &Path) -> Result<Self> {
        let stamp = FileStamp::read(path)?;
        let source = super::scoped::resolve(path)?;
        let reader = if crate::partitions::is_directory(&source.path) {
            ensure!(
                stamp.size.is_multiple_of(crate::partitions::ENTRY_BYTES),
                "truncated dependency partition directory"
            );
            Input::Partitioned(Box::new(crate::partitions::Reader::open(&source.path)?))
        } else {
            Input::Flat(BufReader::new(File::open(&source.path)?))
        };
        Ok(Self {
            path: path.to_owned(),
            stamp,
            reader,
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

    pub(super) fn uses_locations(&self) -> bool {
        self.source.locations.is_some() || matches!(&self.reader, Input::Partitioned(_))
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
            match &mut self.reader {
                Input::Flat(reader) => {
                    reader.seek(SeekFrom::Start(location.offset))?;
                    self.buffer.resize(usize::try_from(location.length)?, 0);
                    reader.read_exact(&mut self.buffer)?;
                }
                Input::Partitioned(reader) => {
                    reader.read(
                        location.line,
                        Some((location.offset, location.length)),
                        &mut self.buffer,
                    )?;
                }
            }
            ensure!(
                digest(&self.buffer) == location.sha256,
                "central dependency record checksum mismatch"
            );
            self.position += 1;
            return self.decoded(location).map(Some);
        }
        let length = match &mut self.reader {
            Input::Flat(reader) => {
                let length = reader
                    .read_until(b'\n', &mut self.buffer)
                    .with_context(|| {
                        format!("failed to read dependency evidence {}", self.path.display())
                    })? as u64;
                if length == 0 {
                    ensure!(
                        self.offset == self.stamp.size,
                        "dependency file changed during traversal"
                    );
                }
                length
            }
            Input::Partitioned(reader) => {
                if self.line as u64 == self.stamp.size / crate::partitions::ENTRY_BYTES {
                    0
                } else {
                    let span = reader.read(self.line + 1, None, &mut self.buffer)?;
                    ensure!(
                        span.logical == self.offset,
                        "dependency row directory is not contiguous"
                    );
                    span.length
                }
            }
        };
        if length == 0 {
            super::scoped::validate_stamp(&self.path, &self.stamp)?;
            return Ok(None);
        }
        self.line += 1;
        let location = RecordLocation {
            line: self.line,
            offset: self.offset,
            length,
            sha256: digest(&self.buffer),
        };
        self.offset = self
            .offset
            .checked_add(length)
            .context("dependency row offset overflow")?;
        self.decoded(location).map(Some)
    }

    fn decoded(&mut self, location: RecordLocation) -> Result<(RecordLocation, &[u8])> {
        if super::compact::is_compact(&self.source.path) {
            self.buffer = super::compact::decode(&self.source.path, &self.buffer)?;
        }
        Ok((location, &self.buffer))
    }
}
