//! Bounded working-set traversal of immutable dependency records.
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::compact;
use super::{FileStamp, RecordLocation, digest};
use crate::partitions;

pub struct RecordStream {
    verify: bool,
    path: PathBuf,
    pub stamp: FileStamp,
    reader: Input,
    buffer: Vec<u8>,
    materialized: Vec<u8>,
    offset: u64,
    line: usize,
    source: super::scoped::Source,
    position: usize,
    compact: Option<compact::Reader>,
}

enum Input {
    Flat(BufReader<File>),
    Partitioned(Box<partitions::Reader>, u64),
}

type DecodedRow<'a> = (RecordLocation, &'a [u8], Option<Value>);

impl RecordStream {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_verification(path, true)
    }

    /// Traverse a recording for Replay using its physical locations and bounds.
    pub fn open_for_replay(path: &Path) -> Result<Self> {
        Self::open_with_verification(path, false)
    }

    fn open_with_verification(path: &Path, verify: bool) -> Result<Self> {
        let source = super::scoped::resolve(path)?;
        let stamp = FileStamp::read_native(&source.path)?;
        let (reader, recording_id) = if partitions::is_directory(&source.path) {
            let records = partitions::record_count(stamp.size)?;
            let reader = Box::new(partitions::Reader::open(&source.path)?);
            let recording_id = reader.recording_id;
            (Input::Partitioned(reader, records), Some(recording_id))
        } else {
            (
                Input::Flat(BufReader::new(File::open(&source.path)?)),
                super::compact::flat_recording_id(&source.path)?,
            )
        };
        let compact = recording_id
            .map(|id| {
                if verify {
                    compact::Reader::open(&source.path, id)
                } else {
                    compact::Reader::open_for_replay(&source.path, id)
                }
            })
            .transpose()?;
        Ok(Self {
            verify,
            path: path.to_owned(),
            stamp,
            reader,
            buffer: Vec::new(),
            materialized: Vec::new(),
            offset: 0,
            line: 0,
            source,
            position: 0,
            compact,
        })
    }

    pub fn scope_membership_sha256(&self) -> Result<Option<String>> {
        self.source.membership_sha256()
    }

    pub(super) fn uses_locations(&self) -> bool {
        self.source.locations.is_some() || matches!(&self.reader, Input::Partitioned(..))
    }

    // Each result borrows the cursor's reusable read buffer.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<(RecordLocation, &[u8])>> {
        let Some(location) = self.next_row(self.verify)? else {
            return Ok(None);
        };
        if let Some(compact) = &self.compact {
            compact::encode_materialized(&compact.read(&self.buffer)?, &mut self.materialized)?;
            return Ok(Some((location, &self.materialized)));
        }
        Ok(Some((location, &self.buffer)))
    }

    /// Index builders keep the canonical materialized bytes for existing hashes,
    /// while using the decoded value directly for projection.
    pub(super) fn next_value(&mut self) -> Result<Option<DecodedRow<'_>>> {
        let Some(location) = self.next_row(true)? else {
            return Ok(None);
        };
        if let Some(compact) = &self.compact {
            let value = compact.read(&self.buffer)?;
            compact::encode_materialized(&value, &mut self.materialized)?;
            return Ok(Some((location, &self.materialized, Some(value))));
        }
        let value = if self.buffer.iter().all(u8::is_ascii_whitespace) {
            None
        } else {
            Some(serde_json::from_slice(&self.buffer).with_context(|| {
                format!(
                    "invalid dependency evidence {} line {}",
                    self.path.display(),
                    location.line
                )
            })?)
        };
        Ok(Some((location, &self.buffer, value)))
    }

    fn next_row(&mut self, record_digest: bool) -> Result<Option<RecordLocation>> {
        self.buffer.clear();
        if let Some(locations) = &self.source.locations {
            let Some(location) = locations.get(self.position).cloned() else {
                self.validate_stamp()?;
                return Ok(None);
            };
            match &mut self.reader {
                Input::Flat(reader) => {
                    reader.seek(SeekFrom::Start(location.offset))?;
                    self.buffer.resize(usize::try_from(location.length)?, 0);
                    reader.read_exact(&mut self.buffer)?;
                }
                Input::Partitioned(reader, _) => {
                    reader.read(
                        location.line,
                        Some((location.offset, location.length)),
                        &mut self.buffer,
                    )?;
                }
            }
            ensure!(
                !self.verify || digest(&self.buffer) == location.sha256,
                "central dependency record checksum mismatch"
            );
            self.position += 1;
            return Ok(Some(location));
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
            Input::Partitioned(reader, records) => {
                if self.line as u64 == *records {
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
            self.validate_stamp()?;
            return Ok(None);
        }
        self.line += 1;
        let location = RecordLocation {
            line: self.line,
            offset: self.offset,
            length,
            sha256: if record_digest {
                digest(&self.buffer)
            } else {
                String::new()
            },
        };
        self.offset = self
            .offset
            .checked_add(length)
            .context("dependency row offset overflow")?;
        Ok(Some(location))
    }

    fn validate_stamp(&self) -> Result<()> {
        if !self.verify {
            return Ok(());
        }
        if let Some(compact) = &self.compact {
            compact.validate()?;
        }
        super::scoped::validate_stamp(&self.path, &self.stamp)
    }
}
