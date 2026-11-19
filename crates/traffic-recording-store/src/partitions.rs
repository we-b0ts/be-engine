//! Physical dependency partitions and the ordered directory of their rows.
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use traffic_model::attribution::DependencyOwner;
use uuid::Uuid;

pub(crate) const DIRECTORY: &str = "dependency-locations.bin";
pub(crate) const PUSH_DEPENDENCIES: &str = "dependencies-push.tsv";
pub(crate) const ORDINARY: usize = 0;
pub(crate) const PUSH: usize = 2;
pub(crate) const FILES: [&str; 5] = [
    crate::format::DEPENDENCIES,
    "dependencies-process.tsv",
    PUSH_DEPENDENCIES,
    "dependencies-unattributed.tsv",
    "observations.tsv",
];
const HEADER_BYTES: usize = 16;
const ENTRY_BYTES: u64 = 49;

pub(crate) fn record_count(size: u64) -> Result<u64> {
    let entries_bytes = size
        .checked_sub(HEADER_BYTES as u64)
        .context("missing dependency partition directory header")?;
    ensure!(
        entries_bytes.is_multiple_of(ENTRY_BYTES),
        "truncated dependency partition directory"
    );
    Ok(entries_bytes / ENTRY_BYTES)
}

fn read_recording_id(input: &mut impl Read) -> Result<Uuid> {
    let mut bytes = [0; HEADER_BYTES];
    input
        .read_exact(&mut bytes)
        .context("missing dependency partition recording identity")?;
    Ok(Uuid::from_bytes(bytes))
}

pub(crate) fn recording_id(path: &Path) -> Result<Uuid> {
    crate::source::FileStamp::read_native(path)?;
    read_recording_id(&mut File::open(path)?)
}

#[derive(Clone, Copy)]
pub enum RecordKind {
    Exchange,
    Message,
    Observation,
}

pub(crate) fn partition(owner: &DependencyOwner, kind: RecordKind) -> usize {
    match (owner, kind) {
        (_, RecordKind::Observation) => 4,
        (DependencyOwner::Unattributed { .. }, _) => 3,
        (_, RecordKind::Message) => PUSH,
        (DependencyOwner::Case { .. }, _) => ORDINARY,
        _ => 1,
    }
}

pub(crate) fn is_directory(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == DIRECTORY)
}

pub(crate) struct Span {
    pub logical: u64,
    pub header_offset: u64,
    pub header_length: u64,
    pub request_length: u64,
    pub response_offset: u64,
    pub response_length: u64,
    pub partition: usize,
}

impl Span {
    pub(crate) fn length(&self) -> Result<u64> {
        self.header_length
            .checked_add(self.request_length.max(1))
            .and_then(|length| length.checked_add(self.response_length))
            .and_then(|length| length.checked_add(3))
            .context("dependency record length overflow")
    }

    pub(crate) fn encode(&self) -> [u8; ENTRY_BYTES as usize] {
        let mut row = [0; ENTRY_BYTES as usize];
        row[0..8].copy_from_slice(&self.logical.to_le_bytes());
        row[8..16].copy_from_slice(&self.header_offset.to_le_bytes());
        row[16..24].copy_from_slice(&self.header_length.to_le_bytes());
        row[24..32].copy_from_slice(&self.request_length.to_le_bytes());
        row[32..40].copy_from_slice(&self.response_offset.to_le_bytes());
        row[40..48].copy_from_slice(&self.response_length.to_le_bytes());
        row[48] = self.partition as u8;
        row
    }

    fn decode(row: [u8; ENTRY_BYTES as usize]) -> Result<Self> {
        let partition = usize::from(row[48]);
        ensure!(partition < FILES.len(), "unknown dependency partition");
        let header_length = u64::from_le_bytes(row[16..24].try_into()?);
        let response_length = u64::from_le_bytes(row[40..48].try_into()?);
        ensure!(
            header_length > 0 && response_length > 0,
            "empty dependency cell span"
        );
        Ok(Self {
            logical: u64::from_le_bytes(row[0..8].try_into()?),
            header_offset: u64::from_le_bytes(row[8..16].try_into()?),
            header_length,
            request_length: u64::from_le_bytes(row[24..32].try_into()?),
            response_offset: u64::from_le_bytes(row[32..40].try_into()?),
            response_length,
            partition,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Reader {
    root: PathBuf,
    directory: BufReader<File>,
    pub(crate) recording_id: Uuid,
    partitions: [Option<PartitionInput>; FILES.len()],
    next_line: usize,
}

#[derive(Debug)]
struct PartitionInput {
    file: BufReader<File>,
    length: u64,
    position: u64,
}

impl Reader {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let root = path
            .parent()
            .context("missing dependency directory root")?
            .into();
        let mut directory = BufReader::new(File::open(path)?);
        let recording_id = read_recording_id(&mut directory)?;
        Ok(Self {
            root,
            directory,
            recording_id,
            partitions: Default::default(),
            next_line: 1,
        })
    }

    pub(crate) fn read(
        &mut self,
        line: usize,
        expected: Option<(u64, u64)>,
        bytes: &mut Vec<u8>,
    ) -> Result<Span> {
        self.read_cells(line, expected, bytes, false)
    }

    pub(crate) fn read_header(
        &mut self,
        line: usize,
        expected: (u64, u64),
        bytes: &mut Vec<u8>,
    ) -> Result<()> {
        self.read_cells(line, Some(expected), bytes, true)?;
        Ok(())
    }

    pub(crate) fn span(&mut self, line: usize) -> Result<Span> {
        if line != self.next_line {
            let position = u64::try_from(line.checked_sub(1).context("invalid dependency line")?)?
                .checked_mul(ENTRY_BYTES)
                .and_then(|offset| offset.checked_add(HEADER_BYTES as u64))
                .context("dependency directory position overflow")?;
            self.directory.seek(SeekFrom::Start(position))?;
        }
        let mut entry = [0; ENTRY_BYTES as usize];
        self.directory.read_exact(&mut entry)?;
        self.next_line = line.checked_add(1).context("dependency line overflow")?;
        Span::decode(entry)
    }

    fn read_cells(
        &mut self,
        line: usize,
        expected: Option<(u64, u64)>,
        bytes: &mut Vec<u8>,
        header_only: bool,
    ) -> Result<Span> {
        let span = self.span(line)?;
        let length = span.length()?;
        ensure!(
            expected.is_none_or(|expected| expected == (span.logical, length)),
            "dependency scope does not match its partition directory"
        );
        let file = &mut self.partitions[span.partition];
        if file.is_none() {
            let path = self.root.join(FILES[span.partition]);
            let length = crate::source::FileStamp::read_native(&path)?.size;
            *file = Some(PartitionInput {
                file: BufReader::with_capacity(64 * 1024, File::open(path)?),
                length,
                position: 0,
            });
        }
        let file = file.as_mut().context("missing dependency partition")?;
        bytes.clear();
        let header_length = if !header_only && span.request_length > 0 {
            span.header_length
                .checked_add(1)
                .and_then(|length| length.checked_add(span.request_length))
                .context("dependency request span overflow")?
        } else {
            span.header_length
        };
        file.read(span.header_offset, header_length, bytes)?;
        if header_only {
            bytes.extend_from_slice(b"\t-\t-\n");
        } else {
            if span.request_length == 0 {
                bytes.extend_from_slice(b"\t-");
            }
            bytes.push(b'\t');
            file.read(span.response_offset, span.response_length, bytes)?;
            bytes.push(b'\n');
        }
        Ok(span)
    }
}

impl PartitionInput {
    fn read(&mut self, offset: u64, length: u64, bytes: &mut Vec<u8>) -> Result<()> {
        let end = offset
            .checked_add(length)
            .context("dependency span overflow")?;
        ensure!(end <= self.length, "dependency span escapes its partition");
        if self.position != offset {
            if let Ok(distance) = i64::try_from(i128::from(offset) - i128::from(self.position)) {
                self.file.seek_relative(distance)?;
            } else {
                self.file.seek(SeekFrom::Start(offset))?;
            }
        }
        let start = bytes.len();
        let size = start
            .checked_add(usize::try_from(length)?)
            .context("dependency span exceeds address space")?;
        bytes.resize(size, 0);
        self.file.read_exact(&mut bytes[start..])?;
        self.position = end;
        Ok(())
    }
}
