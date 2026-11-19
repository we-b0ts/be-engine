//! Physical dependency partitions and the ordered directory of their rows.
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use traffic_model::attribution::DependencyOwner;

pub(crate) const DIRECTORY: &str = "dependency-locations.bin";
pub(crate) const FILES: [&str; 4] = [
    crate::format::DEPENDENCIES,
    "dependencies-process.tsv",
    "dependencies-push.tsv",
    "dependencies-unattributed.tsv",
];
pub(crate) const ENTRY_BYTES: u64 = 25;

pub(crate) fn partition(owner: &DependencyOwner, message: bool) -> usize {
    match owner {
        DependencyOwner::Unattributed { .. } => 3,
        _ if message => 2,
        DependencyOwner::Case { .. } => 0,
        _ => 1,
    }
}

pub(crate) fn is_directory(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == DIRECTORY)
}

pub(crate) struct Span {
    pub logical: u64,
    pub offset: u64,
    pub length: u64,
    pub partition: usize,
}

impl Span {
    pub(crate) fn encode(&self) -> [u8; ENTRY_BYTES as usize] {
        let mut row = [0; ENTRY_BYTES as usize];
        row[0..8].copy_from_slice(&self.logical.to_le_bytes());
        row[8..16].copy_from_slice(&self.offset.to_le_bytes());
        row[16..24].copy_from_slice(&self.length.to_le_bytes());
        row[24] = self.partition as u8;
        row
    }

    fn decode(row: [u8; ENTRY_BYTES as usize]) -> Result<Self> {
        let partition = usize::from(row[24]);
        ensure!(partition < FILES.len(), "unknown dependency partition");
        let logical = u64::from_le_bytes(row[0..8].try_into()?);
        let offset = u64::from_le_bytes(row[8..16].try_into()?);
        let length = u64::from_le_bytes(row[16..24].try_into()?);
        ensure!(length > 0, "empty dependency row span");
        Ok(Self {
            logical,
            offset,
            length,
            partition,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Reader {
    root: PathBuf,
    directory: BufReader<File>,
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
        Ok(Self {
            root,
            directory: BufReader::new(File::open(path)?),
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
        if line != self.next_line {
            let position = u64::try_from(line.checked_sub(1).context("invalid dependency line")?)?
                .checked_mul(ENTRY_BYTES)
                .context("dependency directory position overflow")?;
            self.directory.seek(SeekFrom::Start(position))?;
        }
        let mut entry = [0; ENTRY_BYTES as usize];
        self.directory.read_exact(&mut entry)?;
        self.next_line = line.checked_add(1).context("dependency line overflow")?;
        let span = Span::decode(entry)?;
        ensure!(
            expected.is_none_or(|expected| expected == (span.logical, span.length)),
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
        let end = span
            .offset
            .checked_add(span.length)
            .context("dependency span overflow")?;
        ensure!(end <= file.length, "dependency span escapes its partition");
        if file.position != span.offset {
            file.file.seek(SeekFrom::Start(span.offset))?;
        }
        bytes.resize(usize::try_from(span.length)?, 0);
        file.file.read_exact(bytes)?;
        file.position = end;
        Ok(span)
    }
}
