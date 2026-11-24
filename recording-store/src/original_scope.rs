//! Append-time membership of the four recording-wide dependency scopes.
use std::{
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use traffic_model::recording::{
    LedgerFileIdentity, SCOPE_SCHEMA, ScopeIndex, ScopeKind, ScopeRecordLocation,
};
use uuid::Uuid;

use crate::{
    partitions,
    source::{FileStamp, RecordLocation},
    writer::{FileDigest, JsonlWriterPool},
};

pub(crate) const FILES: [&str; 4] = [
    "indexes/startup-scope.bin",
    "indexes/process-scope.bin",
    "indexes/shutdown-scope.bin",
    "indexes/unattributed-scope.bin",
];
const ENTRY_BYTES: usize = 60;
const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn files(session: bool) -> impl Iterator<Item = (usize, &'static str)> {
    FILES
        .into_iter()
        .enumerate()
        .filter(move |(index, _)| !session || *index == 0)
}

pub(crate) struct OriginalScopes {
    digests: [FileDigest; FILES.len()],
    session: bool,
}

impl OriginalScopes {
    pub(crate) async fn initialize(root: &Path, session: bool) -> Result<Self> {
        tokio::fs::create_dir_all(root.join("indexes")).await?;
        for (_, file) in files(session) {
            crate::storage::write(&root.join(file), b"").await?;
        }
        Ok(Self {
            digests: Default::default(),
            session,
        })
    }

    pub(crate) async fn append(
        &mut self,
        root: &Path,
        files: &mut JsonlWriterPool,
        kind: ScopeKind,
        location: &ScopeRecordLocation,
    ) -> Result<()> {
        let scope = match kind {
            ScopeKind::Startup => 0,
            ScopeKind::Process => 1,
            ScopeKind::Shutdown => 2,
            ScopeKind::Unattributed => 3,
            ScopeKind::Case { .. } => anyhow::bail!("Case dependencies use their Case scope"),
        };
        ensure!(
            !self.session || scope == 0,
            "case attribution scope in a session recording"
        );
        let mut entry = [0; ENTRY_BYTES];
        entry[..8].copy_from_slice(&u64::try_from(location.line)?.to_le_bytes());
        let hash = location.sha256.as_bytes();
        ensure!(hash.len() == 64, "invalid dependency scope digest length");
        for (byte, digits) in entry[8..40].iter_mut().zip(hash.as_chunks::<2>().0) {
            let nibble = |digit| {
                char::from(digit)
                    .to_digit(16)
                    .context("invalid dependency scope digest")
            };
            *byte = (nibble(digits[0])? << 4 | nibble(digits[1])?) as u8;
        }
        entry[40..56].copy_from_slice(location.exchange_id.as_bytes());
        entry[56..].copy_from_slice(&location.effect_index.to_le_bytes());
        files.append(&root.join(FILES[scope]), &entry).await?;
        self.digests[scope].observe(&entry);
        Ok(())
    }

    pub(crate) fn identities(&self) -> Vec<LedgerFileIdentity> {
        files(self.session)
            .map(|(index, name)| self.digests[index].identity(name))
            .collect()
    }
}

fn binary_kind(path: &Path) -> Option<ScopeKind<String>> {
    if path.parent()?.file_name()? != "indexes" {
        return None;
    }
    Some(match path.file_name()?.to_str()? {
        "startup-scope.bin" => ScopeKind::Startup,
        "process-scope.bin" => ScopeKind::Process,
        "shutdown-scope.bin" => ScopeKind::Shutdown,
        "unattributed-scope.bin" => ScopeKind::Unattributed,
        _ => return None,
    })
}

pub(crate) fn binary_view(path: &Path) -> Option<PathBuf> {
    if !matches!(path.extension()?.to_str()?, "bin" | "json") {
        return None;
    }
    let binary = path.with_extension("bin");
    binary_kind(&binary)?;
    binary.is_file().then_some(binary)
}

pub(crate) fn read(path: &Path) -> Option<Result<ScopeIndex<String>>> {
    let kind = binary_kind(path)?;
    Some(read_scope(path, kind))
}

fn read_scope(path: &Path, scope: ScopeKind<String>) -> Result<ScopeIndex<String>> {
    let root = path
        .parent()
        .and_then(Path::parent)
        .context("dependency scope has no recording root")?;
    let dependency_path = root.join(partitions::DIRECTORY);
    let mut directory = partitions::Reader::open(&dependency_path)?;
    let mut locations = Vec::new();
    visit(path, &dependency_path, None, |entry| {
        let location = entry.position(&mut directory)?;
        locations.push(ScopeRecordLocation {
            line: location.line,
            offset: location.offset,
            length: location.length,
            sha256: location.sha256,
            exchange_id: entry.exchange_id,
            effect_index: entry.effect_index,
        });
        Ok(())
    })?;
    Ok(ScopeIndex {
        schema: SCOPE_SCHEMA.into(),
        run_relpath: "..".into(),
        scope,
        locations,
    })
}

pub(crate) fn select(
    root: &Path,
    file: &LedgerFileIdentity,
    exchange_id: Uuid,
) -> Option<Result<(u64, Vec<RecordLocation>)>> {
    FILES.contains(&file.path.as_str()).then(|| {
        let dependency_path = root.join(partitions::DIRECTORY);
        let mut directory = partitions::Reader::open(&dependency_path)?;
        let mut locations = Vec::new();
        let count = visit(
            &root.join(&file.path),
            &dependency_path,
            Some(file),
            |entry| {
                if entry.exchange_id == exchange_id {
                    locations.push(entry.position(&mut directory)?);
                }
                Ok(())
            },
        )?;
        Ok((count, locations))
    })
}

struct Entry {
    line: usize,
    exchange_id: Uuid,
    effect_index: u32,
    digest: [u8; 32],
}

impl Entry {
    fn position(&self, directory: &mut partitions::Reader) -> Result<RecordLocation> {
        let span = directory.span(self.line)?;
        let mut sha256 = String::with_capacity(64);
        for byte in self.digest {
            sha256.push(char::from(HEX[usize::from(byte >> 4)]));
            sha256.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(RecordLocation {
            line: self.line,
            offset: span.logical,
            length: span.length()?,
            sha256,
        })
    }
}

fn visit(
    path: &Path,
    dependency_path: &Path,
    expected: Option<&LedgerFileIdentity>,
    mut visit: impl FnMut(Entry) -> Result<()>,
) -> Result<u64> {
    let stamp = FileStamp::read_native(path)?;
    ensure!(
        stamp.size.is_multiple_of(ENTRY_BYTES as u64),
        "truncated dependency scope positions"
    );
    ensure!(
        expected.is_none_or(|file| file.length == stamp.size),
        "sealed Source locator length changed"
    );
    let directory = FileStamp::read_native(dependency_path)?;
    let records = partitions::record_count(directory.size)?;
    let mut reader = BufReader::new(File::open(path)?);
    let mut hash = expected.map(|_| Sha256::new());
    let mut previous_line = 0;
    let count = stamp.size / ENTRY_BYTES as u64;
    for _ in 0..count {
        let mut row = [0; ENTRY_BYTES];
        reader.read_exact(&mut row)?;
        if let Some(hash) = &mut hash {
            hash.update(row);
        }
        let line = u64::from_le_bytes(row[..8].try_into()?);
        ensure!(
            line > previous_line && line <= records,
            "unordered or invalid dependency scope position"
        );
        visit(Entry {
            line: usize::try_from(line)?,
            exchange_id: Uuid::from_bytes(row[40..56].try_into()?),
            effect_index: u32::from_le_bytes(row[56..].try_into()?),
            digest: row[8..40].try_into()?,
        })?;
        previous_line = line;
    }
    if let Some((hash, expected)) = hash.zip(expected) {
        ensure!(
            format!("{:x}", hash.finalize()) == expected.sha256.trim_start_matches("sha256:"),
            "sealed Source locator content changed"
        );
    }
    ensure!(
        FileStamp::read_native(path)? == stamp,
        "dependency scope changed while opening"
    );
    Ok(count)
}
