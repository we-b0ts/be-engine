//! Resolve immutable scope views to original central-ledger byte locations.
//! Views select evidence; they never authorize ownership or consumption.
use super::{FileStamp, RecordLocation};
use crate::original_scope;
use anyhow::{Context, Result, ensure};
use std::{
    collections::VecDeque,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};
use traffic_model::recording::{
    LedgerFileIdentity, SCOPE_SCHEMA, ScopeIndex, ScopeKind, identity::IdentityKind,
};
use uuid::Uuid;

pub const CASE_SCOPE: &str = "dependency-scope.json";

#[derive(Debug, Clone)]
pub struct Source {
    pub path: PathBuf,
    pub locations: Option<Arc<Vec<RecordLocation>>>,
    pub view: Option<(PathBuf, FileStamp)>,
}

impl Source {
    /// Iterate compact ledger locations for Replay without reading payload cells.
    pub fn replay_locations(&self) -> Result<impl Iterator<Item = Result<RecordLocation>> + '_> {
        let mut selected = self.locations.as_deref().map(|rows| rows.iter());
        let mut session = if selected.is_none() && super::compact::is_session(&self.path) {
            Some(super::RecordStream::open_for_replay(&self.path)?)
        } else {
            None
        };
        let mut central = if selected.is_none() && session.is_none() {
            let count = crate::partitions::record_count(FileStamp::read_native(&self.path)?.size)?;
            let directory = crate::partitions::Reader::open(&self.path)?;
            Some((directory, 1..=usize::try_from(count)?))
        } else {
            None
        };
        Ok(std::iter::from_fn(move || {
            if let Some(rows) = &mut selected {
                return rows.next().cloned().map(Ok);
            }
            if let Some(stream) = &mut session {
                return stream.next_location_for_replay().transpose();
            }
            let (directory, lines) = central.as_mut()?;
            let line = lines.next()?;
            Some(directory.span(line).and_then(|span| {
                Ok(RecordLocation {
                    line,
                    offset: span.logical,
                    length: span.length()?,
                    // The central Replay cursor validates each physical range.
                    // Authenticated evidence readers calculate record digests separately.
                    sha256: String::new(),
                })
            }))
        }))
    }
}

struct CachedScope {
    source: Source,
    ledger: FileStamp,
    bytes: usize,
}
static SCOPES: OnceLock<Mutex<VecDeque<CachedScope>>> = OnceLock::new();
const SCOPE_CACHE_BYTES: usize = 32 * 1024 * 1024;
const SCOPE_CACHE_ENTRIES: usize = 64;

/// The aliases exist only as in-memory addresses for native protocol readers.
/// Recorder never writes per-case or Global payload copies.
pub fn view_path(path: &Path) -> Option<PathBuf> {
    if let Some(binary) = original_scope::binary_view(path) {
        return Some(binary);
    }
    if path
        .file_name()
        .is_some_and(|name| name == CASE_SCOPE || name.to_string_lossy().ends_with("-scope.json"))
    {
        return Some(path.into());
    }
    if path
        .file_name()
        .is_some_and(|name| name == "dependencies.jsonl")
    {
        let scope = path.with_file_name(CASE_SCOPE);
        if scope.is_file() {
            return Some(scope);
        }
    }
    if path
        .file_name()
        .is_some_and(|name| name == "global-dependencies.jsonl")
    {
        let scope = path.parent()?.join("indexes/startup-scope.json");
        return view_path(&scope).filter(|scope| scope.is_file());
    }
    None
}

pub fn resolve(path: &Path) -> Result<Source> {
    let Some(view) = view_path(path) else {
        let physical = if path
            .file_name()
            .is_some_and(|name| name == "dependencies.jsonl")
        {
            super::recording::dependency_path(path.parent().context("dependency has no directory")?)
        } else {
            path.into()
        };
        return Ok(Source {
            path: physical,
            locations: None,
            view: None,
        });
    };
    let stamp = FileStamp::read_native(&view)?;
    let cache = SCOPES.get_or_init(|| Mutex::new(VecDeque::new()));
    {
        let mut cached = cache
            .lock()
            .map_err(|_| anyhow::anyhow!("scope cache lock poisoned"))?;
        if let Some(position) = cached.iter().position(|entry| {
            entry
                .source
                .view
                .as_ref()
                .is_some_and(|(path, current)| path == &view && current == &stamp)
        }) {
            let entry = cached.remove(position).expect("selected cached scope");
            if FileStamp::read_native(&entry.source.path)? == entry.ledger {
                let source = entry.source.clone();
                cached.push_back(entry);
                return Ok(source);
            }
        }
    }
    let scope = read_wire_index(&view)?;
    let parent = view.parent().context("dependency scope has no directory")?;
    let root = fs::canonicalize(parent.join(&scope.run_relpath))?;
    ensure!(
        root.join("dependency-manifest.json").is_file()
            || root.join("recording-run.json").is_file(),
        "dependency scope has no recording boundary"
    );
    let path = super::recording::dependency_path(&root);
    let ledger = FileStamp::read_native(&path)?;
    let partition_records = crate::partitions::is_directory(&path)
        .then(|| crate::partitions::record_count(ledger.size))
        .transpose()?;
    let mut end = 0;
    let mut line = 0;
    let mut locations = Vec::with_capacity(scope.locations.len());
    for item in scope.locations {
        ensure!(
            item.length > 0
                && item.offset >= end
                && item.line > line
                && item.offset.checked_add(item.length).is_some_and(|n| {
                    if let Some(records) = partition_records {
                        item.line as u64 <= records
                    } else {
                        n <= ledger.size
                    }
                }),
            "dependency scope contains overlapping, unordered or invalid locations"
        );
        ensure!(
            item.sha256.len() == 64 && item.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "dependency scope contains an invalid record identity"
        );
        end = item.offset + item.length;
        line = item.line;
        locations.push(RecordLocation {
            line: item.line,
            offset: item.offset,
            length: item.length,
            sha256: item.sha256,
        });
    }
    ensure!(
        FileStamp::read_native(&view)? == stamp,
        "dependency scope changed while opening"
    );
    let bytes = locations
        .iter()
        .map(|location| std::mem::size_of::<RecordLocation>() + location.sha256.capacity())
        .sum::<usize>();
    let source = Source {
        path,
        locations: Some(Arc::new(locations)),
        view: Some((view, stamp)),
    };
    if bytes <= SCOPE_CACHE_BYTES {
        let mut cached = cache
            .lock()
            .map_err(|_| anyhow::anyhow!("scope cache lock poisoned"))?;
        let mut occupied = cached.iter().map(|entry| entry.bytes).sum::<usize>();
        while cached.len() >= SCOPE_CACHE_ENTRIES || occupied + bytes > SCOPE_CACHE_BYTES {
            if let Some(entry) = cached.pop_front() {
                occupied -= entry.bytes;
            } else {
                break;
            }
        }
        cached.push_back(CachedScope {
            source: source.clone(),
            ledger,
            bytes,
        });
    }
    Ok(source)
}

pub fn exists(path: &Path) -> bool {
    view_path(path).is_some_and(|p| p.is_file())
        || path.is_file()
        || path
            .file_name()
            .is_some_and(|name| name == "dependencies.jsonl")
            && path
                .parent()
                .is_some_and(|root| super::recording::dependency_path(root).is_file())
}

pub fn case_path(directory: &Path) -> PathBuf {
    directory.join(CASE_SCOPE)
}

pub fn selected_bytes(path: &Path) -> Result<u64> {
    let source = resolve(path)?;
    if let Some(locations) = source.locations {
        return locations.iter().try_fold(0u64, |n, location| {
            n.checked_add(location.length)
                .context("dependency scope byte count overflow")
        });
    }
    if crate::partitions::is_directory(&source.path) {
        let root = source
            .path
            .parent()
            .context("missing dependency directory root")?;
        let session = root.join(crate::session::FILE).try_exists()?;
        return crate::partitions::files(session).try_fold(0u64, |size, (_, name)| {
            size.checked_add(FileStamp::read_native(&root.join(name))?.size)
                .context("dependency ledger byte count overflow")
        });
    }
    Ok(FileStamp::read_native(&source.path)?.size)
}

pub fn validate_stamp(path: &Path, expected: &FileStamp) -> Result<()> {
    let source = resolve(path)?;
    let actual = FileStamp::read_native(&source.path)?;
    if actual == *expected {
        return source.validate();
    }
    let collecting = source.locations.is_some()
        && source
            .path
            .parent()
            .is_some_and(|root| !root.join("dependency-manifest.json").exists());
    ensure!(
        collecting
            && actual.device == expected.device
            && actual.inode == expected.inode
            && actual.size >= expected.size,
        "dependency evidence changed after admission"
    );
    source.validate()
}

pub fn case_directory(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .context("dependency evidence has no directory")?;
    let Some(view) = view_path(path) else {
        return Ok(parent.into());
    };
    let index = read_wire_index(&view)?;
    let ScopeKind::Case { case_id } = index.scope else {
        anyhow::bail!("dependency scope is not Case owned");
    };
    if parent
        .file_name()
        .is_some_and(|name| name == case_id.as_str())
    {
        return Ok(parent.into());
    }
    let root = fs::canonicalize(
        view.parent()
            .context("scope has no directory")?
            .join(index.run_relpath),
    )?;
    let (_, manifest) = super::recording::manifest(&root)?;
    let case_id = IdentityKind::Case
        .parse(manifest.run_epoch, &case_id)
        .context("invalid Case scope identity")?;
    let input = manifest
        .inputs
        .into_iter()
        .find(|input| input.case_id == case_id)
        .context("Case scope has no original input")?;
    Ok(root.join(input.path))
}

/// Project an on-disk Case ID into the UUID used by attribution and Replay.
pub fn read_index(path: &Path) -> Result<ScopeIndex> {
    let index = read_wire_index(path)?;
    let root = path
        .parent()
        .context("scope has no directory")?
        .join(&index.run_relpath);
    index.try_map_case_id(|id| {
        if let Ok(id) = id.parse::<Uuid>() {
            return Ok(id);
        }
        let epoch = crate::partitions::recording_id(&super::recording::dependency_path(&root))?;
        IdentityKind::Case
            .parse(epoch, &id)
            .context("invalid Case scope identity")
    })
}

pub fn read_index_with_epoch(path: &Path, epoch: Uuid) -> Result<ScopeIndex> {
    read_wire_index(path)?.try_map_case_id(|id| {
        IdentityKind::Case
            .parse(epoch, &id)
            .context("invalid Case scope identity")
    })
}

/// Resolve one exchange from an original binary scope, authenticating the
/// scope's sealed bytes and skipping dependency and payload reads.
pub fn select_original_scope(
    root: &Path,
    file: &LedgerFileIdentity,
    exchange_id: Uuid,
) -> Result<Option<(u64, Vec<RecordLocation>)>> {
    original_scope::select(root, file, exchange_id).transpose()
}

fn read_wire_index(path: &Path) -> Result<ScopeIndex<String>> {
    let binary = original_scope::binary_view(path);
    if let Some(index) = original_scope::read(binary.as_deref().unwrap_or(path)) {
        return index;
    }
    let index: ScopeIndex<String> = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        index.schema == SCOPE_SCHEMA,
        "unsupported dependency scope schema; record with the current engine"
    );
    Ok(index)
}

pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    read_bytes_with_verification(path, true)
}

pub fn read_bytes_for_replay(path: &Path) -> Result<Vec<u8>> {
    read_bytes_with_verification(path, false)
}

fn read_bytes_with_verification(path: &Path, verify: bool) -> Result<Vec<u8>> {
    let source = resolve(path)?;
    if super::compact::is_compact(&source.path) {
        let mut stream = if verify {
            super::RecordStream::open(path)?
        } else {
            super::RecordStream::open_for_replay(path)?
        };
        let mut bytes = Vec::new();
        while let Some((_, record)) = stream.next()? {
            bytes.extend_from_slice(record);
        }
        return Ok(bytes);
    }
    let Some(locations) = &source.locations else {
        return Ok(fs::read(source.path)?);
    };
    let total = locations
        .iter()
        .try_fold(0usize, |n, p| {
            n.checked_add(usize::try_from(p.length).ok()?)
        })
        .context("scope size exceeds address space")?;
    let mut bytes = Vec::with_capacity(total);
    let mut file = fs::File::open(&source.path)?;
    for location in locations.iter() {
        file.seek(SeekFrom::Start(location.offset))?;
        let start = bytes.len();
        bytes.resize(start + usize::try_from(location.length)?, 0);
        file.read_exact(&mut bytes[start..])?;
        ensure!(
            !verify || super::digest(&bytes[start..]) == location.sha256,
            "central dependency record checksum mismatch"
        );
    }
    if verify {
        source.validate()?;
    }
    Ok(bytes)
}

impl Source {
    pub fn membership_sha256(&self) -> Result<Option<String>> {
        // Staging and published scopes have different relative ledger paths.
        // Their ordered, authenticated record references define membership.
        let Some(locations) = &self.locations else {
            return Ok(None);
        };
        self.validate()?;
        Ok(Some(super::digest(&serde_json::to_vec(
            locations.as_ref(),
        )?)))
    }

    pub fn scope_sha256(&self) -> Result<Option<String>> {
        let Some((view, _)) = &self.view else {
            return Ok(None);
        };
        let sha256 = super::digest(&fs::read(view)?);
        self.validate()?;
        Ok(Some(sha256))
    }

    pub fn validate(&self) -> Result<()> {
        if let Some((path, stamp)) = &self.view {
            ensure!(
                FileStamp::read_native(path)? == *stamp,
                "dependency scope changed during traversal"
            );
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn evict_projection(scope: &Path) {
    if let Some(scopes) = SCOPES.get() {
        scopes.lock().unwrap().retain(|entry| {
            entry
                .source
                .view
                .as_ref()
                .is_none_or(|(path, _)| path != scope)
        });
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn projection_is_cached(scope: &Path) -> bool {
    SCOPES.get().is_some_and(|scopes| {
        scopes.lock().unwrap().iter().any(|entry| {
            entry
                .source
                .view
                .as_ref()
                .is_some_and(|(path, _)| path == scope)
        })
    })
}
