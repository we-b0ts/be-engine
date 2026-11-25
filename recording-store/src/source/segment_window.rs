//! Byte access to immutable payload segments with a two-segment forward window.

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fmt,
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
    ptr::NonNull,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{Builder, JoinHandle},
};

use crate::format::{PayloadRef, SEGMENT_BYTES};
use traffic_model::recording::{LedgerFileIdentity, RecordingManifest, SESSION_RECORDING_SCHEMA};

// A single value may take a segment past the rollover target. Larger files
// still support positional reads without expanding the mapping budget.
const MAX_MAPPED_BYTES: u64 = 2 * SEGMENT_BYTES;
const MAPPING_SLOTS: usize = 2;

#[derive(Debug)]
pub(crate) struct SegmentWindow {
    root: PathBuf,
    mapping: bool,
    directory: Option<Arc<File>>,
    current: Option<Segment>,
    next: Option<(u64, JoinHandle<Result<Segment>>)>,
    mapped: Arc<AtomicUsize>,
    identities: Option<Arc<BTreeMap<String, LedgerFileIdentity>>>,
}

impl SegmentWindow {
    /// Open a read-ahead window for a recording that remains immutable.
    ///
    /// # Safety
    ///
    /// The caller must use a sealed recording and keep its segment files
    /// unchanged while this window or any returned byte slice is in use.
    pub(crate) unsafe fn new(root: PathBuf) -> Self {
        let mut window = Self::new_copying(root);
        window.mapping = true;
        window
    }

    pub(crate) fn new_copying(root: PathBuf) -> Self {
        Self {
            root,
            mapping: false,
            directory: None,
            current: None,
            next: None,
            mapped: Arc::default(),
            identities: None,
        }
    }

    pub(crate) fn with_seal(mut self, manifest: &RecordingManifest) -> Self {
        if manifest.schema == SESSION_RECORDING_SCHEMA {
            self.identities = Some(Arc::new(
                manifest
                    .files
                    .iter()
                    .filter(|identity| identity.path.starts_with("payload/"))
                    .map(|identity| (identity.path.clone(), identity.clone()))
                    .collect(),
            ));
        }
        self
    }

    pub(crate) fn read(&mut self, reference: &PayloadRef) -> Result<Bytes> {
        let directory = if let Some(directory) = &self.directory {
            directory.clone()
        } else {
            let directory = Arc::new(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                    .open(self.root.join("payload"))
                    .context("open recording payload directory")?,
            );
            self.directory = Some(directory.clone());
            directory
        };
        let number = reference.segment;
        if self
            .current
            .as_ref()
            .is_some_and(|current| number < current.number)
        {
            // A late dependency cannot move the ordered delivery window back.
            return Segment::open(&directory, number, None, false, self.identities.as_deref())?
                .read(reference);
        }
        if self
            .current
            .as_ref()
            .is_none_or(|current| current.number != number)
        {
            self.current = None;
            let prepared = if self.next.as_ref().is_some_and(|(next, _)| *next == number) {
                self.next
                    .take()
                    .and_then(|(_, task)| task.join().ok()?.ok())
            } else {
                None
            };
            let segment = match prepared {
                Some(mut segment) => {
                    if segment.mapped.is_none() && self.mapping {
                        segment.map(&self.mapped, false);
                    }
                    segment
                }
                None => Segment::open(
                    &directory,
                    number,
                    self.mapping.then_some(&self.mapped),
                    false,
                    self.identities.as_deref(),
                )?,
            };
            self.current = Some(segment);
        }
        let bytes = self
            .current
            .as_ref()
            .expect("current segment")
            .read(reference)?;
        if self.mapping {
            self.prefetch_next(directory, number);
        }
        Ok(bytes)
    }

    fn prefetch_next(&mut self, directory: Arc<File>, current: u64) {
        let Some(number) = current.checked_add(1) else {
            return;
        };
        if self
            .next
            .as_ref()
            .is_some_and(|(next, task)| *next == number || !task.is_finished())
        {
            return;
        }
        self.next = None;
        let mapped = self.mapped.clone();
        let identities = self.identities.clone();
        if let Ok(task) = Builder::new()
            .name("payload-prefault".into())
            .spawn(move || {
                Segment::open(
                    &directory,
                    number,
                    Some(&mapped),
                    true,
                    identities.as_deref(),
                )
            })
        {
            self.next = Some((number, task));
        }
    }
}

struct Segment {
    number: u64,
    file: File,
    length: u64,
    mapped: Option<Bytes>,
}

impl fmt::Debug for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Segment")
            .field("number", &self.number)
            .field("length", &self.length)
            .field("mapped", &self.mapped.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for SegmentWindow {
    fn drop(&mut self) {
        if let Some((_, task)) = self.next.take() {
            let _ = task.join();
        }
    }
}

impl Segment {
    fn open(
        directory: &File,
        number: u64,
        slots: Option<&Arc<AtomicUsize>>,
        prefault: bool,
        identities: Option<&BTreeMap<String, LedgerFileIdentity>>,
    ) -> Result<Self> {
        let path = PayloadRef::path(number);
        let name = CString::new(path.strip_prefix("payload/").expect("payload segment path"))?;
        // SAFETY: name is a NUL-terminated basename and directory is a live fd.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("open {path}"));
        }
        // SAFETY: the successfully opened descriptor is owned exclusively here.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "dependency payload segment is not a regular file"
        );
        let length = metadata.len();
        if let Some(identities) = identities {
            let identity = identities
                .get(&path)
                .context("recording seal omits payload segment")?;
            ensure!(
                length == identity.length,
                "sealed payload length changed: {path}"
            );
            let mut hash = Sha256::new();
            let mut offset = 0;
            let mut buffer = [0; 64 * 1024];
            while offset < length {
                let len = (length - offset).min(buffer.len() as u64) as usize;
                file.read_exact_at(&mut buffer[..len], offset)?;
                hash.update(&buffer[..len]);
                offset += len as u64;
            }
            let after = file.metadata()?;
            ensure!(
                format!("{:x}", hash.finalize()) == identity.sha256
                    && (metadata.ctime(), metadata.ctime_nsec())
                        == (after.ctime(), after.ctime_nsec()),
                "sealed payload changed: {path}"
            );
        }
        let mut segment = Self {
            number,
            file,
            length,
            mapped: None,
        };
        if let Some(slots) = slots {
            segment.map(slots, prefault);
        }
        Ok(segment)
    }

    fn map(&mut self, slots: &Arc<AtomicUsize>, prefault: bool) {
        if (1..=MAX_MAPPED_BYTES).contains(&self.length) {
            self.mapped = Mapping::open(&self.file, self.length as usize, slots, prefault);
        }
    }

    fn read(&self, reference: &PayloadRef) -> Result<Bytes> {
        let end = reference
            .offset
            .checked_add(reference.length)
            .filter(|end| *end <= self.length)
            .context("dependency payload range escapes its segment")?;
        if let Some(mapped) = &self.mapped {
            return Ok(mapped.slice(reference.offset as usize..end as usize));
        }
        let mut bytes = vec![0; usize::try_from(reference.length)?];
        self.file.read_exact_at(&mut bytes, reference.offset)?;
        Ok(bytes.into())
    }
}

struct Mapping {
    address: NonNull<u8>,
    length: usize,
    _permit: MappingPermit,
}

// SAFETY: these mappings are read-only and own their address range. Sealed
// segment contents remain immutable while any slice is live.
unsafe impl Send for Mapping {}

impl Mapping {
    fn open(file: &File, length: usize, slots: &Arc<AtomicUsize>, prefault: bool) -> Option<Bytes> {
        let permit = MappingPermit::acquire(slots)?;
        let flags = libc::MAP_PRIVATE | populate_flag(prefault);
        // SAFETY: file is a live descriptor for a sealed regular file, length
        // was checked against the mapping limit, and offset zero is aligned.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                flags,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return None;
        }
        let Some(address) = NonNull::new(address.cast()) else {
            // SAFETY: a successful mapping at address zero still requires unmapping.
            unsafe { libc::munmap(address, length) };
            return None;
        };
        Some(Bytes::from_owner(Self {
            address,
            length,
            _permit: permit,
        }))
    }
}

impl AsRef<[u8]> for Mapping {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: this owner keeps the successful read-only mapping alive.
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.length) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this mapping owns the whole successful mmap region.
        unsafe { libc::munmap(self.address.as_ptr().cast(), self.length) };
    }
}

#[cfg(target_os = "linux")]
fn populate_flag(prefault: bool) -> libc::c_int {
    if prefault { libc::MAP_POPULATE } else { 0 }
}

#[cfg(not(target_os = "linux"))]
fn populate_flag(_prefault: bool) -> libc::c_int {
    0
}

struct MappingPermit(Arc<AtomicUsize>);

impl MappingPermit {
    fn acquire(slots: &Arc<AtomicUsize>) -> Option<Self> {
        slots
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < MAPPING_SLOTS).then_some(used + 1)
            })
            .ok()?;
        Some(Self(slots.clone()))
    }
}

impl Drop for MappingPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    fn range(segment: u64, offset: u64, length: u64) -> PayloadRef {
        PayloadRef {
            segment,
            offset,
            length,
        }
    }

    #[test]
    fn promotes_prefetched_segments_and_uses_positional_reads_when_mappings_are_pinned() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("payload")).unwrap();
        for (number, bytes) in [b"zero", b"once", b"twos"].into_iter().enumerate() {
            fs::write(dir.path().join(PayloadRef::path(number as u64)), bytes).unwrap();
        }

        // SAFETY: the fixture does not mutate the segments after starting the window.
        let mut window = unsafe { SegmentWindow::new(dir.path().to_owned()) };
        let first = window.read(&range(0, 1, 3)).unwrap();
        assert_eq!(window.next.as_ref().map(|(number, _)| *number), Some(1));
        let second = window.read(&range(1, 0, 3)).unwrap();
        assert_eq!(window.mapped.load(Ordering::Relaxed), 2);
        assert_eq!(window.read(&range(2, 0, 4)).unwrap(), b"twos"[..]);
        assert!(window.current.as_ref().unwrap().mapped.is_none());
        assert_eq!(window.read(&range(0, 0, 4)).unwrap(), b"zero"[..]);
        assert_eq!(window.current.as_ref().unwrap().number, 2);
        drop(window);
        assert_eq!(first, b"ero"[..]);
        assert_eq!(second, b"onc"[..]);
    }

    #[test]
    fn rejects_symlinks_and_out_of_bounds_ranges() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("payload")).unwrap();
        let segment = dir.path().join(PayloadRef::path(0));
        fs::write(&segment, b"sealed").unwrap();
        symlink(&segment, dir.path().join(PayloadRef::path(1))).unwrap();
        // SAFETY: the fixture does not mutate the segments after starting the window.
        let mut window = unsafe { SegmentWindow::new(dir.path().to_owned()) };
        assert!(window.read(&range(0, 5, 2)).is_err());
        assert!(window.read(&range(0, u64::MAX, 1)).is_err());
        assert!(window.read(&range(1, 0, 1)).is_err());

        let other = tempfile::tempdir().unwrap();
        symlink(dir.path().join("payload"), other.path().join("payload")).unwrap();
        // SAFETY: the fixture does not mutate the segments after starting the window.
        let mut window = unsafe { SegmentWindow::new(other.path().to_owned()) };
        assert!(window.read(&range(0, 0, 1)).is_err());
    }
}
