//! Resolve and verify the payloads referenced by one compact dependency row.
use crate::dependency_columns::{FILE, ReadTerms, TermsStamp};
use crate::format::{PayloadRef, PendingDependency};
use crate::partitions;
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use std::{
    cell::{Cell, RefCell},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

use super::segment_window::SegmentWindow;

pub(super) fn is_compact(path: &Path) -> bool {
    is_session(path)
        || partitions::is_directory(path)
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| partitions::FILES.contains(&name))
}

pub(super) fn is_session(path: &Path) -> bool {
    path.parent().is_some_and(|root| {
        (path.ends_with(crate::session::FILE)
            || path == crate::session_records::observation_path(root))
            && !root.join(partitions::DIRECTORY).exists()
            && root.join(crate::session::FILE).is_file()
    })
}

pub(super) fn flat_recording_id(path: &Path) -> Result<Option<Uuid>> {
    if is_session(path) {
        let (_, manifest) = super::recording::manifest(path)?;
        ensure!(
            manifest.schema == traffic_model::recording::SESSION_RECORDING_SCHEMA,
            "unsupported Session recording schema"
        );
        return Ok(Some(manifest.run_epoch));
    }
    if !is_compact(path) {
        return Ok(None);
    }
    partitions::recording_id(&path.with_file_name(partitions::DIRECTORY)).map(Some)
}

#[derive(Debug)]
pub(super) struct Reader {
    root: PathBuf,
    recording_id: Uuid,
    terms: ReadTerms,
    stamp: Option<TermsStamp>,
    payload_dir_opened: Cell<bool>,
    segment: RefCell<Option<Segment>>,
    replay_segments: Option<RefCell<SegmentWindow>>,
    verified_payloads: bool,
}

#[derive(Debug)]
struct Segment {
    number: u64,
    file: File,
    length: u64,
}

impl Reader {
    pub(super) fn recording_id(&self) -> Uuid {
        self.recording_id
    }
    pub(super) fn open(path: &Path, recording_id: Uuid) -> Result<Self> {
        Self::open_with(path, recording_id, false, false)
    }

    pub(super) fn open_for_replay(path: &Path, recording_id: Uuid) -> Result<Self> {
        Self::open_with(path, recording_id, true, false)
    }

    /// The recording must remain immutable while any mapped slice is live.
    pub(super) unsafe fn open_for_session_replay(path: &Path, recording_id: Uuid) -> Result<Self> {
        Self::open_with(path, recording_id, true, true)
    }

    fn open_with(
        path: &Path,
        recording_id: Uuid,
        replay: bool,
        map_payloads: bool,
    ) -> Result<Self> {
        let root = path
            .parent()
            .context("compact dependency has no recording root")?
            .to_owned();
        let streaming_manifest = is_session(path)
            .then(|| super::recording::manifest(path).map(|(_, manifest)| manifest))
            .transpose()?;
        let (terms, stamp) = if replay && streaming_manifest.is_none() {
            (ReadTerms::open_for_replay(&root)?, None)
        } else {
            let (terms, stamp) = ReadTerms::open(&root)?;
            (terms, Some(stamp))
        };
        let replay_segments = replay.then(|| {
            let window = if map_payloads {
                // SAFETY: only the immutable Session Replay constructor enables mappings.
                unsafe { SegmentWindow::new(root.clone()) }
            } else {
                SegmentWindow::new_copying(root.clone())
            };
            RefCell::new(match &streaming_manifest {
                Some(manifest) => window.with_seal(manifest),
                None => window,
            })
        });
        Ok(Self {
            root,
            recording_id,
            terms,
            stamp,
            payload_dir_opened: Cell::new(false),
            segment: RefCell::new(None),
            replay_segments,
            verified_payloads: streaming_manifest.is_some(),
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        if let Some(stamp) = &self.stamp {
            stamp.validate(&self.root.join(FILE))?;
        }
        Ok(())
    }

    pub(super) fn read(&self, row: &[u8]) -> Result<serde_json::Value> {
        PendingDependency::materialize(row, self.recording_id, &self.terms, |reference| {
            self.read_payload(reference)
        })
    }

    pub(super) fn read_header(&self, row: &[u8]) -> Result<serde_json::Value> {
        PendingDependency::materialize_header(row, self.recording_id, &self.terms)
    }

    pub(super) fn read_request(&self, row: &[u8]) -> Result<serde_json::Value> {
        PendingDependency::materialize_request(row, self.recording_id, &self.terms, |reference| {
            self.read_payload(reference)
        })
    }

    pub(super) fn read_response_bytes(&self, cell: &[u8]) -> Result<Option<Bytes>> {
        let Some(window) = &self.replay_segments else {
            return Ok(None);
        };
        let Some(reference) = crate::format::response_payload_ref(cell)? else {
            return Ok(None);
        };
        window.borrow_mut().read(&reference).map(Some)
    }

    fn read_payload(&self, reference: &PayloadRef) -> Result<Vec<u8>> {
        if let Some(window) = &self.replay_segments
            && self.verified_payloads
        {
            return Ok(window.borrow_mut().read(reference)?.to_vec());
        }
        let mut segment = self.segment.borrow_mut();
        if segment
            .as_ref()
            .is_none_or(|loaded| loaded.number != reference.segment)
        {
            if !self.payload_dir_opened.get() {
                ensure!(
                    fs::symlink_metadata(self.root.join("payload"))?.is_dir(),
                    "dependency payload directory must be a real directory"
                );
                self.payload_dir_opened.set(true);
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(self.root.join(PayloadRef::path(reference.segment)))?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file(),
                "dependency payload segment is not a regular file"
            );
            *segment = Some(Segment {
                number: reference.segment,
                file,
                length: metadata.len(),
            });
        }
        let segment = segment.as_mut().expect("opened payload segment");
        ensure!(
            reference
                .offset
                .checked_add(reference.length)
                .is_some_and(|end| end <= segment.length),
            "dependency payload range escapes its segment"
        );
        segment.file.seek(SeekFrom::Start(reference.offset))?;
        let mut bytes = vec![0; usize::try_from(reference.length)?];
        segment.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

pub(super) fn encode_materialized(record: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
    out.clear();
    serde_json::to_writer(&mut *out, record)?;
    out.push(b'\n');
    Ok(())
}
