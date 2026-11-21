//! Seekable event trace locations. The journals remain the Source of event order.
use crate::{event_format::decode_event, partitions, source::FileStamp};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use traffic_model::trace::{CaptureEvent, RecordedEvent};

mod writer;
pub(crate) use writer::EventLocations;

pub(crate) const INDEX: &str = "event-locations.bin";
const POSTINGS: &str = "event-spans.bin";
pub(crate) const FILES: [&str; 2] = [INDEX, POSTINGS];
pub(crate) const JOURNALS: [&str; 2] = [
    partitions::FILES[partitions::ORDINARY],
    partitions::FILES[partitions::PUSH],
];
const ENTRY_BYTES: u64 = 8;
const POSTING_HEADER_BYTES: u64 = 5;
const SPAN_BYTES: u64 = 12;

#[derive(Debug)]
struct Span {
    offset: u64,
    length: u32,
}

fn locator_position(dependency: u64) -> Result<u64> {
    dependency
        .checked_sub(1)
        .and_then(|sequence| sequence.checked_mul(ENTRY_BYTES))
        .context("invalid dependency event locator sequence")
}

/// A compact directory shared by the Replay plans of one sealed run.
#[derive(Debug)]
pub struct SourceEventIndex {
    root: PathBuf,
    recording_id: uuid::Uuid,
    locators: FileStamp,
    postings: FileStamp,
    journals: [FileStamp; JOURNALS.len()],
    verify: bool,
}

fn bytes<const N: usize>(input: &mut impl Read) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

impl SourceEventIndex {
    pub(crate) fn open(root: PathBuf, recording_id: uuid::Uuid) -> Result<Self> {
        Self::open_with_verification(root, recording_id, true)
    }

    pub(crate) fn open_for_replay(root: PathBuf, recording_id: uuid::Uuid) -> Result<Self> {
        Self::open_with_verification(root, recording_id, false)
    }

    fn open_with_verification(
        root: PathBuf,
        recording_id: uuid::Uuid,
        verify: bool,
    ) -> Result<Self> {
        let locators = FileStamp::read_native(&root.join(INDEX))?;
        let postings = FileStamp::read_native(&root.join(POSTINGS))?;
        ensure!(
            locators.size.is_multiple_of(ENTRY_BYTES),
            "event locator file has an incomplete entry"
        );
        Ok(Self {
            recording_id,
            journals: [
                FileStamp::read_native(&root.join(JOURNALS[0]))?,
                FileStamp::read_native(&root.join(JOURNALS[1]))?,
            ],
            root,
            locators,
            postings,
            verify,
        })
    }

    pub fn selected(
        &self,
        dependencies: impl IntoIterator<Item = u64>,
    ) -> Result<impl Iterator<Item = Result<RecordedEvent<CaptureEvent>>>> {
        let selected: BTreeSet<u64> = dependencies.into_iter().collect();
        let locator_path = self.root.join(INDEX);
        let posting_path = self.root.join(POSTINGS);
        if self.verify {
            self.validate(&locator_path, &posting_path)?;
        }
        let mut locations = [Vec::new(), Vec::new()];
        if !selected.is_empty() {
            let mut locators = BufReader::new(File::open(&locator_path)?);
            let mut postings = BufReader::new(File::open(&posting_path)?);
            let mut cursor = 0;
            let mut posting_cursor = 0;
            for dependency in selected {
                let position = locator_position(dependency)?;
                ensure!(
                    position
                        .checked_add(ENTRY_BYTES)
                        .is_some_and(|end| end <= self.locators.size),
                    "dependency {dependency} has no recorded event trace"
                );
                if position != cursor {
                    seek(&mut locators, cursor, position)?;
                }
                cursor = position + ENTRY_BYTES;
                let pointer = u64::from_le_bytes(bytes(&mut locators)?);
                let posting = pointer.checked_sub(1).with_context(|| {
                    format!("dependency {dependency} has no recorded event trace")
                })?;
                if posting_cursor != posting {
                    seek(&mut postings, posting_cursor, posting)?;
                }
                posting_cursor =
                    self.read_locations(&mut postings, &mut locations, dependency, posting)?;
            }
        }
        if self.verify {
            self.validate(&locator_path, &posting_path)?;
        }
        let [ordinary, pushes] = locations;
        let ordinary = Journal::open(
            self.root.join(JOURNALS[0]),
            &self.journals[0],
            ordinary,
            self.recording_id,
            self.verify,
        )?;
        let pushes = Journal::open(
            self.root.join(JOURNALS[1]),
            &self.journals[1],
            pushes,
            self.recording_id,
            self.verify,
        )?;
        Ok(merge(
            ordinary.into_iter().flatten(),
            pushes.into_iter().flatten(),
            true,
        ))
    }

    fn validate(&self, locator_path: &Path, posting_path: &Path) -> Result<()> {
        ensure!(
            FileStamp::read_native(locator_path)? == self.locators
                && FileStamp::read_native(posting_path)? == self.postings,
            "Source event directory changed"
        );
        Ok(())
    }

    fn read_locations(
        &self,
        postings: &mut BufReader<File>,
        locations: &mut [Vec<(Span, u64)>; 2],
        dependency: u64,
        position: u64,
    ) -> Result<u64> {
        ensure!(
            position
                .checked_add(POSTING_HEADER_BYTES)
                .is_some_and(|end| end <= self.postings.size),
            "event trace locator escapes its posting file"
        );
        let journal = usize::from(bytes::<1>(postings)?[0]);
        let count = u32::from_le_bytes(bytes(postings)?);
        ensure!(
            count > 0
                && journal < locations.len()
                && position
                    .checked_add(POSTING_HEADER_BYTES + u64::from(count) * SPAN_BYTES)
                    .is_some_and(|end| end <= self.postings.size),
            "invalid Source event trace posting"
        );
        for _ in 0..count {
            let offset = u64::from_le_bytes(bytes(postings)?);
            let length = u32::from_le_bytes(bytes(postings)?);
            locations[journal].push((Span { offset, length }, dependency));
        }
        Ok(position + POSTING_HEADER_BYTES + u64::from(count) * SPAN_BYTES)
    }
}

fn seek(reader: &mut BufReader<File>, current: u64, next: u64) -> Result<()> {
    if let Ok(distance) = i64::try_from(i128::from(next) - i128::from(current)) {
        reader.seek_relative(distance)?;
    } else {
        reader.seek(SeekFrom::Start(next))?;
    }
    Ok(())
}

struct Journal {
    recording_id: uuid::Uuid,
    path: PathBuf,
    stamp: FileStamp,
    reader: BufReader<File>,
    location: std::vec::IntoIter<(Span, u64)>,
    row: Vec<u8>,
    position: u64,
    finished: bool,
    verify: bool,
}

impl Journal {
    fn open(
        path: PathBuf,
        stamp: &FileStamp,
        mut locations: Vec<(Span, u64)>,
        recording_id: uuid::Uuid,
        verify: bool,
    ) -> Result<Option<Self>> {
        if locations.is_empty() {
            return Ok(None);
        }
        locations.sort_unstable_by_key(|(span, _)| span.offset);
        if verify {
            ensure!(
                FileStamp::read_native(&path)? == *stamp,
                "Source event journal changed"
            );
        }
        let reader = BufReader::with_capacity(64 * 1024, File::open(&path)?);
        Ok(Some(Self {
            recording_id,
            path,
            stamp: stamp.clone(),
            reader,
            location: locations.into_iter(),
            row: Vec::new(),
            position: 0,
            finished: false,
            verify,
        }))
    }

    fn read(&mut self) -> Result<Option<RecordedEvent<CaptureEvent>>> {
        let Some((span, expected)) = self.location.next() else {
            if self.verify {
                ensure!(
                    FileStamp::read_native(&self.path)? == self.stamp,
                    "Source event journal changed"
                );
            }
            return Ok(None);
        };
        let end = span
            .offset
            .checked_add(u64::from(span.length))
            .context("event span overflow")?;
        ensure!(
            span.length > 0 && span.offset >= self.position && end <= self.stamp.size,
            "invalid event span"
        );
        if span.offset != self.position {
            seek(&mut self.reader, self.position, span.offset)?;
        }
        self.row.resize(span.length as usize, 0);
        self.reader.read_exact(&mut self.row)?;
        self.position = end;
        let event = decode_event(std::str::from_utf8(&self.row)?, self.recording_id)?;
        ensure!(
            event.event.dependency_sequence() == Some(expected),
            "selected Source event has a foreign dependency"
        );
        Ok(Some(event))
    }
}

impl Iterator for Journal {
    type Item = Result<RecordedEvent<CaptureEvent>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let result = self.read();
        self.finished = !matches!(result, Ok(Some(_)));
        result.transpose()
    }
}

pub(crate) fn merge(
    ordinary: impl Iterator<Item = Result<RecordedEvent<CaptureEvent>>>,
    pushes: impl Iterator<Item = Result<RecordedEvent<CaptureEvent>>>,
    ordered: bool,
) -> impl Iterator<Item = Result<RecordedEvent<CaptureEvent>>> {
    let mut ordinary = ordinary.peekable();
    let mut pushes = pushes.peekable();
    let mut last = 0;
    let mut failed = false;
    std::iter::from_fn(move || {
        if failed {
            return None;
        }
        let next = match (ordinary.peek(), pushes.peek()) {
            (Some(Ok(left)), Some(Ok(right))) if right.sequence < left.sequence => pushes.next(),
            (_, Some(Err(_))) | (None, _) => pushes.next(),
            _ => ordinary.next(),
        }?;
        let result = next.and_then(|event| {
            ensure!(
                !ordered || event.sequence > last,
                "unordered or duplicate Source event sequence"
            );
            last = event.sequence;
            Ok(event)
        });
        failed = result.is_err();
        Some(result)
    })
}
