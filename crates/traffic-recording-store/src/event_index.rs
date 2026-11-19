//! Seekable event trace locations. The journals remain the Source of event order.
use crate::{
    format::{EVENTS, PUSH_EVENTS, decode_event},
    source::FileStamp,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use traffic_model::{
    recording::LedgerFileIdentity,
    trace::{CaptureEvent, RecordedEvent},
};

pub(crate) const INDEX: &str = "event-locations.bin";
pub(crate) const JOURNALS: [&str; 2] = [EVENTS, PUSH_EVENTS];
const ENTRY_BYTES: u64 = 21;
const SPAN_BYTES: u64 = 12;

#[derive(Debug)]
struct Span {
    offset: u64,
    length: u32,
}

#[derive(Debug)]
struct Trace {
    dependency: u64,
    first_span: u64,
    count: u32,
    journal: usize,
}

pub(crate) fn seal(root: &Path) -> Result<LedgerFileIdentity> {
    let mut traces = HashMap::<u64, (usize, Vec<Span>)>::new();
    for (journal, filename) in JOURNALS.into_iter().enumerate() {
        let mut reader = BufReader::new(File::open(root.join(filename))?);
        let mut offset = 0;
        let mut row = String::new();
        loop {
            row.clear();
            let length = reader.read_line(&mut row)?;
            if length == 0 {
                break;
            }
            if let Some(dependency) = decode_event(&row)?.event.dependency_sequence() {
                let (owner, spans) = traces
                    .entry(dependency)
                    .or_insert_with(|| (journal, Vec::new()));
                ensure!(
                    *owner == journal,
                    "dependency trace spans two event journals"
                );
                spans.push(Span {
                    offset,
                    length: u32::try_from(length)?,
                });
            }
            offset += length as u64;
        }
    }
    let mut traces = traces.into_iter().collect::<Vec<_>>();
    traces.sort_unstable_by_key(|(dependency, _)| *dependency);
    let mut output = BufWriter::new(File::create(root.join(INDEX))?);
    let mut digest = crate::writer::FileDigest::default();
    let mut write = |bytes: &[u8]| -> Result<()> {
        output.write_all(bytes)?;
        digest.observe(bytes);
        Ok(())
    };
    write(&(traces.len() as u64).to_le_bytes())?;
    let mut first_span = 0u64;
    for (dependency, (journal, spans)) in &traces {
        write(&dependency.to_le_bytes())?;
        write(&first_span.to_le_bytes())?;
        write(&u32::try_from(spans.len())?.to_le_bytes())?;
        write(&[*journal as u8])?;
        first_span += spans.len() as u64;
    }
    for (_, (_, spans)) in traces {
        for span in spans {
            write(&span.offset.to_le_bytes())?;
            write(&span.length.to_le_bytes())?;
        }
    }
    output.flush()?;
    output.get_ref().sync_all()?;
    Ok(digest.identity(INDEX))
}

/// A compact directory shared by the Replay plans of one authenticated run.
#[derive(Debug)]
pub struct SourceEventIndex {
    root: PathBuf,
    stamp: FileStamp,
    traces: Vec<Trace>,
    postings_offset: u64,
    journals: [FileStamp; JOURNALS.len()],
}

fn bytes<const N: usize>(input: &mut impl Read) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

impl SourceEventIndex {
    pub(crate) fn open(root: PathBuf) -> Result<Self> {
        let path = root.join(INDEX);
        let stamp = FileStamp::read_native(&path)?;
        let mut file = BufReader::new(File::open(&path)?);
        let count = u64::from_le_bytes(bytes(&mut file)?);
        let postings_offset = count
            .checked_mul(ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(8))
            .context("event directory size overflow")?;
        ensure!(
            postings_offset <= stamp.size,
            "event directory escapes its file"
        );
        let mut traces = Vec::<Trace>::with_capacity(usize::try_from(count)?);
        let mut expected_span = 0u64;
        for _ in 0..count {
            let trace = Trace {
                dependency: u64::from_le_bytes(bytes(&mut file)?),
                first_span: u64::from_le_bytes(bytes(&mut file)?),
                count: u32::from_le_bytes(bytes(&mut file)?),
                journal: usize::from(bytes::<1>(&mut file)?[0]),
            };
            ensure!(
                trace.dependency > traces.last().map_or(0, |prior| prior.dependency)
                    && trace.first_span == expected_span
                    && trace.count > 0
                    && trace.journal < JOURNALS.len(),
                "invalid event trace directory entry"
            );
            expected_span += u64::from(trace.count);
            traces.push(trace);
        }
        ensure!(
            expected_span
                .checked_mul(SPAN_BYTES)
                .and_then(|len| postings_offset.checked_add(len))
                == Some(stamp.size)
                && FileStamp::read_native(&path)? == stamp,
            "event trace locations changed or are incomplete"
        );
        Ok(Self {
            journals: [
                FileStamp::read_native(&root.join(EVENTS))?,
                FileStamp::read_native(&root.join(PUSH_EVENTS))?,
            ],
            root,
            stamp,
            traces,
            postings_offset,
        })
    }

    pub fn selected(
        &self,
        dependencies: impl IntoIterator<Item = u64>,
    ) -> Result<impl Iterator<Item = Result<RecordedEvent<CaptureEvent>>>> {
        let selected: BTreeSet<u64> = dependencies.into_iter().collect();
        let path = self.root.join(INDEX);
        ensure!(
            FileStamp::read_native(&path)? == self.stamp,
            "Source event directory changed"
        );
        let mut postings = BufReader::new(File::open(&path)?);
        let mut locations = [Vec::new(), Vec::new()];
        let mut cursor = 0;
        for dependency in selected {
            let entry = self
                .traces
                .binary_search_by_key(&dependency, |entry| entry.dependency)
                .map_err(|_| {
                    anyhow::anyhow!("dependency {dependency} has no recorded event trace")
                })?;
            let trace = &self.traces[entry];
            let position = self.postings_offset + trace.first_span * SPAN_BYTES;
            if cursor != position {
                postings.seek(SeekFrom::Start(position))?;
            }
            for _ in 0..trace.count {
                let offset = u64::from_le_bytes(bytes(&mut postings)?);
                let length = u32::from_le_bytes(bytes(&mut postings)?);
                locations[trace.journal].push((Span { offset, length }, dependency));
            }
            cursor = position + u64::from(trace.count) * SPAN_BYTES;
        }
        ensure!(
            FileStamp::read_native(&path)? == self.stamp,
            "Source event directory changed"
        );
        let [ordinary, pushes] = locations;
        let ordinary = Journal::open(self.root.join(EVENTS), &self.journals[0], ordinary)?;
        let pushes = Journal::open(self.root.join(PUSH_EVENTS), &self.journals[1], pushes)?;
        Ok(merge(
            ordinary.into_iter().flatten(),
            pushes.into_iter().flatten(),
            true,
        ))
    }
}

struct Journal {
    path: PathBuf,
    stamp: FileStamp,
    reader: BufReader<File>,
    location: std::vec::IntoIter<(Span, u64)>,
    row: Vec<u8>,
    position: u64,
    finished: bool,
}

impl Journal {
    fn open(
        path: PathBuf,
        stamp: &FileStamp,
        mut locations: Vec<(Span, u64)>,
    ) -> Result<Option<Self>> {
        if locations.is_empty() {
            return Ok(None);
        }
        locations.sort_unstable_by_key(|(span, _)| span.offset);
        ensure!(
            FileStamp::read_native(&path)? == *stamp,
            "Source event journal changed"
        );
        let reader = BufReader::with_capacity(64 * 1024, File::open(&path)?);
        Ok(Some(Self {
            path,
            stamp: stamp.clone(),
            reader,
            location: locations.into_iter(),
            row: Vec::new(),
            position: 0,
            finished: false,
        }))
    }

    fn read(&mut self) -> Result<Option<RecordedEvent<CaptureEvent>>> {
        let Some((span, expected)) = self.location.next() else {
            ensure!(
                FileStamp::read_native(&self.path)? == self.stamp,
                "Source event journal changed"
            );
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
            self.reader.seek(SeekFrom::Start(span.offset))?;
        }
        self.row.resize(span.length as usize, 0);
        self.reader.read_exact(&mut self.row)?;
        self.position = end;
        let event = decode_event(std::str::from_utf8(&self.row)?)?;
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
