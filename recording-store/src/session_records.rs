//! Sequential access to complete dependency cells embedded in Session rows.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_model::recording::{RecordingManifest, SESSION_RECORDING_SCHEMA};

use crate::{
    event_format, partitions, session,
    source::{RecordLocation, RecordStream, digest, recording},
};

pub fn observation_path(root: &Path) -> PathBuf {
    root.join(partitions::FILES[partitions::OBSERVATIONS])
}

pub fn records(root: &Path) -> Result<impl Iterator<Item = Result<Value>> + use<>> {
    let (root, manifest) = recording::manifest(root)?;
    recording::authenticate(&root)?;
    let mut timeline = RecordStream::open(&recording::dependency_path(&root))?;
    let mut observations = (manifest.schema == SESSION_RECORDING_SCHEMA)
        .then(|| RecordStream::open(&observation_path(&root)))
        .transpose()?;
    let mut finished = false;
    Ok(std::iter::from_fn(move || {
        if finished {
            return None;
        }
        let result = (|| {
            if let Some((_, bytes)) = timeline.next()? {
                return Ok(Some(serde_json::from_slice(bytes)?));
            }
            if let Some(stream) = &mut observations
                && let Some((_, bytes)) = stream.next()?
            {
                return Ok(Some(serde_json::from_slice(bytes)?));
            }
            Ok(None)
        })();
        finished = !matches!(result, Ok(Some(_)));
        result.transpose()
    }))
}

/// Find a dependency or its lifecycle event by Source sequence.
pub fn dependency(root: &Path, sequence: u64) -> Result<Value> {
    let (root, manifest) = recording::manifest(root)?;
    ensure!(manifest.capture_complete, "Source lead-in is incomplete");
    recording::authenticate(&root)?;
    if manifest.schema != SESSION_RECORDING_SCHEMA {
        return legacy_dependency(&root, sequence);
    }
    let admission = resolve_admission(&root, &manifest, sequence)?;
    let timeline = crate::session_integrity::events(&root, &manifest)?;
    let observation = File::open(observation_path(&root))?;
    let files: [Box<dyn std::io::Read + Send>; 2] = [timeline, Box::new(observation)];
    let mut row = Vec::new();
    for input in files {
        let mut file = BufReader::new(input);
        while file.read_until(b'\n', &mut row)? > 0 {
            if let Some(cells) = record_cells(&row)?
                && compact_admission(cells)? == admission
            {
                return super::source::materialize_session_row(&root, manifest.run_epoch, cells);
            }
            row.clear();
        }
    }
    anyhow::bail!("no protected dependency record for Source sequence {sequence}")
}

fn resolve_admission(root: &Path, manifest: &RecordingManifest, sequence: u64) -> Result<u64> {
    let mut file = BufReader::new(crate::session_integrity::events(root, manifest)?);
    let mut row = Vec::new();
    while file.read_until(b'\n', &mut row)? > 0 {
        let (row_seq, _, kind, _) = session::parse_prefix(&row)?;
        if row_seq > sequence {
            break;
        }
        if row_seq == sequence {
            if let Some(cells) = record_cells(&row)? {
                return compact_admission(cells);
            }
            if session::primary_kind(kind).is_none()
                && let Some(event) = event_format::decode_stream_event(&row, manifest.run_epoch)?
            {
                return event
                    .event
                    .dependency_sequence()
                    .context("Source event has no dependency");
            }
            break;
        }
        row.clear();
    }
    Ok(sequence)
}

fn legacy_dependency(root: &Path, sequence: u64) -> Result<Value> {
    for row in records(root)? {
        let row = row?;
        if row["capture"]["sequence"].as_u64() == Some(sequence) {
            return Ok(row);
        }
    }
    anyhow::bail!("no protected dependency record for Source sequence {sequence}")
}

pub(crate) fn record_cells(row: &[u8]) -> Result<Option<&[u8]>> {
    let mut columns = row.splitn(4, |byte| *byte == b'\t');
    let kind = columns
        .nth(2)
        .context("missing recording stream row type")?;
    if matches!(kind, b"dependency" | b"notification" | b"observation") {
        return Ok(Some(columns.next().context("missing dependency cells")?));
    }
    Ok(None)
}

pub(crate) fn compact_admission(cells: &[u8]) -> Result<u64> {
    let sequence = cells
        .split(|byte| *byte == b'\t')
        .next()
        .unwrap_or_default();
    Ok(std::str::from_utf8(sequence)?.parse()?)
}

pub(crate) fn next_location(
    input: &mut impl BufRead,
    row: &mut Vec<u8>,
    offset: &mut u64,
    line: &mut usize,
) -> Result<Option<RecordLocation>> {
    loop {
        row.clear();
        let bytes = input.read_until(b'\n', row)?;
        if bytes == 0 {
            return Ok(None);
        }
        *line += 1;
        *offset += bytes as u64;
        if let Some(cells) = record_cells(row)? {
            let prefix = bytes - cells.len();
            let length = cells.len() as u64;
            let sha256 = digest(cells);
            row.copy_within(prefix.., 0);
            row.truncate(bytes - prefix);
            return Ok(Some(RecordLocation {
                line: *line,
                offset: *offset - length,
                length,
                sha256,
            }));
        }
    }
}
