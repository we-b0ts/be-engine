//! Primary interaction journal for an authenticated Source session.

use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use traffic_model::{session::SessionEvent, trace::RecordedEvent};

pub const FILE: &str = "request-response.tsv";

pub(crate) fn encode(event: &RecordedEvent<SessionEvent>) -> Result<Vec<u8>> {
    let mut row = Vec::new();
    write!(
        row,
        "{}\t{}\t{}\t",
        event.sequence,
        event.offset_micros,
        event.event.kind()
    )?;
    serde_json::to_writer(&mut row, &event.event)?;
    row.push(b'\n');
    Ok(row)
}

fn decode(row: &str) -> Result<RecordedEvent<SessionEvent>> {
    let mut cells = row.splitn(4, '\t');
    let sequence = cells.next().context("missing event sequence")?.parse()?;
    let offset_micros = cells.next().context("missing event offset")?.parse()?;
    let kind = cells.next().context("missing event kind")?;
    let event: SessionEvent =
        serde_json::from_str(cells.next().context("missing session event payload")?)?;
    ensure!(
        event.kind() == kind,
        "session event kind disagrees with its payload"
    );
    Ok(RecordedEvent {
        sequence,
        offset_micros,
        event,
    })
}

/// Read the primary and lifecycle events of one complete session.
pub fn read(root: &Path) -> Result<Vec<RecordedEvent<SessionEvent>>> {
    let (root, manifest) = crate::source::recording::manifest(root)?;
    ensure!(
        manifest.capture_complete,
        "Source session capture is incomplete"
    );
    ensure!(
        manifest
            .files
            .iter()
            .any(|file| file.path == FILE && file.length > 0),
        "sealed recording has no session events"
    );
    crate::source::recording::authenticate(&root)?;
    let input = BufReader::new(File::open(root.join(FILE))?);
    let mut events = Vec::new();
    let mut previous_seq = 0;
    let mut previous_offset = 0;
    for (index, line) in input.lines().enumerate() {
        let event = decode(&line?).with_context(|| format!("parse {FILE} row {}", index + 1))?;
        ensure!(
            event.sequence > previous_seq && event.offset_micros >= previous_offset,
            "unordered session event {}",
            event.sequence
        );
        previous_seq = event.sequence;
        previous_offset = event.offset_micros;
        events.push(event);
    }
    ensure!(
        matches!(
            events.first().map(|row| &row.event),
            Some(SessionEvent::SourceStart)
        ),
        "Source session does not start with a process launch"
    );
    Ok(events)
}
