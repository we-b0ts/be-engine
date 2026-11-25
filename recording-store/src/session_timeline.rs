//! Sequential access to the sealed Session timeline without opening payloads.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use traffic_model::trace::{CaptureEvent, RecordedEvent};

use crate::{event_format, session, source::recording};

pub enum SessionTimelineEvent {
    Primary(RecordedEvent<session::PrimaryEventKind>),
    Dependency(RecordedEvent<CaptureEvent>),
}

pub fn read(root: &Path) -> Result<impl Iterator<Item = Result<SessionTimelineEvent>> + use<>> {
    let (root, manifest) = recording::manifest(root)?;
    ensure!(
        manifest.capture_complete,
        "Source session capture is incomplete"
    );
    ensure!(
        manifest
            .files
            .iter()
            .any(|file| file.path == session::FILE && file.length > 0),
        "sealed recording has no session event stream"
    );
    recording::authenticate(&root)?;
    let mut input = BufReader::with_capacity(64 * 1024, File::open(root.join(session::FILE))?);
    let mut row = Vec::new();
    let mut previous = (0, 0);
    let mut saw_primary = false;
    let mut finished = false;
    Ok(std::iter::from_fn(move || {
        if finished {
            return None;
        }
        let result = (|| {
            loop {
                row.clear();
                if input.read_until(b'\n', &mut row)? == 0 {
                    ensure!(saw_primary, "Source session has no primary timeline");
                    return Ok(None);
                }
                let (sequence, offset_micros, kind, _) = session::parse_prefix(&row)?;
                ensure!(
                    sequence > previous.0 && offset_micros >= previous.1,
                    "unordered session event {sequence}"
                );
                previous = (sequence, offset_micros);
                if let Some(event) = session::primary_kind(kind) {
                    ensure!(
                        saw_primary || matches!(event, session::PrimaryEventKind::SourceStart),
                        "Source session does not start with a process launch"
                    );
                    saw_primary = true;
                    return Ok(Some(SessionTimelineEvent::Primary(RecordedEvent {
                        sequence,
                        offset_micros,
                        event,
                    })));
                }
                if let Some(event) = event_format::decode_stream_event(&row, manifest.run_epoch)
                    .with_context(|| format!("parse session event {sequence}"))?
                {
                    return Ok(Some(SessionTimelineEvent::Dependency(event)));
                }
            }
        })();
        finished = !matches!(result, Ok(Some(_)));
        result.transpose()
    }))
}
