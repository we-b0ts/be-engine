//! Read-only queries and public progress derived from the sealed Source timeline.

use std::{
    collections::{BTreeSet, HashSet},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use traffic_model::{
    session::SessionEvent,
    trace::{CaptureEvent, OutputKind, RecordedEvent},
};
pub use traffic_recording_store::session_summary::recording_end_sequence;
use traffic_recording_store::{session, source::recording};

mod progress;
pub use progress::{SessionApiCounts, publish_passed_progress};

#[derive(Debug, Serialize)]
pub struct SessionEventPage {
    pub recording_id: String,
    pub events: Vec<Value>,
    pub next_after_sequence: Option<u64>,
}

#[derive(Debug)]
pub struct SessionEventQuery {
    pub from_sequence: u64,
    pub after_sequence: u64,
    pub window_ms: Option<u64>,
    pub limit: usize,
    pub payload: bool,
    pub with_push_event: bool,
    pub selected: BTreeSet<u64>,
}

/// Return a bounded evidence page in original Source sequence.
pub fn events(root: &Path, query: SessionEventQuery) -> Result<SessionEventPage> {
    let SessionEventQuery {
        from_sequence,
        after_sequence,
        window_ms,
        limit,
        payload,
        with_push_event,
        selected,
    } = query;
    ensure!(
        (1..=200).contains(&limit),
        "event page limit must be between 1 and 200"
    );
    let first_sequence = if window_ms.is_none() {
        from_sequence.max(selected.first().copied().unwrap_or_default())
    } else {
        from_sequence
    };
    let mut primary = session::evidence_events_from(root, first_sequence)?;
    let (root, manifest) = recording::manifest(root)?;
    let mut dependency = recording::events(&root)?;
    let mut next_primary = None;
    let mut next_dependency = None;
    let mut end = None;
    let mut previous_sequence = 0;
    let mut events = Vec::new();
    let mut hidden_pushes = (!with_push_event && selected.is_empty()).then(HashSet::<u64>::new);
    loop {
        if next_primary.is_none() {
            next_primary = primary.next().transpose()?;
        }
        if next_dependency.is_none() {
            next_dependency = dependency.next().transpose()?;
        }
        let take_primary = match (&next_primary, &next_dependency) {
            (None, None) => break,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (Some(primary), Some(dependency)) => primary.sequence < dependency.sequence,
        };
        let (sequence, offset, value) = if take_primary {
            let event = next_primary.take().expect("primary head exists");
            let value = Some(primary_value(&event, payload)?);
            (event.sequence, event.offset_micros, value)
        } else {
            let event = next_dependency.take().expect("dependency head exists");
            // A delivery inside the window can belong to a notification that
            // started before it. Update the filter before applying the cursor.
            let hidden = hidden_pushes
                .as_mut()
                .is_some_and(|pushes| is_push_event(pushes, &event.event));
            let value = (!hidden)
                .then(|| serde_json::to_value(&event))
                .transpose()?;
            (event.sequence, event.offset_micros, value)
        };
        ensure!(
            sequence > previous_sequence,
            "duplicate or unordered Source sequence {sequence}"
        );
        previous_sequence = sequence;
        if selected.last().is_some_and(|&last| sequence > last) {
            break;
        }
        if sequence < first_sequence {
            continue;
        }
        let end_offset = end.get_or_insert_with(|| {
            window_ms.map(|window| offset.saturating_add(window.saturating_mul(1000)))
        });
        if end_offset.is_some_and(|end| offset > end) {
            break;
        }
        if sequence <= after_sequence || (!selected.is_empty() && !selected.contains(&sequence)) {
            continue;
        }
        let Some(value) = value else {
            continue;
        };
        if events.len() == limit {
            let next_after_sequence = events
                .last()
                .and_then(|row: &Value| row["sequence"].as_u64());
            return Ok(SessionEventPage {
                recording_id: manifest.run_id,
                events,
                next_after_sequence,
            });
        }
        events.push(value);
    }
    Ok(SessionEventPage {
        recording_id: manifest.run_id,
        events,
        next_after_sequence: None,
    })
}

fn is_push_event(pushes: &mut HashSet<u64>, event: &CaptureEvent) -> bool {
    let Some(sequence) = event.dependency_sequence() else {
        return false;
    };
    match event {
        CaptureEvent::MessageStarted { .. } => {
            pushes.insert(sequence);
            true
        }
        // A sealed stream can omit capture termination after a wire terminal.
        CaptureEvent::Terminal { .. }
        | CaptureEvent::Output {
            output: OutputKind::End | OutputKind::Terminated { .. },
            ..
        } => pushes.remove(&sequence),
        _ => pushes.contains(&sequence),
    }
}

fn primary_value(row: &RecordedEvent<SessionEvent>, payload: bool) -> Result<Value> {
    Ok(match &row.event {
        SessionEvent::PrimaryRequest { exchange, request } if !payload => json!({
            "sequence": row.sequence, "offset_micros": row.offset_micros, "event_type": row.event.kind(),
            "exchange": exchange, "method": request["method"],
            "path": request["uri"].as_str().and_then(|uri| uri.split('?').next()),
        }),
        SessionEvent::PrimaryResponseHeaders { exchange, response } if !payload => json!({
            "sequence": row.sequence, "offset_micros": row.offset_micros, "event_type": row.event.kind(),
            "exchange": exchange, "status": response["status"],
        }),
        SessionEvent::PrimaryResponsePart {
            exchange,
            part,
            data_base64,
        } if !payload => json!({
            "sequence": row.sequence, "offset_micros": row.offset_micros, "event_type": row.event.kind(),
            "exchange": exchange, "part": part, "encoded_bytes": data_base64.len(),
        }),
        SessionEvent::PrimaryResponseTrailers { exchange, .. } if !payload => json!({
            "sequence": row.sequence, "offset_micros": row.offset_micros, "event_type": row.event.kind(),
            "exchange": exchange,
        }),
        _ => serde_json::to_value(row)?,
    })
}

/// Resolve a dependency admission sequence to its protected semantic record.
pub fn dependency(root: &Path, sequence: u64) -> Result<Value> {
    traffic_recording_store::session_records::dependency(root, sequence)
}

/// Read a retained Target observation tied to this recording and Replay attempt.
pub fn target_observation(root: &Path, report: &Path, observation_id: uuid::Uuid) -> Result<Value> {
    use crate::policy_evidence::{self, WitnessManifest};

    let value: Value = serde_json::from_slice(&std::fs::read(report)?)?;
    let report_source = value["case_dir"]
        .as_str()
        .context("Replay report source is missing")?;
    ensure!(
        value["mode"] == "session"
            && Path::new(report_source).canonicalize()? == root.canonicalize()?,
        "Replay report does not describe the selected Source session"
    );
    let manifest: WitnessManifest = serde_json::from_value(value["policy_witnesses"].clone())?;
    let path = policy_evidence::verify(report, &manifest)?;
    let graph = manifest
        .graph()
        .context("Target observation graph is missing")?;
    let id = observation_id.to_string();
    let index = graph
        .targets
        .iter()
        .position(|target| {
            target.id == id
                || target
                    .id
                    .strip_prefix(&id)
                    .is_some_and(|role| role.starts_with(':'))
        })
        .context("Target observation is absent from this Replay report")?;
    let context = value["target_observation_key_context"]
        .as_str()
        .context("Target observation key context is missing")?;
    let bytes = policy_evidence::read_target(&path, &manifest, index, Path::new(context))?;
    serde_json::from_slice(&bytes).context("Target observation is not a native event payload")
}
