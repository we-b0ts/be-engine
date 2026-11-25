//! Read-only queries and public progress derived from the sealed Source timeline.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use traffic_model::{session::SessionEvent, trace::RecordedEvent};
use traffic_recording_store::{session, source::recording};

mod progress;
pub use progress::{SessionApiCounts, api_counts, publish_passed_progress};

#[derive(Debug, Serialize)]
pub struct SessionEventPage {
    pub recording_id: String,
    pub events: Vec<Value>,
    pub next_after_sequence: Option<u64>,
}

/// Return a bounded evidence page in original Source sequence.
pub fn events(
    root: &Path,
    from_sequence: u64,
    after_sequence: u64,
    window_ms: Option<u64>,
    limit: usize,
    payload: bool,
    selected: &BTreeSet<u64>,
) -> Result<SessionEventPage> {
    ensure!(
        (1..=200).contains(&limit),
        "event page limit must be between 1 and 200"
    );
    let mut primary = session::evidence_events(root)?;
    let (root, manifest) = recording::manifest(root)?;
    let mut dependency = recording::events(&root)?;
    let mut next_primary = None;
    let mut next_dependency = None;
    let mut end = None;
    let mut previous_sequence = 0;
    let mut events = Vec::new();
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
            let value = primary_value(&event, payload)?;
            (event.sequence, event.offset_micros, value)
        } else {
            let event = next_dependency.take().expect("dependency head exists");
            let value = serde_json::to_value(&event)?;
            (event.sequence, event.offset_micros, value)
        };
        ensure!(
            sequence > previous_sequence,
            "duplicate or unordered Source sequence {sequence}"
        );
        previous_sequence = sequence;
        if sequence < from_sequence {
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
    let (root, manifest) = recording::manifest(root)?;
    ensure!(manifest.capture_complete, "Source lead-in is incomplete");
    recording::authenticate(&root)?;
    let mut rows =
        traffic_recording_store::source::RecordStream::open(&recording::dependency_path(&root))?;
    while let Some((_, bytes)) = rows.next()? {
        let row: Value = serde_json::from_slice(bytes)?;
        if row["capture"]["sequence"].as_u64() == Some(sequence) {
            return Ok(row);
        }
    }
    None.context("no protected dependency record for that admission sequence")
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
