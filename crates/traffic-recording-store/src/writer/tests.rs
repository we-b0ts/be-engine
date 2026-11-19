use super::*;
use crate::source::{RecordReader, RecordStream};
use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::time::Duration;
use traffic_model::{
    recording::{CapturePhase, ProtocolRef},
    trace::{OutputKind, RecordedEvent},
};
use uuid::Uuid;

#[tokio::test]
async fn sealed_partitions_preserve_logical_rows_and_selected_event_order() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    LedgerFiles::initialize(root).await?;
    let mut ledger = LedgerFiles::new(root);
    let mut files = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: Duration::from_secs(30),
    });
    let epoch = Uuid::new_v4();
    let case_id = Uuid::new_v4();
    let request = Uuid::new_v4();
    let message = Uuid::new_v4();
    let owner = DependencyOwner::Case {
        origin_case_id: case_id,
        task_instance: None,
    };
    let process = DependencyOwner::Process {
        process_epoch: epoch,
        source_task: "timer".into(),
        invocation: None,
    };
    let unknown = DependencyOwner::Unattributed {
        reason: "outside_admission".into(),
    };
    let row = |label| {
        json!({
            "recording_id": epoch, "capture": {}, "outcome": {"kind": "response"},
            "capture_complete": true, "label": label,
        })
    };
    let first = ledger
        .append_dependency(&mut files, row("case"), &owner, false)
        .await?;
    let second = ledger
        .append_dependency(&mut files, row("push"), &process, true)
        .await?;
    ledger
        .append_dependency(&mut files, row("process"), &process, false)
        .await?;
    ledger
        .append_dependency(&mut files, row("unknown"), &unknown, false)
        .await?;
    for (sequence, event) in [
        (
            3,
            CaptureEvent::Started {
                exchange_id: request,
                dependency_sequence: 3,
                process_epoch: epoch,
                phase: CapturePhase::Runtime,
                observed_case: Some(case_id),
                admitted_case: Some(case_id),
                started_at: Utc::now(),
            },
        ),
        (
            4,
            CaptureEvent::MessageStarted {
                exchange_id: message,
                dependency_sequence: 4,
            },
        ),
        (
            6,
            CaptureEvent::Bound {
                exchange_id: request,
                dependency_sequence: 3,
                protocol_ref: ProtocolRef::observation(request, "test"),
            },
        ),
        (
            5,
            CaptureEvent::Output {
                exchange_id: request,
                dependency_sequence: 3,
                output: OutputKind::End,
            },
        ),
        (
            7,
            CaptureEvent::Terminal {
                exchange_id: message,
                dependency_sequence: 4,
                outcome: "response".into(),
                capture_complete: true,
            },
        ),
    ] {
        ledger
            .append_event(
                &mut files,
                &RecordedEvent {
                    sequence,
                    offset_micros: sequence,
                    event,
                },
            )
            .await?;
    }
    ledger.seal(&mut files).await?;

    let dependency_path = crate::source::recording::dependency_path(root);
    for (name, label) in partitions::FILES
        .into_iter()
        .zip(["case", "process", "push", "unknown"])
    {
        let physical = std::fs::read_to_string(root.join(name))?;
        assert!(physical.contains(label));
        assert_eq!(physical.lines().count(), 1);
    }
    let mut stream = RecordStream::open(&dependency_path)?;
    for label in ["case", "push", "process", "unknown"] {
        let (_, raw) = stream.next()?.context("missing logical row")?;
        assert_eq!(serde_json::from_slice::<Value>(raw)?["label"], label);
    }
    assert!(stream.next()?.is_none());
    let mut reader = RecordReader::new(0);
    let raw = reader.read(&dependency_path, &stream.stamp, &second)?;
    assert_eq!(serde_json::from_slice::<Value>(&raw)?["label"], "push");
    let raw = reader.read(&dependency_path, &stream.stamp, &first)?;
    assert_eq!(serde_json::from_slice::<Value>(&raw)?["label"], "case");

    let index = event_index::SourceEventIndex::open(root.to_owned())?;
    let selected = |dependencies: &[u64]| -> Result<Vec<u64>> {
        index
            .selected(dependencies.iter().copied())?
            .map(|event| event.map(|event| event.sequence))
            .collect()
    };
    assert_eq!(selected(&[4, 3])?, [3, 4, 5, 6, 7]);
    std::fs::remove_file(root.join(format::PUSH_EVENTS))?;
    assert_eq!(selected(&[3])?, [3, 5, 6]);
    assert!(selected(&[4]).is_err());
    Ok(())
}
