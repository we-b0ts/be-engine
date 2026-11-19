use super::*;
use crate::format;
use crate::source::{RecordReader, RecordStream};
use anyhow::Result;
use serde_json::json;
use std::time::Duration;
use traffic_model::{
    recording::CapturePhase,
    trace::{OutputKind, RecordedEvent},
};
use uuid::Uuid;

#[tokio::test]
async fn sealed_partitions_preserve_logical_rows_and_selected_event_order() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let epoch = Uuid::new_v4();
    let mut ledger = LedgerFiles::initialize(root, epoch).await?;
    let mut files = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: Duration::from_secs(30),
    });
    let case_id = Uuid::new_v4();
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
            "recording_id": epoch, "capture": {"sequence": 1}, "outcome": {"kind": "response"},
            "capture_complete": true, "label": label,
            "target_host": "db.example.test", "target_port": 1234,
            "username": "test-user",
        })
    };
    let layout = RowLayout::default();
    let first = ledger
        .append_dependency(
            &mut files,
            row("case"),
            &owner,
            RecordKind::Exchange,
            &layout,
        )
        .await?;
    let second = ledger
        .append_dependency(
            &mut files,
            row("push"),
            &process,
            RecordKind::Message,
            &layout,
        )
        .await?;
    let observation = ledger
        .append_dependency(
            &mut files,
            row("observation"),
            &owner,
            RecordKind::Observation,
            &layout,
        )
        .await?;
    ledger
        .append_dependency(
            &mut files,
            row("process"),
            &process,
            RecordKind::Exchange,
            &layout,
        )
        .await?;
    ledger
        .append_dependency(
            &mut files,
            row("unknown"),
            &unknown,
            RecordKind::Exchange,
            &layout,
        )
        .await?;
    for (sequence, event) in [
        (
            3,
            CaptureEvent::Started {
                dependency_sequence: 3,
                phase: CapturePhase::Runtime,
                observed_case: Some(case_id),
                admitted_case: Some(case_id),
            },
        ),
        (
            4,
            CaptureEvent::MessageStarted {
                dependency_sequence: 4,
            },
        ),
        (
            5,
            CaptureEvent::Output {
                dependency_sequence: 3,
                output: OutputKind::End,
            },
        ),
        (
            7,
            CaptureEvent::Terminal {
                dependency_sequence: 4,
                outcome: "response".into(),
                capture_complete: true,
            },
        ),
        (8, CaptureEvent::Sealed),
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
    let identities = ledger.seal(&mut files).await?;

    let dependency_path = crate::source::recording::dependency_path(root);
    assert_eq!(partitions::recording_id(&dependency_path)?, epoch);
    let ordinary = std::fs::read_to_string(root.join(format::EVENTS))?;
    assert_eq!(ordinary.lines().last(), Some("8\t8\tcapture_sealed"));
    for (name, label) in
        partitions::FILES
            .into_iter()
            .zip(["case", "process", "push", "unknown", "observation"])
    {
        let physical = std::fs::read_to_string(root.join(name))?;
        assert!(!physical.contains(&epoch.to_string()));
        assert_eq!(physical.split('\t').count(), crate::format::COLUMN_COUNT);
        assert!(physical.starts_with("1\t"));
        assert!(physical.contains("db.example.test"));
        assert!(physical.contains("test-user"));
        assert!(physical.contains(label));
        assert_eq!(physical.lines().count(), 1);
        let sealed = identities.iter().find(|file| file.path == name).unwrap();
        assert_eq!(sealed.length, physical.len() as u64);
        assert_eq!(sealed.sha256, crate::source::digest(physical.as_bytes()));
    }
    let terms_file = root.join(crate::dependency_columns::FILE);
    let terms = std::fs::read_to_string(&terms_file)?;
    assert!(!terms.contains("test-user"));
    let mut stream = RecordStream::open(&dependency_path)?;
    for label in ["case", "push", "observation", "process", "unknown"] {
        let (_, raw) = stream.next()?.context("missing logical row")?;
        let decoded = serde_json::from_slice::<Value>(raw)?;
        assert_eq!(decoded["label"], label);
        assert_eq!(decoded["recording_id"], epoch.to_string());
        assert_eq!(decoded["target_host"], "db.example.test");
        assert_eq!(decoded["target_port"], 1234);
    }
    assert!(stream.next()?.is_none());
    let mut reader = RecordReader::new(0);
    let raw = reader.read(&dependency_path, &stream.stamp, &observation)?;
    assert_eq!(
        serde_json::from_slice::<Value>(&raw)?["label"],
        "observation"
    );
    let raw = reader.read(&dependency_path, &stream.stamp, &second)?;
    assert_eq!(serde_json::from_slice::<Value>(&raw)?["label"], "push");
    let raw = reader.read(&dependency_path, &stream.stamp, &first)?;
    let decoded = serde_json::from_slice::<Value>(&raw)?;
    assert_eq!(decoded["label"], "case");
    assert_eq!(decoded["recording_id"], epoch.to_string());
    std::fs::write(&terms_file, terms.replacen('2', "3", 1))?;
    assert!(
        reader
            .read(&dependency_path, &stream.stamp, &first)
            .is_err()
    );

    let index = event_index::SourceEventIndex::open(root.to_owned(), epoch)?;
    let selected = |dependencies: &[u64]| -> Result<Vec<u64>> {
        index
            .selected(dependencies.iter().copied())?
            .map(|event| event.map(|event| event.sequence))
            .collect()
    };
    assert_eq!(selected(&[4, 3])?, [3, 4, 5, 7]);
    std::fs::remove_file(root.join(format::PUSH_EVENTS))?;
    assert_eq!(selected(&[3])?, [3, 5]);
    assert!(selected(&[4]).is_err());
    Ok(())
}
