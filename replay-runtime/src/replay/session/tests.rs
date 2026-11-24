use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use serde_json::json;
use traffic_model::{
    attribution::DependencyOwner,
    capture::capture_body,
    recording::{
        COMPACT_RECORDING_SCHEMA, CaptureCoverage, CapturePhase, MANIFEST_FILE, RecordingManifest,
        SemanticInventory, SourceArtifactIdentity,
    },
    session::SessionEvent,
    trace::{CaptureEvent, OutputKind, RecordedEvent},
};
use traffic_protocol::connection::NativeProtocol;
use traffic_recording_store::{
    source::{FileStamp, RecordReader, RecordSource, recording},
    writer::{JsonlBufferSettings, JsonlWriterPool, LedgerFiles, RecordKind, RowLayout, RowStamp},
};

use super::{EventKind, Instant, SequenceRuntime, plan};

fn recorded<T>(sequence: u64, event: T) -> RecordedEvent<T> {
    RecordedEvent {
        sequence,
        offset_micros: sequence,
        event,
    }
}

#[tokio::test]
async fn unified_session_plans_and_delivers_redis_push_from_recorded_bytes() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let epoch = uuid::Uuid::new_v4();
    let exchange = uuid::Uuid::new_v4();
    let owner = DependencyOwner::Startup {
        process_epoch: epoch,
        initialization_unit: "session".into(),
    };
    let mut ledger = LedgerFiles::initialize_for_mode(root, epoch, epoch, true).await?;
    let mut files = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: Duration::from_secs(30),
    });
    let wire = traffic_protocol_redis::encode_array(&[b"message", b"events", b"a\0b"]);
    let dependency = |sequence, kind, response: &[u8]| {
        json!({
            "recording_id": epoch,
            "capture": {"sequence": sequence, "process_epoch": epoch, "semantic_required": true},
            "outcome": {"kind": "response"},
            "capture_complete": true,
            "event_type": kind,
            "response": capture_body(response, usize::MAX),
        })
    };
    let stamp = |sequence| RowStamp {
        sequence,
        offset_micros: sequence,
    };
    let start = CaptureEvent::Started {
        dependency_sequence: 2,
        phase: CapturePhase::Runtime,
        observed_case: None,
        admitted_case: None,
    };
    let output_start = |dependency_sequence| CaptureEvent::OutputStarted {
        dependency_sequence,
        output: OutputKind::End,
    };
    let output_end = |dependency_sequence| CaptureEvent::Output {
        dependency_sequence,
        output: OutputKind::End,
    };
    ledger
        .append_session_event(&mut files, &recorded(1, SessionEvent::SourceStart))
        .await?;
    ledger.append_event(&mut files, &recorded(2, start)).await?;
    ledger
        .append_session_event(&mut files, &recorded(3, SessionEvent::Ready))
        .await?;
    for (sequence, event) in [(4, output_start(2)), (5, output_end(2))] {
        ledger
            .append_event(&mut files, &recorded(sequence, event))
            .await?;
    }
    ledger
        .append_dependency(
            &mut files,
            dependency(2, "redis_exchange", b"+OK\r\n"),
            &owner,
            RecordKind::Exchange,
            &RowLayout::default(),
            None,
            stamp(6),
        )
        .await?;
    ledger
        .append_event(
            &mut files,
            &recorded(
                7,
                CaptureEvent::MessageStarted {
                    dependency_sequence: 7,
                },
            ),
        )
        .await?;
    ledger
        .append_session_event(
            &mut files,
            &recorded(
                8,
                SessionEvent::PrimaryRequest {
                    exchange,
                    request: json!({"method":"GET", "uri":"/events"}),
                },
            ),
        )
        .await?;
    let push = ledger
        .append_dependency(
            &mut files,
            dependency(7, "redis_pub_sub_push", &wire),
            &owner,
            RecordKind::Message,
            &RowLayout::default(),
            None,
            stamp(9),
        )
        .await?;
    ledger
        .append_event(&mut files, &recorded(10, output_start(7)))
        .await?;
    ledger
        .append_session_event(
            &mut files,
            &recorded(
                11,
                SessionEvent::PrimaryCancel {
                    exchange,
                    reason: "fixture".into(),
                },
            ),
        )
        .await?;
    ledger
        .append_event(&mut files, &recorded(12, output_end(7)))
        .await?;
    for (sequence, event) in [
        (13, SessionEvent::Stop),
        (14, SessionEvent::SourceExit { status: Some(0) }),
    ] {
        ledger
            .append_session_event(&mut files, &recorded(sequence, event))
            .await?;
    }
    ledger
        .append_event(&mut files, &recorded(15, CaptureEvent::Sealed))
        .await?;
    let manifest = RecordingManifest {
        schema: COMPACT_RECORDING_SCHEMA.into(),
        run_id: "unified-session".into(),
        run_epoch: epoch,
        process_epochs: vec![epoch],
        capture_policy_identity: String::new(),
        source_artifact: SourceArtifactIdentity::Unavailable {
            reason: "fixture".into(),
        },
        sealed: true,
        capture_complete: true,
        coverage: CaptureCoverage {
            admitted: 2,
            terminal: 2,
            ..Default::default()
        },
        records: 2,
        unattributed_records: 0,
        semantic_inventory: SemanticInventory {
            total_mandatory: 2,
            by_owner_kind: [("startup".into(), 2)].into(),
            ..Default::default()
        },
        inputs: Vec::new(),
        files: ledger.seal(&mut files).await?,
    };
    std::fs::write(
        root.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest.archive())?,
    )?;
    assert!(!root.join("event-locations.bin").exists());
    assert!(!root.join("event-spans.bin").exists());
    assert!(recording::event_index_for_replay(root)?.is_none());

    let plan = plan(root, [2, 7].into(), Default::default())?;
    assert_eq!(
        plan.events()
            .map(|row| (row.sequence, row.kind))
            .collect::<Vec<_>>(),
        [
            (1, EventKind::SessionSourceStart),
            (2, EventKind::Request),
            (3, EventKind::SessionReady),
            (4, EventKind::ResponseEndStarted),
            (5, EventKind::ResponseEnd),
            (7, EventKind::Message),
            (8, EventKind::PrimaryRequest),
            (10, EventKind::ResponseEndStarted),
            (11, EventKind::PrimaryCancel),
            (12, EventKind::ResponseEnd),
            (13, EventKind::SessionStop),
            (14, EventKind::SessionSourceExit),
        ]
    );
    let path = recording::dependency_path(root);
    // SAFETY: This private temp fixture remains sealed and immutable until the reader drops.
    let reader = Arc::new(Mutex::new(unsafe { RecordReader::for_session_replay(0) }));
    let source = RecordSource::new(&path, FileStamp::read_native(&path)?, reader);
    let body = source
        .reference(push)
        .load_response_bytes()?
        .context("missing raw Redis push")?;
    assert_eq!(body.as_ref(), wire.as_slice());
    let decoder = traffic_protocol_redis::native::Native
        .emission_body_decoder()
        .context("missing Redis push decoder")?;
    let response = decoder(body)?;
    let values = response
        .project()?
        .values
        .into_iter()
        .map(|(path, value)| (path, value.bytes))
        .collect();

    let runtime = SequenceRuntime::with_session_timing(plan, Some(Duration::ZERO), []);
    let deadline = Instant::now() + Duration::from_secs(1);
    runtime.commit_driver(1)?;
    let request = runtime.admit(2)?;
    runtime.commit_driver(3)?;
    request.wait_delivery(deadline).await?;
    request.publish()?;
    let push = runtime.admit(7)?;
    runtime.commit_driver(8)?;
    push.wait_delivery(deadline).await?;
    let mut output = response.output(&values)?;
    let mut delivered = Vec::new();
    traffic_replay::output::deliver(&mut delivered, &mut *output, Some(&push)).await?;
    assert_eq!(delivered, wire);
    push.publish()?;
    assert_eq!(runtime.expected().unwrap().sequence, 11);
    runtime.commit_driver(11)?;
    assert_eq!(runtime.progress().last_sequence, Some(12));
    runtime.commit_driver(13)?;
    runtime.commit_driver(14)?;
    assert!(runtime.complete());
    Ok(())
}
