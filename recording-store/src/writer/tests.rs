use super::*;
use crate::event_index;
use crate::source::{RecordReader, RecordSource, RecordStream};
use anyhow::Result;
use serde_json::json;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use traffic_model::{
    recording::CapturePhase,
    trace::{OutputKind, RecordedEvent},
};
use uuid::Uuid;

pub(crate) fn write_session_manifest(
    root: &Path,
    epoch: Uuid,
    process_epoch: Uuid,
    files: Vec<LedgerFileIdentity>,
) -> Result<()> {
    use traffic_model::recording::{
        MANIFEST_FILE, RecordingManifest, SESSION_RECORDING_SCHEMA, SourceArtifactIdentity,
    };

    let manifest = RecordingManifest {
        schema: SESSION_RECORDING_SCHEMA.into(),
        run_id: "test".into(),
        process_epochs: vec![process_epoch],
        run_epoch: epoch,
        capture_policy_identity: "test".into(),
        source_artifact: SourceArtifactIdentity::Unavailable {
            reason: "test".into(),
        },
        sealed: true,
        capture_complete: true,
        coverage: Default::default(),
        records: 0,
        unattributed_records: 0,
        semantic_inventory: Default::default(),
        inputs: Vec::new(),
        files,
    };
    std::fs::write(root.join(MANIFEST_FILE), serde_json::to_vec(&manifest)?)?;
    Ok(())
}

#[tokio::test]
async fn sealed_partitions_preserve_logical_rows_and_selected_event_order() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let epoch = Uuid::new_v4();
    let process_epoch = Uuid::new_v4();
    let mut ledger = LedgerFiles::initialize(root, epoch, process_epoch).await?;
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
        process_epoch,
        source_task: "timer".into(),
        invocation: None,
    };
    let unknown = DependencyOwner::Unattributed {
        reason: "outside_admission".into(),
    };
    let row = |label, sequence| {
        json!({
            "recording_id": epoch, "capture": {"sequence": sequence, "process_epoch": process_epoch}, "outcome": {"kind": "response"},
            "capture_complete": true, "label": label,
            "target_host": "db.example.test", "target_port": 1234,
            "username": "test-user",
            "response": {"value":"x".repeat(5000)},
        })
    };
    let stamp = |sequence| RowStamp {
        sequence,
        offset_micros: sequence,
    };
    let layout = RowLayout::default();
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
    let mut case_row = row("case", 3);
    case_row["request"] = json!({"command":"example", "args":["a", "b"]});
    let first = ledger
        .append_dependency(
            &mut files,
            case_row.clone(),
            &owner,
            RecordKind::Exchange,
            &layout,
            Some(stamp(8)),
            stamp(9),
        )
        .await?;
    let second = ledger
        .append_dependency(
            &mut files,
            row("push", 4),
            &process,
            RecordKind::Message,
            &layout,
            None,
            stamp(10),
        )
        .await?;
    let observation = ledger
        .append_dependency(
            &mut files,
            row("observation", 11),
            &owner,
            RecordKind::Observation,
            &layout,
            None,
            stamp(11),
        )
        .await?;
    ledger
        .append_dependency(
            &mut files,
            row("process", 12),
            &process,
            RecordKind::Exchange,
            &layout,
            Some(stamp(12)),
            stamp(13),
        )
        .await?;
    ledger
        .append_dependency(
            &mut files,
            row("unknown", 14),
            &unknown,
            RecordKind::Exchange,
            &layout,
            Some(stamp(14)),
            stamp(15),
        )
        .await?;
    ledger
        .append_event(
            &mut files,
            &RecordedEvent {
                sequence: 16,
                offset_micros: 16,
                event: CaptureEvent::Terminal {
                    dependency_sequence: 3,
                    outcome: "response".into(),
                    capture_complete: true,
                },
            },
        )
        .await?;
    ledger
        .append_event(
            &mut files,
            &RecordedEvent {
                sequence: 17,
                offset_micros: 17,
                event: CaptureEvent::Sealed,
            },
        )
        .await?;
    let identities = ledger.seal(&mut files).await?;

    let dependency_path = crate::source::recording::dependency_path(root);
    assert_eq!(partitions::recording_id(&dependency_path)?, epoch);
    let ordinary = std::fs::read_to_string(root.join(event_index::JOURNALS[0]))?;
    assert_eq!(ordinary.lines().last(), Some("17\t17\tcapture_sealed"));
    assert!(!ordinary.contains("capture_terminated\t3\t"));
    for (name, label) in
        partitions::FILES
            .into_iter()
            .zip(["case", "process", "push", "unknown", "observation"])
    {
        let physical = std::fs::read_to_string(root.join(name))?;
        assert!(!physical.contains(&epoch.to_string()));
        assert!(!physical.contains("process_epoch"));
        assert!(physical.contains("db.example.test"));
        assert!(physical.contains("test-user"));
        assert!(physical.contains(label));
        assert!(
            physical
                .lines()
                .map(|row| { row.split_once('\t').unwrap().0.parse::<u64>().unwrap() })
                .is_sorted()
        );
        let sealed = identities.iter().find(|file| file.path == name).unwrap();
        assert_eq!(sealed.length, physical.len() as u64);
        assert_eq!(sealed.sha256, crate::source::digest(physical.as_bytes()));
    }
    let terms_file = root.join(crate::dependency_columns::FILE);
    let terms = std::fs::read_to_string(&terms_file)?;
    assert!(!terms.contains("test-user"));
    assert_eq!(
        terms.lines().next().unwrap().split_once('\t').unwrap().1,
        process_epoch.to_string(),
    );
    let mut stream = RecordStream::open(&dependency_path)?;
    for label in ["case", "push", "observation", "process", "unknown"] {
        let (_, raw) = stream.next()?.context("missing logical row")?;
        let decoded = serde_json::from_slice::<Value>(raw)?;
        assert_eq!(decoded["label"], label);
        assert_eq!(decoded["recording_id"], epoch.to_string());
        assert_eq!(
            decoded["capture"]["process_epoch"],
            process_epoch.to_string()
        );
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
    assert_eq!(decoded["request"], case_row["request"]);
    assert_eq!(decoded["response"], case_row["response"]);
    let replay_raw = RecordReader::for_replay(0).read(&dependency_path, &stream.stamp, &first)?;
    assert_eq!(serde_json::from_slice::<Value>(&replay_raw)?, decoded);
    let metadata_source = RecordSource::new(
        &dependency_path,
        stream.stamp.clone(),
        Arc::new(Mutex::new(RecordReader::for_replay(0))),
    );
    let metadata = metadata_source.reference(second.clone()).load_metadata()?;
    assert_eq!(metadata["label"], "push");
    assert!(metadata.get("response").is_none());
    std::fs::remove_dir_all(root.join("payload"))?;
    let push = metadata_source.reference(second.clone());
    assert_eq!(push.load_metadata()?["label"], "push");
    assert!(push.load::<Value>().is_err());
    let mut modified_terms = terms.into_bytes();
    modified_terms[0] = b'X';
    std::fs::write(&terms_file, modified_terms)?;
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
    std::fs::remove_file(root.join(event_index::JOURNALS[1]))?;
    assert_eq!(selected(&[3])?, [3, 5]);
    assert!(selected(&[4]).is_err());
    Ok(())
}

#[tokio::test]
async fn push_trace_elides_only_complete_success_after_a_wire_end() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let epoch = Uuid::new_v4();
    let mut ledger = LedgerFiles::initialize(root, epoch, Uuid::new_v4()).await?;
    let mut files = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: Duration::from_secs(30),
    });
    for (dependency, output, outcome, complete) in [
        (1, OutputKind::End, "delivery", true),
        (4, OutputKind::End, "delivery", false),
        (7, OutputKind::End, "custom_outcome", true),
        (10, OutputKind::Part, "delivery", true),
    ] {
        for (sequence, event) in [
            (
                dependency,
                CaptureEvent::MessageStarted {
                    dependency_sequence: dependency,
                },
            ),
            (
                dependency + 1,
                CaptureEvent::Output {
                    dependency_sequence: dependency,
                    output,
                },
            ),
            (
                dependency + 2,
                CaptureEvent::Terminal {
                    dependency_sequence: dependency,
                    outcome: outcome.into(),
                    capture_complete: complete,
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
        let repeated_sequence = RecordedEvent {
            sequence: dependency + 2,
            offset_micros: dependency + 2,
            event: CaptureEvent::Sealed,
        };
        assert!(
            ledger
                .append_event(&mut files, &repeated_sequence)
                .await
                .is_err()
        );
    }
    ledger.seal(&mut files).await?;
    let index = event_index::SourceEventIndex::open(root.to_owned(), epoch)?;
    let events = index.selected([1, 4, 7, 10])?.collect::<Result<Vec<_>>>()?;
    let terminals: Vec<_> = events
        .iter()
        .filter_map(|row| match row.event {
            CaptureEvent::Terminal {
                dependency_sequence,
                ..
            } => Some(dependency_sequence),
            _ => None,
        })
        .collect();
    assert_eq!(terminals, [4, 7, 10]);
    assert_eq!(
        events.iter().map(|row| row.sequence).collect::<Vec<_>>(),
        [1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    );
    Ok(())
}

#[tokio::test]
async fn unified_stream_rejects_sequence_reversal_across_partitions() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let mut ledger = LedgerFiles::initialize(root, Uuid::new_v4(), Uuid::new_v4()).await?;
    let mut files = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: Duration::from_secs(30),
    });
    ledger
        .append_event(
            &mut files,
            &RecordedEvent {
                sequence: 2,
                offset_micros: 12,
                event: CaptureEvent::MessageStarted {
                    dependency_sequence: 2,
                },
            },
        )
        .await?;
    let error = ledger
        .append_event(
            &mut files,
            &RecordedEvent {
                sequence: 1,
                offset_micros: 11,
                event: CaptureEvent::Sealed,
            },
        )
        .await
        .expect_err("reversed sequences cannot be stored");
    assert!(error.to_string().contains("unordered sequence 1 after 2"));
    files.flush_all().await?;
    assert_eq!(std::fs::read(root.join(event_index::JOURNALS[0]))?, b"");
    Ok(())
}

#[tokio::test]
async fn session_uses_one_sealed_journal_and_resolves_dependency_cells() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let epoch = Uuid::new_v4();
    let process_epoch = Uuid::new_v4();
    let mut ledger = LedgerFiles::initialize_for_mode(root, epoch, process_epoch, true).await?;
    let mut files = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: Duration::from_secs(30),
    });
    ledger
        .append_session_event(
            &mut files,
            &RecordedEvent {
                sequence: 1,
                offset_micros: 1,
                event: SessionEvent::SourceStart,
            },
        )
        .await?;
    let owner = DependencyOwner::Startup {
        process_epoch,
        initialization_unit: "session".into(),
    };
    for (sequence, kind) in [
        (2, RecordKind::Exchange),
        (4, RecordKind::Message),
        (5, RecordKind::Observation),
    ] {
        let mut record = json!({
            "recording_id": epoch,
            "capture": {"sequence": sequence, "process_epoch": process_epoch},
            "outcome": {"kind": "response"},
            "capture_complete": true,
            "response": traffic_model::capture::capture_body(b"response", usize::MAX),
        });
        let request_stamp = matches!(kind, RecordKind::Exchange).then(|| {
            record["request"] =
                serde_json::to_value(traffic_model::capture::capture_body(b"request", usize::MAX))
                    .unwrap();
            RowStamp {
                sequence,
                offset_micros: sequence,
            }
        });
        ledger
            .append_dependency(
                &mut files,
                record,
                &owner,
                kind,
                &RowLayout::default(),
                request_stamp,
                RowStamp {
                    sequence: sequence + u64::from(request_stamp.is_some()),
                    offset_micros: sequence + u64::from(request_stamp.is_some()),
                },
            )
            .await?;
    }
    ledger
        .append_event(
            &mut files,
            &RecordedEvent {
                sequence: 6,
                offset_micros: 6,
                event: CaptureEvent::Sealed,
            },
        )
        .await?;
    let identities = ledger.seal(&mut files).await?;
    let journal = std::fs::read_to_string(root.join(crate::session::FILE))?;
    let sealed = identities
        .iter()
        .find(|file| file.path == crate::session::FILE)
        .unwrap();
    assert_eq!(sealed.length, journal.len() as u64);
    assert_eq!(sealed.sha256, crate::source::digest(journal.as_bytes()));
    assert!(
        partitions::FILES
            .into_iter()
            .filter(|file| *file != "observations.tsv")
            .chain(event_index::FILES)
            .chain([partitions::DIRECTORY])
            .all(|file| !root.join(file).exists())
    );
    assert!(
        std::fs::read_to_string(root.join("observations.tsv"))?.starts_with("5\t5\tobservation\t")
    );
    assert_eq!(
        journal
            .lines()
            .map(|line| line.split('\t').nth(2).unwrap())
            .collect::<Vec<_>>(),
        [
            "source_start",
            "dependency",
            "notification",
            "capture_sealed"
        ]
    );

    write_session_manifest(root, epoch, process_epoch, identities)?;
    let path = root.join(crate::session::FILE);
    let mut stream = RecordStream::open(&path)?;
    let (first, row) = stream.next()?.context("missing request/response pair")?;
    let response = serde_json::to_value(traffic_model::capture::capture_body(
        b"response",
        usize::MAX,
    ))?;
    let record: Value = serde_json::from_slice(row)?;
    assert_eq!(
        record["request"],
        serde_json::to_value(traffic_model::capture::capture_body(b"request", usize::MAX))?
    );
    assert_eq!(record["response"], response);
    let (_, row) = stream.next()?.context("missing message row")?;
    assert_eq!(serde_json::from_slice::<Value>(row)?["response"], response);
    assert!(stream.next()?.is_none());
    let mut observations = RecordStream::open(&crate::session_records::observation_path(root))?;
    let (_, row) = observations.next()?.context("missing observation row")?;
    assert_eq!(serde_json::from_slice::<Value>(row)?["response"], response);
    assert!(observations.next()?.is_none());
    let summary = crate::session_summary::read(root)?;
    assert_eq!(summary.physical_events, 4);
    assert!(summary.routes.is_empty());
    assert_eq!(
        crate::session_records::dependency(root, 3)?["response"],
        response
    );

    let replay = RecordSource::new(
        &path,
        stream.stamp.clone(),
        Arc::new(Mutex::new(RecordReader::for_replay(0))),
    );
    assert_eq!(
        &replay
            .reference(first)
            .load_response_bytes()?
            .context("missing raw response")?[..],
        b"response"
    );
    Ok(())
}

#[tokio::test]
async fn session_response_literals_skip_payload_and_preserve_the_original_record() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let epoch = Uuid::new_v4();
    let mut ledger = LedgerFiles::initialize_for_mode(root, epoch, epoch, true).await?;
    let mut files = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: Duration::from_secs(30),
    });
    let owner = DependencyOwner::Startup {
        process_epoch: epoch,
        initialization_unit: "session".into(),
    };
    let layout = RowLayout {
        response_literal: Some("redis_ok"),
        ..RowLayout::default()
    };
    let reply = traffic_model::capture::capture_body(b"+OK\r\n", usize::MAX);
    for sequence in [1, 2] {
        ledger
            .append_dependency(
                &mut files,
                json!({
                    "recording_id": epoch,
                    "capture": {
                        "sequence": sequence,
                        "process_epoch": epoch,
                        "effect_index": 0,
                        "observed_case": null,
                        "admitted_case": null,
                        "attribution": owner,
                    },
                    "outcome": "response",
                    "capture_complete": true,
                    "event_type": "redis_exchange",
                    "response": reply,
                }),
                &owner,
                RecordKind::Exchange,
                &layout,
                None,
                RowStamp {
                    sequence,
                    offset_micros: sequence,
                },
            )
            .await?;
    }

    let identities = ledger.seal(&mut files).await?;
    assert!(
        identities
            .iter()
            .all(|file| !file.path.starts_with("payload/"))
    );
    let journal = std::fs::read_to_string(root.join(crate::session::FILE))?;
    assert_eq!(journal.matches("\tconst:redis_ok\n").count(), 2);
    for key in [
        "attribution",
        "effect_index",
        "observed_case",
        "admitted_case",
    ] {
        assert!(!journal.contains(key));
    }
    let terms = std::fs::read_to_string(root.join(dependency_columns::FILE))?;
    assert_eq!(terms.matches("literal\tredis_ok\t").count(), 1);

    write_session_manifest(root, epoch, epoch, identities)?;
    let mut stream = RecordStream::open(&root.join(crate::session::FILE))?;
    let (_, row) = stream.next()?.context("missing constant response")?;
    let record: Value = serde_json::from_slice(row)?;
    assert_eq!(record["response"], json!(reply));
    assert_eq!(record["capture"]["attribution"], json!(owner));
    assert_eq!(record["capture"]["effect_index"], 0);
    assert!(record["capture"]["observed_case"].is_null());
    Ok(())
}
