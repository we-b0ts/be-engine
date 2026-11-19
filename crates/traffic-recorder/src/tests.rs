use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::CapturedEvent;
use tokio::sync::Mutex;
use traffic_model::trace::{CaptureEvent, OutputKind};

use super::*;

struct HeldScope {
    capture: ledger::CaptureReservation,
    dropped: Arc<AtomicBool>,
}

impl Drop for HeldScope {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl CaptureScope for HeldScope {
    fn context(&self) -> CaptureContext<'_> {
        assert!(!self.dropped.load(Ordering::SeqCst));
        CaptureContext {
            cases: &[],
            bootstrap_open: false,
            ambiguous_active_cases: 0,
            process_owned_rule: None,
            process_rule_ids: &[],
            unattributed_reason: None,
            observed_case: None,
            shutdown_case_id: None,
            phase: CapturePhase::Runtime,
            capture: Some(&self.capture),
        }
    }
}

async fn writer(
    path: &std::path::Path,
    epoch: Uuid,
    finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
) -> RecorderWriter {
    RecorderWriter::start(
        Arc::new(path.to_owned()),
        TrafficJsonlMode::Off,
        JsonlBufferSettings {
            capacity: 4096,
            flush_interval: Duration::from_secs(60),
        },
        32,
        finalized_cases,
        CaptureOptions {
            process_epoch: epoch,
            policy_identity: "capture-policy".into(),
            evidence: Arc::new(EvidenceRegistry::default()),
        },
    )
    .await
    .unwrap()
}

fn connection_failure() -> DependencyConnectFailureEvent {
    DependencyConnectFailureEvent {
        id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        client_addr: None,
        protocol: "fixture".into(),
        target_host: "fixture.test".into(),
        target_port: 1234,
        duration_ms: 1,
        failure_kind: "connection_refused".into(),
        client_outcome: "reset".into(),
    }
}

#[tokio::test]
async fn queued_scope_retains_the_hosts_guard_until_its_record_is_written() {
    let directory = tempfile::tempdir().unwrap();
    let epoch = Uuid::new_v4();
    let writer = writer(directory.path(), epoch, Arc::default()).await;
    let registry = ledger::CaptureRegistry::new(writer.clone(), epoch);
    let capture = registry.begin(CapturePhase::Runtime, None, None).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    writer
        .try_record(RecordEnvelope {
            event: CapturedEvent::capture(&connection_failure()).unwrap(),
            targets: Box::new(HeldScope {
                capture,
                dropped: dropped.clone(),
            }),
            global_attribution: None,
            suppress_default_global: false,
        })
        .unwrap();
    assert!(!dropped.load(Ordering::SeqCst));

    writer.flush_all().await.unwrap();

    assert!(dropped.load(Ordering::SeqCst));
    assert!(registry.drain(Duration::from_secs(1)).await);
    let path = traffic_recording_store::source::recording::dependency_path(directory.path());
    let mut records = traffic_recording_store::source::RecordStream::open(&path).unwrap();
    let (location, raw) = records.next().unwrap().unwrap();
    let value: serde_json::Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(value["event_type"], "dependency_connect_failure");
    assert!(records.next().unwrap().is_none());

    let scope_path = directory.path().join("indexes/unattributed-scope.json");
    assert!(!scope_path.exists());
    let scope = traffic_recording_store::source::scoped::read_index(&scope_path).unwrap();
    let [found] = scope.locations.as_slice() else {
        panic!("expected one equivalent scope position");
    };
    assert_eq!(found.line, location.line);
    assert_eq!(found.offset, location.offset);
    assert_eq!(found.length, location.length);
    assert_eq!(found.sha256, location.sha256);
    assert_eq!(
        found.exchange_id.to_string(),
        value["capture"]["exchange_id"]
    );
    writer.seal(registry.coverage()).await.unwrap();
    let mut scoped = traffic_recording_store::source::RecordStream::open(&scope_path).unwrap();
    let (_, raw) = scoped.next().unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(raw).unwrap(),
        value
    );
    assert!(scoped.next().unwrap().is_none());

    let (_, manifest) =
        traffic_recording_store::source::recording::manifest(directory.path()).unwrap();
    let scope_file = manifest
        .files
        .iter()
        .find(|file| file.path == "indexes/unattributed-scope.bin")
        .unwrap();
    let (count, selected) = traffic_recording_store::source::scoped::select_original_scope(
        directory.path(),
        scope_file,
        found.exchange_id,
    )
    .unwrap()
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(selected, vec![location]);
}

#[tokio::test]
async fn source_order_is_fixed_on_enqueue_through_output_cancellation_and_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let epoch = Uuid::new_v4();
    let finalized_cases = Arc::new(Mutex::new(HashSet::new()));
    let writer = writer(directory.path(), epoch, finalized_cases.clone()).await;
    let registry = ledger::CaptureRegistry::new(writer.clone(), epoch);

    let block_append = finalized_cases.lock().await;
    let case = CaseContext {
        id: registry.next_case_id(),
        rule_name: "fixture".into(),
        uri_group: None,
    };
    let mut synthetic = std::pin::pin!(writer.append_case(case, connection_failure(), "fixture"));
    tokio::select! {
        biased;
        result = &mut synthetic => panic!("synthetic dependency should wait for the writer: {result:?}"),
        () = std::future::ready(()) => {},
    }

    let first = registry.begin(CapturePhase::Runtime, None, None).unwrap();
    let attempted = first.prepare_output(OutputKind::End).unwrap();
    let second = registry.begin(CapturePhase::Runtime, None, None).unwrap();
    drop(attempted);
    first.output(OutputKind::End);
    first.finish_metadata("response");
    drop(first);

    let interrupted = second.prepare_output(OutputKind::End).unwrap();
    registry.close();
    registry.finish_incomplete();
    interrupted.commit();
    drop(second);

    drop(block_append);
    synthetic.await.unwrap();
    writer.seal(registry.coverage()).await.unwrap();

    let rows = std::fs::read_to_string(directory.path().join("dependencies.tsv")).unwrap();
    let rows: Vec<_> = rows
        .lines()
        .map(|row| row.split('\t').take(3).collect::<Vec<_>>())
        .collect();
    assert!(
        rows.windows(2).all(|pair| {
            pair[0][0].parse::<u64>().unwrap() < pair[1][0].parse::<u64>().unwrap()
        })
    );
    assert_eq!(
        rows.iter().map(|row| row[2]).collect::<Vec<_>>(),
        [
            "capture_started",
            "request",
            "response",
            "capture_terminated",
            "capture_started",
            "wire_output_started",
            "capture_started",
            "wire_output_cancelled",
            "wire_output_started",
            "wire_output",
            "wire_output_started",
            "wire_output_cancelled",
            "capture_terminated",
            "capture_sealed",
        ]
    );
    let events = traffic_recording_store::source::recording::events(directory.path())
        .unwrap()
        .collect::<anyhow::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|row| matches!(row.event, CaptureEvent::Output { .. }))
            .count(),
        1
    );
    let (_, manifest) =
        traffic_recording_store::source::recording::manifest(directory.path()).unwrap();
    assert_eq!(manifest.coverage.admitted, 3);
    assert_eq!(manifest.coverage.terminal, 3);
    assert_eq!(manifest.coverage.capture_failures, 1);
}
