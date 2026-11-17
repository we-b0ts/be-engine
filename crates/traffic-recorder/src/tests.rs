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

#[tokio::test]
async fn queued_scope_retains_the_hosts_guard_until_its_record_is_written() {
    let directory = tempfile::tempdir().unwrap();
    let epoch = Uuid::new_v4();
    let writer = RecorderWriter::start(
        Arc::new(directory.path().to_owned()),
        TrafficJsonlMode::Off,
        JsonlBufferSettings {
            capacity: 4096,
            flush_interval: Duration::from_secs(60),
        },
        8,
        Arc::new(Mutex::new(HashSet::new())),
        CaptureOptions {
            process_epoch: epoch,
            policy_identity: "capture-policy".into(),
            evidence: Arc::new(EvidenceRegistry::default()),
        },
    )
    .await
    .unwrap();
    let registry = ledger::CaptureRegistry::new(writer.clone(), epoch);
    let capture = registry.begin(CapturePhase::Runtime, None, None).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let event = DependencyConnectFailureEvent {
        id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        client_addr: None,
        protocol: "fixture".into(),
        target_host: "fixture.test".into(),
        target_port: 1234,
        duration_ms: 1,
        failure_kind: "connection_refused".into(),
        client_outcome: "reset".into(),
    };
    writer
        .try_record(RecordEnvelope {
            event: CapturedEvent::capture(&event).unwrap(),
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
    let records = tokio::fs::read_to_string(directory.path().join("dependencies.jsonl"))
        .await
        .unwrap();
    assert_eq!(records.lines().count(), 1);
    let value: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
    assert_eq!(value["event_type"], "dependency_connect_failure");
}
