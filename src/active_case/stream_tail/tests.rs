use super::*;
use crate::active_case::ActiveCaseGuard;
use crate::recorder::{CaseContext, HttpExchangeEvent};

fn active(idle: Duration, timeout: Duration) -> (ActiveCaseRegistry, ActiveCaseGuard, Uuid) {
    let registry = ActiveCaseRegistry::default();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "http".into(),
        uri_group: None,
    };
    let guard = registry.try_reserve(case.clone()).unwrap();
    registry.configure_stream_tail(case.id, idle, Instant::now(), timeout);
    guard.activate_dependencies().unwrap();
    (registry, guard, case.id)
}

fn exchange() -> RecorderEvent {
    RecorderEvent::HttpExchange(HttpExchangeEvent {
        id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        scheme: "http".into(),
        method: "POST".into(),
        uri: "/generation".into(),
        authority: Some("llm.test".into()),
        request_headers: Default::default(),
        request_body: crate::recorder::capture_body(b"", 1024),
        response_status: Some(200),
        response_headers: None,
        response_body: Some(crate::recorder::capture_body(b"done", 1024)),
        response_stream: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: 0,
        error: None,
        outcome: crate::DependencyExchangeOutcome::Response,
    })
}

fn drain(
    registry: &ActiveCaseRegistry,
    id: Uuid,
    writer_timeout: Duration,
) -> tokio::task::JoinHandle<DependencyDrainResult> {
    let registry = registry.clone();
    tokio::spawn(async move {
        registry
            .drain_case_dependencies(id, Duration::ZERO, writer_timeout)
            .await
    })
}

#[tokio::test]
async fn request_started_before_stream_adoption_outlives_short_writer_budget() {
    let (registry, _guard, id) = active(Duration::from_millis(15), Duration::from_secs(2));
    let targets = registry.current_targets_for_http_request(true);
    let writer_clone = targets.clone();
    registry.enable_stream_tail(id);
    let tail = registry.enabled_stream_tail(id).unwrap();
    assert_eq!(tail.activity.snapshot().0, 1);
    let drain = drain(&registry, id, Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(45)).await;
    assert!(!drain.is_finished());
    assert!(!registry.is_quiescing());
    let event = exchange();
    registry.observe_stream_tail_event(&event, &targets, true);
    let completed = tail.activity.snapshot().1;
    assert_eq!(tail.activity.snapshot().0, 0);
    writer_clone.note_stream_tail_activity();
    registry.observe_stream_tail_event(&event, &writer_clone, true);
    assert_eq!(tail.activity.snapshot().1, completed);
    drop(targets);
    drop(writer_clone);
    assert_eq!(drain.await.unwrap(), DependencyDrainResult::Drained);
    assert!(!registry.is_quiescing());
    let report = registry.stream_tail_report(id).unwrap().1;
    assert_eq!(report["completed_refs"].as_array().unwrap().len(), 1);
    assert_eq!(report["completed_refs"][0]["protocol"], "http");
}

#[tokio::test]
async fn new_finite_requests_restart_idle_without_releasing_case_admission() {
    let (registry, _guard, id) = active(Duration::from_millis(50), Duration::from_secs(2));
    registry.enable_stream_tail(id);
    let drain = drain(&registry, id, Duration::from_millis(30));
    tokio::time::sleep(Duration::from_millis(25)).await;
    let late = registry.current_targets_for_http_request(true);
    assert_eq!(late.cases[0].0.id, id);
    registry.observe_stream_tail_event(&exchange(), &late, true);
    drop(late);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!drain.is_finished());
    assert_eq!(drain.await.unwrap(), DependencyDrainResult::Drained);
    assert!(
        registry
            .current_targets_for_http_request(true)
            .cases
            .is_empty()
    );
}

#[tokio::test]
async fn metadata_and_proven_process_requests_do_not_renew_or_hold_tail() {
    let (registry, _guard, id) = active(Duration::from_millis(15), Duration::from_secs(2));
    registry.enable_stream_tail(id);
    let tail = registry.enabled_stream_tail(id).unwrap();
    let before = tail.activity.snapshot();
    let metadata = registry.current_targets_for_event();
    let process = registry
        .current_targets_for_http_request(false)
        .into_process_owned("periodic-refresh".into());
    assert!(process.cases.is_empty());
    assert_eq!(
        process.process_owned_rule.as_deref(),
        Some("periodic-refresh")
    );
    assert_eq!(tail.activity.snapshot(), before);
    registry.observe_stream_tail_event(&exchange(), &process, false);
    drop(metadata);
    assert_eq!(
        drain(&registry, id, Duration::from_millis(10))
            .await
            .unwrap(),
        DependencyDrainResult::Drained
    );
    assert!(!registry.is_quiescing());
    assert!(
        registry.stream_tail_report(id).unwrap().1["completed_refs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Keeping a proven process request alive did not keep the case writer alive.
    drop(process);
}

#[tokio::test]
async fn absolute_deadline_preserves_live_request_and_late_inventory_until_natural_end() {
    let (registry, _guard, id) = active(Duration::from_millis(10), Duration::from_millis(30));
    registry.enable_stream_tail(id);
    let targets = registry.current_targets_for_http_request(true);
    let drain = drain(&registry, id, Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(registry.is_quiescing());
    assert!(!drain.is_finished());
    assert!(registry.case_slot_occupied());
    assert!(
        registry
            .current_targets_for_http_request(true)
            .cases
            .is_empty()
    );
    registry.observe_stream_tail_event(&exchange(), &targets, true);
    drop(targets);
    assert_eq!(
        drain.await.unwrap(),
        DependencyDrainResult::ObservationTimedOut
    );
    assert_eq!(
        registry.stream_tail_report(id).unwrap().1["completed_refs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn writer_timeout_preserves_guard_until_queued_original_case_evidence_is_released() {
    let (registry, _guard, id) = active(Duration::from_millis(10), Duration::from_secs(2));
    registry.enable_stream_tail(id);
    let targets = registry.current_targets_for_http_request(true);
    registry.observe_stream_tail_event(&exchange(), &targets, true);
    let drain = drain(&registry, id, Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(registry.is_quiescing());
    assert!(!drain.is_finished());
    assert!(registry.case_slot_occupied());
    drop(targets);
    assert_eq!(drain.await.unwrap(), DependencyDrainResult::TimedOut);
}

#[tokio::test]
async fn zero_idle_still_waits_for_real_requests_beyond_writer_timeout() {
    let (registry, _guard, id) = active(Duration::ZERO, Duration::from_secs(2));
    registry.enable_stream_tail(id);
    let targets = registry.current_targets_for_http_request(true);
    let drain = drain(&registry, id, Duration::from_millis(5));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!drain.is_finished());
    assert!(!registry.is_quiescing());
    registry.observe_stream_tail_event(&exchange(), &targets, true);
    drop(targets);
    assert_eq!(drain.await.unwrap(), DependencyDrainResult::Drained);
}

#[tokio::test]
async fn process_detachment_keeps_bootstrap_writer_barrier() {
    let registry = ActiveCaseRegistry::default();
    let targets = registry
        .current_targets_for_http_request(false)
        .into_process_owned("startup-cache".into());
    assert!(targets.bootstrap_open);
    let waiting_registry = registry.clone();
    let seal =
        tokio::spawn(async move { waiting_registry.wait_for_bootstrap_dependencies().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!seal.is_finished());
    drop(targets);
    seal.await.unwrap();
}

#[tokio::test]
async fn late_capture_failure_invalidates_original_case_after_admission_closes() {
    let (registry, _guard, id) = active(Duration::ZERO, Duration::from_millis(10));
    registry.enable_stream_tail(id);
    let targets = registry.current_targets_for_http_request(true);
    let drain = drain(&registry, id, Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let failure = crate::recorder::CaseInvalidation::new("capture_failure", "late capture failure");
    assert_eq!(
        registry.invalidate_case(id, failure.clone()).unwrap().id,
        id
    );
    assert_eq!(registry.invalidation_for(id), Some(failure));
    registry.observe_stream_tail_event(&exchange(), &targets, true);
    drop(targets);
    assert_eq!(
        drain.await.unwrap(),
        DependencyDrainResult::ObservationTimedOut
    );
}
