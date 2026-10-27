use super::*;
use crate::active_case::ActiveCaseGuard;
use crate::recorder::{RedisExchangeEvent, capture_body};

fn active(timeout: Duration) -> (ActiveCaseRegistry, ActiveCaseGuard, Uuid) {
    let registry = ActiveCaseRegistry::default();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "responses".into(),
        uri_group: None,
    };
    let guard = registry.try_reserve(case.clone()).unwrap();
    let rule=serde_json::from_value(serde_json::json!({"when":{"/background":true},"end":[{"redis":{"operation":"DEL","key":"done:*"}}]})).unwrap();
    let rules = std::collections::BTreeMap::from([("POST /api/v1/responses".into(), rule)]);
    let scope = AsyncScope::for_primary(
        &rules,
        &hyper::Method::POST,
        &"/api/v1/responses".parse().unwrap(),
        br#"{"background":true}"#,
    )
    .unwrap();
    registry.configure_async_api(case.id, scope, Instant::now(), timeout);
    registry.configure_stream_tail(case.id, Duration::ZERO, Instant::now(), timeout);
    guard.activate_dependencies().unwrap();
    (registry, guard, case.id)
}

fn event(failure: bool) -> RecorderEvent {
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: chrono::Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        target_host: "redis.test".into(),
        target_port: 6379,
        target_addr: "redis.test:6379".into(),
        upstream_addr: "redis.test:6379".into(),
        resp_version: 2,
        database: 0,
        username: None,
        command: if failure { "GET" } else { "DEL" }.into(),
        args: vec![capture_body(b"done:42", 1024)],
        response_kind: if failure { "error" } else { "integer" }.into(),
        response: capture_body(
            if failure {
                b"-ERR failure\r\n"
            } else {
                b":1\r\n"
            },
            1024,
        ),
        rpc_callback_capture: None,
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: crate::DependencyExchangeOutcome::Response,
        duration_ms: 0,
        replay_safe: true,
        parse_warnings: vec![],
    })
}

fn drain(
    registry: &ActiveCaseRegistry,
    id: Uuid,
    cleanup: Duration,
) -> tokio::task::JoinHandle<DependencyDrainResult> {
    let registry = registry.clone();
    tokio::spawn(async move {
        registry
            .drain_case_dependencies(id, Duration::ZERO, cleanup)
            .await
    })
}

#[tokio::test]
async fn unmatched_source_response_restores_ordinary_drain_after_an_early_signal() {
    let (registry, _guard, id) = active(Duration::from_secs(2));
    let rules = std::collections::BTreeMap::from([(
        "POST /api/v1/responses".into(),
        serde_json::from_value(serde_json::json!([{
            "when_response":{"/status":"queued"},
            "end":[{"redis":{"operation":"DEL","key":"done:*"}}]
        }]))
        .unwrap(),
    )]);
    let scope = AsyncScope::for_primary(
        &rules,
        &hyper::Method::POST,
        &"/api/v1/responses".parse().unwrap(),
        b"{}",
    )
    .unwrap();
    registry.configure_async_api(id, scope, Instant::now(), Duration::from_secs(2));
    let targets = registry.current_targets_for_http_request(true);
    registry.observe_async_dependency_event(&event(true), &targets, true);
    registry.select_async_response(id, Some(&serde_json::json!({"status":"completed"})));
    drop(targets);
    assert!(registry.async_api_report(id).is_none());
    assert_eq!(
        tokio::time::timeout(
            Duration::from_millis(100),
            drain(&registry, id, Duration::from_secs(1))
        )
        .await
        .unwrap()
        .unwrap(),
        DependencyDrainResult::Drained
    );
    assert!(!registry.is_quiescing());
}

#[tokio::test]
async fn early_terminal_is_retained_without_cutting_off_primary_or_dependency_capture() {
    let (registry, _guard, id) = active(Duration::from_secs(2));
    let targets = registry.current_targets_for_http_request(true);
    let terminal = event(false);
    registry.observe_async_dependency_event(&terminal, &targets, true);
    registry.observe_stream_tail_event(&terminal, &targets, true);
    drop(targets);
    // A worker may finish before Source sends its primary response. Admission
    // stays open until the primary finalizer starts draining this case.
    let during_primary = registry.current_targets_for_http_request(true);
    assert_eq!(during_primary.cases[0].0.id, id);
    drop(during_primary);
    assert_eq!(
        drain(&registry, id, Duration::from_secs(1)).await.unwrap(),
        DependencyDrainResult::Drained
    );
    assert!(!registry.is_quiescing());
    assert!(
        registry
            .current_targets_for_http_request(true)
            .cases
            .is_empty()
    );
    assert_eq!(
        registry.async_api_report(id).unwrap().1["end_reason"],
        "resource"
    );
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["inventory_complete"], true);
    assert_eq!(report["request_timeout_ms"], 2000);
    assert_eq!(report["completed_refs"].as_array().unwrap().len(), 1);
    assert_eq!(registry.invalidation_for(id), None);
}

#[tokio::test]
async fn terminal_waits_for_original_writer_reservations_and_no_idle_heuristic() {
    let (registry, _guard, id) = active(Duration::from_secs(2));
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert!(!draining.is_finished());
    let request = registry.current_targets_for_http_request(true);
    let writer = request.clone();
    registry.observe_async_dependency_event(&event(false), &request, true);
    drop(request);
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert!(!draining.is_finished());
    assert!(!registry.is_quiescing());
    drop(writer);
    assert_eq!(draining.await.unwrap(), DependencyDrainResult::Drained);
}

#[tokio::test]
async fn default_dependency_failure_stops_source_and_finishes_without_invalidation() {
    let (registry, _guard, id) = active(Duration::from_secs(2));
    let ordinary = registry.current_targets_for_http_request(true);
    let pending = ordinary.clone();
    let process = registry
        .current_targets_for_http_request(false)
        .into_process_owned("known-process-resource".into());
    registry.observe_async_dependency_event(&event(true), &process, false);
    registry.observe_async_dependency_event(&event(true), &ordinary, false);
    assert!(registry.async_api_report(id).is_none());
    registry.observe_async_dependency_event(&event(true), &ordinary, true);
    drop(ordinary);
    let draining = drain(&registry, id, Duration::from_millis(5));
    tokio::time::timeout(Duration::from_secs(1), registry.wait_for_quiescing())
        .await
        .unwrap();
    assert!(!draining.is_finished());
    assert_eq!(registry.invalidation_for(id), None);
    assert!(
        registry
            .current_targets_for_http_request(true)
            .cases
            .is_empty()
    );
    // Source shutdown/transport reset writes a termination observation against
    // this original reservation before finally releasing it.
    registry.observe_async_dependency_event(&event(true), &pending, true);
    drop(pending);
    drop(process);
    assert_eq!(draining.await.unwrap(), DependencyDrainResult::Drained);
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["end_reason"], "dependency_failure");
    assert_eq!(report["complete"], true);
    assert_eq!(report["source_stop_required"], true);
}

#[tokio::test]
async fn common_request_deadline_is_complete_and_preserves_original_inflight_io() {
    let (registry, _guard, id) = active(Duration::ZERO);
    let pending = registry.current_targets_for_http_request(true);
    let draining = drain(&registry, id, Duration::from_millis(5));
    tokio::time::timeout(Duration::from_secs(1), registry.wait_for_quiescing())
        .await
        .unwrap();
    assert!(!draining.is_finished());
    assert_eq!(registry.invalidation_for(id), None);
    registry.observe_async_dependency_event(&event(false), &pending, true);
    drop(pending);
    assert_eq!(draining.await.unwrap(), DependencyDrainResult::Drained);
    assert_eq!(
        registry.async_api_report(id).unwrap().1["end_reason"],
        "timeout"
    );
}

#[tokio::test]
async fn terminal_cleanup_budget_does_not_drop_unfinished_original_records() {
    let (registry, _guard, id) = active(Duration::from_secs(2));
    let pending = registry.current_targets_for_http_request(true);
    registry.observe_async_dependency_event(&event(false), &pending, true);
    let draining = drain(&registry, id, Duration::from_millis(5));
    tokio::time::timeout(Duration::from_secs(1), registry.wait_for_quiescing())
        .await
        .unwrap();
    assert!(!draining.is_finished());
    drop(pending);
    assert_eq!(draining.await.unwrap(), DependencyDrainResult::Drained);
    assert_eq!(
        registry.async_api_report(id).unwrap().1["end_reason"],
        "resource"
    );
}

#[tokio::test]
async fn source_stop_inventory_marks_only_original_unfinished_io_not_complete_business_errors() {
    let (registry, _guard, id) = active(Duration::ZERO);
    let pending = registry.current_targets_for_http_request(true);
    let mut incomplete = event(false);
    if let RecorderEvent::RedisExchange(event) = &mut incomplete {
        event.command = "GET".into();
        event.response_kind = "other".into();
        event.replay_safe = false;
        event
            .parse_warnings
            .push("engine cleanup interrupted Redis capture".into());
    }
    let mut ended_before_stop = event(false);
    if let RecorderEvent::RedisExchange(event) = &mut ended_before_stop {
        event.sequence = 3;
        event.outcome = crate::DependencyExchangeOutcome::ClientTerminated;
    }
    // The same shape without Source-stop ownership is ordinary invalid evidence.
    registry.observe_stream_tail_event(&incomplete, &pending, true);
    let draining = drain(&registry, id, Duration::from_millis(5));
    registry.wait_for_quiescing().await;
    let mut cleanup = incomplete.clone();
    if let RecorderEvent::RedisExchange(event) = &mut cleanup {
        event.sequence = 2;
        event.request_started_at = chrono::Utc::now();
        event.timestamp = event.request_started_at;
    }
    registry.observe_stream_tail_event(&cleanup, &pending, true);
    // A delayed writer hook cannot move an earlier real peer end past Stop.
    registry.observe_stream_tail_event(&ended_before_stop, &pending, true);
    registry.observe_stream_tail_event(&event(true), &pending, true);
    drop(pending);
    assert_eq!(draining.await.unwrap(), DependencyDrainResult::Drained);
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["cleanup_refs"].as_array().unwrap().len(), 1);
    assert_eq!(report["cleanup_refs"][0]["protocol"], "redis");
    assert_eq!(report["cleanup_refs"][0]["sequence"], 2);
}
