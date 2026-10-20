use super::*;
use crate::active_case::ActiveCaseGuard;
use crate::config::BackgroundDependencyRuleConfig;
use crate::recorder::CaseContext;

fn scope() -> ApiOriginScope {
    let rule: BackgroundDependencyRuleConfig = serde_json::from_value(serde_json::json!({
        "protocol": "redis", "name": "async-cancel", "ports": [6379], "command": "GET",
        "key_templates": ["cancel:{task_id}"], "source_revision": "a".repeat(64),
        "source_evidence": "fixture async task",
        "trigger_source": {
            "kind": "api", "method": "POST", "path": "/jobs",
            "request_body_json": {"/background": true},
            "capture": {"task_id": {
                "protocol": "mysql", "target_host": "mysql.test", "target_port": 3306,
                "database": "jobs", "username": "app", "operation": "INSERT",
                "tables": ["tasks"], "row_match": {"kind": "Task"}, "column": "id"
            }}
        }
    }))
    .unwrap();
    ApiOriginScope::for_primary(
        &[rule],
        &hyper::Method::POST,
        &"/jobs".parse().unwrap(),
        br#"{"background":true}"#,
    )
    .unwrap()
}

fn active(idle: Duration, timeout: Duration) -> (ActiveCaseRegistry, ActiveCaseGuard, Uuid) {
    let registry = ActiveCaseRegistry::default();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "http".into(),
        uri_group: None,
    };
    let guard = registry.try_reserve(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    registry.configure_observation(case.id, scope(), idle, Instant::now(), timeout);
    (registry, guard, case.id)
}

fn request(registry: &ActiveCaseRegistry, key: &str) -> DependencyTargets {
    registry.current_targets_for_request(&DependencyRequest::Redis {
        target_port: 6379,
        command: "GET",
        args: &[key.as_bytes().to_vec()],
    })
}

#[test]
fn selected_request_clones_and_writer_lifetime_do_not_renew_business_activity() {
    let (registry, _guard, id) = active(Duration::from_millis(30), Duration::from_secs(1));
    let targets = request(&registry, "cancel:42");
    let writer_clone = targets.clone();
    let observation = registry.state.lock().unwrap().active[0]
        .observation
        .clone()
        .unwrap();
    assert_eq!(observation.activity.snapshot().0, 1);
    targets.complete_selected_request();
    let finished_at = observation.activity.snapshot().1;
    assert_eq!(observation.activity.snapshot().0, 0);
    writer_clone.complete_selected_request();
    drop(writer_clone);
    assert_eq!(observation.activity.snapshot().1, finished_at);
    assert_eq!(
        registry.observation_report(id).unwrap().1["rules"][0]["selected_selector_only"],
        1
    );
}

#[tokio::test]
async fn selected_in_flight_and_completion_restart_idle_beyond_initial_window() {
    let idle = Duration::from_millis(40);
    let (registry, _guard, id) = active(idle, Duration::from_secs(2));
    let targets = request(&registry, "cancel:42");
    let drain_registry = registry.clone();
    let drain = tokio::spawn(async move {
        drain_registry
            .drain_case_dependencies(id, Duration::ZERO, Duration::from_secs(1))
            .await
    });
    tokio::time::sleep(Duration::from_millis(65)).await;
    assert!(!drain.is_finished());
    targets.complete_selected_request();
    let completed = Instant::now();
    drop(targets);
    assert_eq!(drain.await.unwrap(), DependencyDrainResult::Drained);
    assert!(completed.elapsed() >= idle);
    assert!(registry.current_targets_for_event().cases.is_empty());
}

#[tokio::test]
async fn unrelated_requests_do_not_prevent_quiet_closure() {
    let (registry, _guard, id) = active(Duration::from_millis(35), Duration::from_secs(2));
    let drain_registry = registry.clone();
    let drain = tokio::spawn(async move {
        drain_registry
            .drain_case_dependencies(id, Duration::ZERO, Duration::from_secs(1))
            .await
    });
    // A busy unrelated key keeps arriving until admission closes.
    let started = Instant::now();
    loop {
        let targets = request(&registry, "periodic:unrelated");
        let closed = targets.cases.is_empty();
        drop(targets);
        if closed {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    assert_eq!(drain.await.unwrap(), DependencyDrainResult::Drained);
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn selected_activity_cannot_slide_the_absolute_request_deadline() {
    let (registry, _guard, id) = active(Duration::from_secs(1), Duration::from_millis(50));
    let drain_registry = registry.clone();
    let drain = tokio::spawn(async move {
        drain_registry
            .drain_case_dependencies(id, Duration::ZERO, Duration::from_millis(30))
            .await
    });
    for _ in 0..4 {
        let targets = request(&registry, "cancel:42");
        targets.complete_selected_request();
        drop(targets);
        tokio::time::sleep(Duration::from_millis(8)).await;
    }
    assert_eq!(
        drain.await.unwrap(),
        DependencyDrainResult::ObservationTimedOut
    );
    assert!(registry.current_targets_for_event().cases.is_empty());
}

#[tokio::test]
async fn a_stuck_request_is_bounded_without_resetting_source_or_admitting_another_case() {
    let (registry, _guard, id) = active(Duration::from_millis(5), Duration::from_millis(15));
    let _pending = request(&registry, "cancel:42");
    assert_eq!(
        registry
            .drain_case_dependencies(id, Duration::ZERO, Duration::from_millis(15))
            .await,
        DependencyDrainResult::TimedOut
    );
    assert!(registry.is_quiescing());
}

#[tokio::test]
async fn rpc_attribution_does_not_hold_drain_and_cannot_reacquire_closed_case() {
    let registry = ActiveCaseRegistry::default();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "http".into(),
        uri_group: None,
    };
    let guard = registry.try_reserve(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    let request = registry.current_targets_for_event();
    let reference = request.attribution_only();
    drop(request);
    assert!(registry.reacquire_targets(&reference).is_some());
    assert_eq!(
        registry
            .drain_case_dependencies(case.id, Duration::ZERO, Duration::from_millis(15))
            .await,
        DependencyDrainResult::Drained
    );
    assert!(registry.reacquire_targets(&reference).is_none());
    drop(guard);
}
