use super::*;
use crate::active_case::ActiveCaseGuard;
use crate::active_case::async_api::tests::{active, drain, event};
use crate::protocols::recording::events::RecorderEvent;
use crate::recorder::capture_body;
use serde_json::json;

fn multiple(
    timeout: Duration,
    response_selected: bool,
) -> (ActiveCaseRegistry, ActiveCaseGuard, Uuid) {
    let (registry, guard, id) = active(timeout);
    let mut rule = json!({"end":[
        {"redis":{"operation":"DEL","key":"done:*","occurrence":2}},
        {"redis":{"operation":"GET","key":"telegram:*","when_response":{"kind":"nil"}}}
    ]});
    if response_selected {
        rule["when_response"] = json!({"/status":"in_progress"});
    }
    let rules = std::collections::BTreeMap::from([(
        "POST /api/v1/responses".into(),
        serde_json::from_value(rule).unwrap(),
    )]);
    let scope = AsyncScope::for_primary(
        &rules,
        &hyper::Method::POST,
        &"/api/v1/responses".parse().unwrap(),
        b"{}",
    )
    .unwrap();
    registry.configure_async_api(id, scope, Instant::now(), timeout);
    (registry, guard, id)
}

fn primary(registry: &ActiveCaseRegistry, id: Uuid) {
    registry.select_async_response(id, Some(&json!({"status":"in_progress"})));
}

fn complete(registry: &ActiveCaseRegistry, targets: &DependencyTargets, event: &RecorderEvent) {
    registry.observe_async_dependency_event(event, targets, true);
    registry.observe_stream_tail_event(event, targets, true);
}

fn issue(registry: &ActiveCaseRegistry, event: &RecorderEvent) {
    let targets = registry.current_targets_for_http_request(true);
    complete(registry, &targets, event);
}

fn hit_del(registry: &ActiveCaseRegistry) -> RecorderEvent {
    issue(registry, &event(false));
    let second = event(false);
    issue(registry, &second);
    second
}

fn final_get() -> RecorderEvent {
    let mut result = event(false);
    if let RecorderEvent::RedisExchange(event) = &mut result {
        event.command = "GET".into();
        event.args = vec![capture_body(b"telegram:42", 1024)];
        event.response_kind = "null".into();
        event.response = capture_body(b"$-1\r\n", 1024);
    }
    result
}

fn ordinary() -> RecorderEvent {
    let mut result = event(false);
    if let RecorderEvent::RedisExchange(event) = &mut result {
        event.command = "GET".into();
    }
    result
}

#[tokio::test]
async fn extra_request_requires_a_fresh_end_even_after_two_seconds_without_traffic() {
    let (registry, _guard, id) = multiple(Duration::from_secs(10), false);
    primary(&registry, id);
    let prior = hit_del(&registry);
    let draining = drain(&registry, id, Duration::from_secs(2));
    issue(&registry, &ordinary());
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert!(!draining.is_finished());
    assert!(registry.async_api_report(id).is_none());
    // Repeating an already observed exchange cannot grant another probe.
    registry.observe_async_dependency_event(&prior, &registry.current_targets_for_event(), true);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!draining.is_finished());
    issue(&registry, &final_get());
    tokio::time::timeout(Duration::from_millis(500), drain_join(draining))
        .await
        .expect("the last missing end must not start another one-second probe");
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["ending"], serde_json::Value::Null);
    assert_eq!(report["business_complete"], true);
    assert_eq!(report["business_completion"], "observed");
    assert_eq!(report["source_stop_required"], false);
    assert!(!registry.is_quiescing());
}

#[tokio::test]
async fn absent_next_end_keeps_source_alive_past_the_original_request_budget() {
    let (registry, _guard, id) = multiple(Duration::from_millis(80), false);
    primary(&registry, id);
    hit_del(&registry);
    issue(&registry, &ordinary());
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!draining.is_finished());
    assert!(!registry.is_quiescing());
    issue(&registry, &final_get());
    drain_join(draining).await;
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["end_reason"], "resource");
    assert_eq!(report["source_stop_required"], false);
    assert!(!registry.is_quiescing());
}

#[tokio::test]
async fn known_process_does_not_cancel_probe_or_keep_case_in_flight() {
    let (registry, _guard, id) = multiple(Duration::from_secs(5), false);
    primary(&registry, id);
    hit_del(&registry);
    let process = registry
        .current_targets_for_http_request(false)
        .into_process_owned("refresh".into());
    registry.observe_async_dependency_event(&ordinary(), &process, false);
    registry.observe_stream_tail_event(&ordinary(), &process, false);
    assert_eq!(
        drain(&registry, id, Duration::from_secs(1)).await.unwrap(),
        DependencyDrainResult::Drained
    );
    assert!(!registry.is_quiescing());
    assert_eq!(
        registry.async_api_report(id).unwrap().1["ending"]["reason"],
        "probe_completed"
    );
    drop(process);
}

#[tokio::test]
async fn partial_completion_still_requires_the_fixed_probe() {
    let (registry, _guard, id) = multiple(Duration::from_secs(10), false);
    primary(&registry, id);
    hit_del(&registry);
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!draining.is_finished());
    assert!(registry.async_api_report(id).is_none());
    drain_join(draining).await;
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["ending"]["reason"], "probe_completed");
    assert_eq!(report["business_complete"], false);
}

#[tokio::test]
async fn all_early_ends_close_immediately_after_primary_selects_the_scenario() {
    let (registry, _guard, id) = multiple(Duration::from_secs(10), true);
    hit_del(&registry);
    issue(&registry, &final_get());
    assert!(registry.async_api_report(id).is_none());
    primary(&registry, id);
    assert!(
        registry
            .current_targets_for_http_request(true)
            .cases
            .is_empty()
    );
    tokio::time::timeout(
        Duration::from_millis(500),
        drain_join(drain(&registry, id, Duration::from_secs(1))),
    )
    .await
    .expect("already matched ends need no post-response probe");
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["end_reason"], "resource");
    assert_eq!(report["business_complete"], true);
    assert_eq!(report["ending"], serde_json::Value::Null);
}

#[tokio::test]
async fn unknown_process_overlap_cancels_probe_without_granting_case_ownership() {
    let (registry, _guard, id) = multiple(Duration::from_millis(80), false);
    primary(&registry, id);
    hit_del(&registry);
    let targets = registry.current_targets_for_http_request(true);
    let tasks = std::collections::BTreeMap::from([
        ("a".into(), "first".into()),
        ("b".into(), "second".into()),
    ]);
    let unknown = crate::recorder::process_classification::classify(
        targets,
        ["a".into(), "b".into()],
        &tasks,
    );
    assert!(unknown.cases.is_empty());
    assert_eq!(unknown.unattributed_reason, Some("ambiguous_process_task"));
    registry.observe_async_dependency_event(&ordinary(), &unknown, false);
    registry.observe_stream_tail_event(&ordinary(), &unknown, false);
    drop(unknown);
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!draining.is_finished());
    assert!(!registry.is_quiescing());
    registry.begin_quiescing();
    drain_join(draining).await;
    assert_eq!(
        registry.async_api_report(id).unwrap().1["end_reason"],
        "stopped"
    );
}

#[tokio::test]
async fn request_start_at_probe_boundary_is_seen_before_atomic_closure() {
    let (registry, _guard, id) = multiple(Duration::from_secs(10), false);
    primary(&registry, id);
    hit_del(&registry);
    // Advance the probe close to its boundary without changing production time.
    {
        let state = registry.state.lock().unwrap();
        let observation = state.active[0].async_api.as_ref().unwrap();
        observation
            .ending
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .probe_started = Some(Instant::now() - Duration::from_millis(999));
    }
    let request = registry.current_targets_for_http_request(true);
    let draining = drain(&registry, id, Duration::from_secs(1));
    complete(&registry, &request, &ordinary());
    drop(request);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(!draining.is_finished());
    issue(&registry, &final_get());
    drain_join(draining).await;
}

async fn drain_join(draining: tokio::task::JoinHandle<DependencyDrainResult>) {
    assert_eq!(draining.await.unwrap(), DependencyDrainResult::Drained);
}

#[tokio::test]
async fn probe_uses_request_starts_not_completions_frames_or_writer_clones() {
    let (registry, _guard, id) = multiple(Duration::from_secs(10), false);
    primary(&registry, id);
    let earlier = registry.current_targets_for_http_request(true);
    hit_del(&registry);
    let draining = drain(&registry, id, Duration::from_secs(2));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        !draining.is_finished(),
        "already accepted real I/O must finish"
    );
    let writer = earlier.clone();
    earlier.note_stream_tail_activity();
    complete(&registry, &earlier, &ordinary());
    drop(earlier);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !draining.is_finished(),
        "writer still owns its publication barrier"
    );
    assert!(
        registry.async_api_report(id).is_some(),
        "completion cannot restart the fixed probe"
    );
    drop(writer);
    drain_join(draining).await;
}

#[tokio::test]
async fn early_candidate_cannot_be_reused_after_a_later_request_before_response_selection() {
    let (registry, _guard, id) = multiple(Duration::from_secs(10), true);
    hit_del(&registry);
    issue(&registry, &ordinary());
    primary(&registry, id);
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(!draining.is_finished());
    issue(&registry, &final_get());
    drain_join(draining).await;
}

#[tokio::test]
async fn single_end_remains_complete_when_previously_accepted_io_finishes_after_deadline() {
    let (registry, _guard, id) = active(Duration::from_millis(20));
    primary(&registry, id);
    let pending = registry.current_targets_for_http_request(true);
    issue(&registry, &event(false));
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(40)).await;
    complete(&registry, &pending, &ordinary());
    drop(pending);
    drain_join(draining).await;
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["end_reason"], "resource");
    assert_eq!(report["business_complete"], true);
    assert_eq!(report["source_stop_required"], false);
}

#[tokio::test]
async fn waiting_for_first_end_ignores_request_budget_and_explicit_stop_wakes_it() {
    let (registry, _guard, id) = multiple(Duration::from_millis(10), false);
    primary(&registry, id);
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!draining.is_finished());
    assert!(!registry.is_quiescing());
    registry.begin_quiescing();
    drain_join(draining).await;
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["end_reason"], "stopped");
    assert_eq!(report["business_complete"], false);
}

fn activity(registry: &ActiveCaseRegistry, id: Uuid) -> Arc<DependencyActivity> {
    registry
        .state
        .lock()
        .unwrap()
        .active
        .iter()
        .find(|case| case.case.id == id)
        .unwrap()
        .business_activity()
}

#[tokio::test]
async fn five_minute_idle_before_any_candidate_closes_only_case_and_ignores_process() {
    let (registry, _guard, id) = multiple(Duration::from_millis(10), false);
    primary(&registry, id);
    let activity = activity(&registry, id);
    activity.set_last_activity(Instant::now() - IDLE);
    let process = registry
        .current_targets_for_http_request(false)
        .into_process_owned("refresh".into());
    drain_join(drain(&registry, id, Duration::from_secs(1))).await;
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["end_reason"], "idle");
    assert_eq!(report["idle_completion"]["quiet_ms"], 300_000);
    assert_eq!(report["business_complete"], false);
    assert_eq!(report["business_completion"], "unobserved");
    assert_eq!(report["source_stop_required"], false);
    assert!(!registry.is_quiescing());
    drop(process);
}

#[tokio::test]
async fn waiting_for_next_end_uses_five_minute_idle_and_real_io_renews_it() {
    let (registry, _guard, id) = multiple(Duration::from_millis(10), false);
    primary(&registry, id);
    hit_del(&registry);
    let pending = registry.current_targets_for_http_request(true);
    let activity = activity(&registry, id);
    activity.set_last_activity(Instant::now() - IDLE);
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!draining.is_finished(), "in-flight I/O is never idle");
    complete(&registry, &pending, &ordinary());
    drop(pending);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !draining.is_finished(),
        "real completion starts another five-minute period"
    );
    activity.set_last_activity(Instant::now() - IDLE);
    // A new start racing an aged timer must revoke its inactivity eligibility.
    let fresh = registry.current_targets_for_http_request(true);
    complete(&registry, &fresh, &ordinary());
    drop(fresh);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!draining.is_finished());
    activity.set_last_activity(Instant::now() - IDLE);
    drain_join(draining).await;
    let report = registry.async_api_report(id).unwrap().1;
    assert_eq!(report["end_reason"], "idle");
    assert_eq!(report["ending"], serde_json::Value::Null);
    assert!(!registry.is_quiescing());
}

#[tokio::test]
async fn primary_response_starts_the_five_minute_inactivity_period() {
    let (registry, _guard, id) = multiple(Duration::from_millis(10), false);
    let activity = activity(&registry, id);
    activity.set_last_activity(Instant::now() - IDLE);
    primary(&registry, id);
    let draining = drain(&registry, id, Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!draining.is_finished());
    assert!(!registry.is_quiescing());
    registry.begin_quiescing();
    drain_join(draining).await;
    assert_eq!(
        registry.async_api_report(id).unwrap().1["end_reason"],
        "stopped"
    );
}
