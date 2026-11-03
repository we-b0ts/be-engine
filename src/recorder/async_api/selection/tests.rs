use super::*;
use crate::recorder::async_api::tests::redis;
use serde_json::json;

fn scope(scenarios: Value, body: &[u8]) -> AsyncScope {
    AsyncScope::for_primary(
        &BTreeMap::from([(
            "POST /jobs".into(),
            serde_json::from_value(scenarios).unwrap(),
        )]),
        &Method::POST,
        &"/jobs".parse().unwrap(),
        body,
    )
    .unwrap()
}

#[test]
fn early_terminal_is_retained_for_only_the_first_matching_response_scenario() {
    let scenarios = json!([
        {"when_response":{"/status":"queued"},"end":[{"redis":{"operation":"DEL","key":"queued:*"}}]},
        {"when_response":{"/status":"in_progress"},"end":[{"redis":{"operation":"DEL","key":"running:*"}}]},
        {"when_response":{"/status":"queued"},"end":[{"redis":{"operation":"DEL","key":"other:*"}}]}
    ]);
    let early = scope(scenarios.clone(), b"{}");
    assert!(early.observe(&redis("DEL", b"running:42")).is_none());
    assert!(early.observe(&redis("DEL", b"queued:42")).is_none());
    let (selected, signal) = early.select_response(Some(&json!({"status":"queued"})));
    assert!(selected);
    assert_eq!(early.scenario_index(), Some(0));
    assert_eq!(signal.unwrap().end_reason, AsyncEndReason::Resource);

    let late = scope(scenarios, b"{}");
    assert!(late.observe(&redis("DEL", b"other:42")).is_none());
    assert!(
        late.select_response(Some(&json!({"status":"queued"})))
            .1
            .is_none()
    );
    assert!(late.observe(&redis("DEL", b"running:42")).is_none());
    assert_eq!(
        late.observe(&redis("DEL", b"queued:42"))
            .unwrap()
            .resource_index,
        Some(0)
    );
}

#[test]
fn redis_occurrences_remain_independent_across_candidates_and_response_boundary() {
    let scope = scope(
        json!([
            {"when_response":{"/status":"queued"},"end":[{"redis":{"operation":"DEL","key":"done:*"}}]},
            {"when_response":{"/status":"in_progress"},"end":[{"redis":{"operation":"DEL","key":"done:*","occurrence":2}}]}
        ]),
        b"{}",
    );
    let initial = redis("DEL", b"done:42");
    assert!(scope.observe(&initial).is_none());
    assert!(
        scope
            .select_response(Some(&json!({"status":"in_progress"})))
            .1
            .is_none()
    );
    assert_eq!(scope.scenario_index(), Some(1));
    assert!(
        scope.observe(&initial).is_none(),
        "mirrored event must not increment count"
    );
    assert!(scope.observe(&redis("DEL", b"done:other")).is_none());
    assert_eq!(
        scope.observe(&redis("DEL", b"done:42")).unwrap().end_reason,
        AsyncEndReason::Resource
    );
}

#[test]
fn request_filters_exclusions_and_no_match_do_not_borrow_other_scenarios() {
    let scope = scope(
        json!([
            {"when":{"/background":true},"end":[{"redis":{"operation":"DEL","key":"done:*"}}]},
            {"when_response":{"/status":"queued"},"unless_response":{"/is_latest":true},"end":[{"redis":{"operation":"DEL","key":"done:*"}}]}
        ]),
        br#"{"background":"true"}"#,
    );
    assert!(scope.observe(&redis("DEL", b"done:42")).is_none());
    assert!(
        !scope
            .select_response(Some(&json!({"status":"queued","is_latest":true})))
            .0
    );
    assert_eq!(scope.scenario_index(), None);
    assert!(scope.observe(&redis("DEL", b"done:42")).is_none());
}

#[test]
fn earlier_response_condition_takes_priority_over_unconditional_fallback() {
    for (response, expected) in [
        (json!({"status":"queued"}), 0),
        (json!({"status":"completed"}), 1),
    ] {
        let scope = scope(
            json!([
                {"when_response":{"/status":"queued"},"end":[{"redis":{"operation":"DEL","key":"queued:*"}}]},
                {"end":[{"redis":{"operation":"DEL","key":"fallback:*"}}]}
            ]),
            b"{}",
        );
        assert!(scope.observe(&redis("DEL", b"fallback:42")).is_none());
        let (_, signal) = scope.select_response(Some(&response));
        assert_eq!(scope.scenario_index(), Some(expected));
        assert_eq!(signal.is_some(), expected == 1);
    }
}

#[test]
fn provenance_retains_the_original_group_and_the_actually_selected_scenario() {
    let scenarios = json!([
        {"when":{"/background":true},"when_response":{"/status":"queued"},"end":[{"redis":{"operation":"DEL","key":"queued:*"}}]},
        {"when_response":{"/status":"in_progress"},"end":[{"redis":{"operation":"DEL","key":"running:*","occurrence":2}}]}
    ]);
    let rules = serde_json::from_value(scenarios.clone()).unwrap();
    let scope = scope(scenarios, b"{}");
    assert!(scope.selected_provenance().is_none());
    scope.select_response(Some(&json!({"status":"in_progress"})));
    assert_eq!(
        scope.selected_provenance(),
        crate::policy::AsyncRuleProvenance::selected("POST /jobs", &rules, 1)
    );
}
