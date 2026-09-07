use super::*;

#[test]
fn projects_a_bounded_evidence_view_from_the_recording_summary() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("source-process-traffic-summary.json"),
        r#"{
  "version": 1,
  "source": "recorder_events",
  "bootstrap": {
    "events": 2,
    "data_interactions": 1,
    "excluded_events": 1,
    "unresolved_interactions": 0,
    "observations": [{"protocol":"redis","endpoint":"redis.internal:20917","operation":"GET","interactions":1}],
    "omitted_interactions": 0,
    "truncated": false
  },
  "background": {
    "events": 3,
    "data_interactions": 3,
    "excluded_events": 0,
    "unresolved_interactions": 0,
    "rules": [{
      "name": "startup-cache-warm",
      "interactions": 3,
      "bootstrap_interactions": 1,
      "runtime_interactions": 2,
      "other_phase_interactions": 0,
      "unresolved_interactions": 0,
      "observations": [{"protocol":"redis","endpoint":"redis.internal:20917","operation":"GET","interactions":3}],
      "omitted_interactions": 0,
      "truncated": false,
      "redis_snapshot": {
        "seeds":1,
        "reuses":1,
        "fill_failures":1,
        "endpoints":[{"endpoint":"redis.internal:20917","seeds":1,"reuses":1,"fill_failures":1}],
        "omitted_interactions":0,
        "truncated":false
      }
    }],
    "omitted_interactions": 0,
    "truncated": false
  },
  "interpretation": "triage only"
}"#,
    )
    .unwrap();
    let mut state = crate::rewrite::test_state();
    state.case_source = Some(temp.path().to_path_buf());

    let view = evidence_view(temp.path(), &state);

    assert!(view.available);
    assert_eq!(view.scope, "recording_global");
    assert_eq!(view.bootstrap.as_ref().unwrap().protocols, ["redis"]);
    assert_eq!(view.bootstrap.unwrap().data_interactions, 1);
    let process_owned = view.process_owned.unwrap();
    assert_eq!(process_owned.rules_total, 1);
    assert_eq!(
        process_owned.rules[0]
            .redis_snapshot
            .as_ref()
            .unwrap()
            .reuses,
        1
    );
    assert_eq!(
        process_owned.rules[0]
            .redis_snapshot
            .as_ref()
            .unwrap()
            .endpoints[0]
            .endpoint,
        "redis.internal:20917"
    );

    let envelope = crate::rewrite::action::for_state(temp.path(), &state);
    let action = serde_json::to_value(envelope).unwrap();
    assert_eq!(action["schema_version"], 25);
    assert!(action.get("source_process_traffic").is_none());
}

#[test]
fn marks_legacy_recordings_unavailable_without_reading_raw_jsonl() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();
    state.case_source = Some(temp.path().to_path_buf());

    let view = evidence_view(temp.path(), &state);

    assert!(!view.available);
    assert!(view.reason.unwrap().contains("predates"));
}
