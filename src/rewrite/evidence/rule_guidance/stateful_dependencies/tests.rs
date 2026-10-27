use super::*;
use serde_json::json;

fn capabilities(facts: &Value) -> Vec<String> {
    hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, facts)
        .into_iter()
        .map(|hint| hint.capability)
        .collect()
}

#[test]
fn redis_mechanisms_follow_observed_operations_without_assuming_source_proof() {
    for (command, expected) in [
        ("APPEND", vec!["redis_append_stream"]),
        ("EXPIRE", vec!["redis_expiry_refresh"]),
        ("LRANGE", vec!["redis_read_back"]),
        (
            "GET",
            vec![
                "redis_finite_process_get",
                "redis_read_back",
                "redis_read_commutation",
                "redis_read_observation",
                "redis_state_observations",
            ],
        ),
    ] {
        let facts = json!({"clusters":[{"protocol":"redis","reason":"unmatched_target","operations":{command:1}}]});
        assert_eq!(capabilities(&facts), expected);
        for hint in hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts) {
            assert!(hint.hint.contains("not proof that a rule applies"));
            assert!(hint.hint.contains("Source file:line proof"));
            assert!(hint.hint.contains("complete Source coverage"));
            assert!(hint.hint.contains("fresh genuine Replay"));
            assert!(hint.hint.contains("See docs/"));
        }
    }
}

#[test]
fn typed_failures_and_lane_blockers_supply_scoped_capability_discovery() {
    let facts = json!({"clusters":[{"protocol":"redis","representative":{"difference":{
        "actual":{"presence":"present","signature":{"command":"MGET","diagnostic":{"kind":"redis_append_stream_boundary_mismatch"}}}}}}]});
    assert_eq!(capabilities(&facts), vec!["redis_append_stream"]);
    let facts = json!({"clusters":[{"protocol":"redis","representative":{"difference":{
        "actual":{"presence":"present","signature":{"diagnostic":{"kind":"redis_state_observation_mismatch"}}}}}}]});
    assert_eq!(capabilities(&facts), vec!["redis_state_observations"]);
    let facts = json!({"clusters":[{"protocol":"redis","operations":{"SET":1},"representative":{"difference":{
        "actual":{"presence":"present","signature":{"diagnostic":{"kind":"lane_blocked","blocked_by":{"command":"GET"}}}}}}}]});
    assert!(capabilities(&facts).contains(&"redis_read_commutation".into()));
    let hint = hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts)
        .into_iter()
        .find(|hint| hint.capability == "redis_read_commutation")
        .unwrap();
    assert!(
        hint.hint
            .contains("does not prove nil values or independence")
    );
}

#[test]
fn read_back_guidance_explains_key_local_state_and_finite_historical_reads() {
    let facts = json!({"clusters":[{"protocol":"redis","operations":{"GET":1}}]});
    let hints = hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts);
    let finite = hints
        .iter()
        .find(|h| h.capability == "redis_read_back")
        .unwrap();
    assert!(finite.hint.contains("redis.keys"));
    assert!(finite.hint.contains("read_back: true"));
    assert!(finite.hint.contains("finite counts"));
    let state = hints
        .iter()
        .find(|h| h.capability == "redis_state_observations")
        .unwrap();
    assert!(state.hint.contains("independent Source proof"));
    assert!(
        state
            .hint
            .contains("Historical reads before the first owned SET stay finite")
    );
    assert!(state.hint.contains("positive write-to-read witness"));
}

#[test]
fn ordinary_mysql_reads_need_no_native_delivery_rule_or_select_template() {
    let facts = json!({"clusters":[{"protocol":"mysql","operations":{"COM_QUERY":1},"representative":{"difference":{
        "expected":{"presence":"present","signature":{"sql_summary":"SELECT payload FROM records WHERE id=?"}}}}}]});
    assert!(capabilities(&facts).is_empty());
}

#[test]
fn unified_source_bindings_expose_supported_delivery_without_inventing_target_evidence() {
    let facts = json!({"source_entry":{"locations":[
        {"location":{"surface":"dependency.response","match":{"resource":{"protocol":"mysql"},"operation":"COM_QUERY"},"slot":{"sql_column":"payload"}},"source_intent_required":true},
        {"location":{"surface":"dependency.request","match":{"resource":{"protocol":"redis"},"operation":"APPEND"},"slot":"value"}},
        {"location":{"surface":"dependency.response","match":{"resource":{"protocol":"redis"},"operation":"GET"},"slot":"value"}}
    ]}});
    let root = Path::new("/target");
    let hints = hints(root, QUERY_UNIFIED_RULE_CANDIDATES, &facts);
    let found: Vec<_> = hints.iter().map(|hint| hint.capability.as_str()).collect();
    assert_eq!(
        found,
        vec![
            "redis_append_stream",
            "redis_finite_process_get",
            "redis_read_back",
            "redis_read_commutation",
            "redis_read_observation",
            "redis_state_observations"
        ]
    );
    assert!(
        hints
            .iter()
            .all(|hint| hint.hint.contains("not proof that a rule applies"))
    );
    let planners = super::super::applicable_rule_planners(
        root,
        RewriteIssueKind::Response,
        QUERY_UNIFIED_RULE_CANDIDATES,
        &facts,
        "current",
    );
    assert!(
        planners
            .iter()
            .all(|planner| planner.capability != "mysql_read_back")
    );
    assert!(capabilities(&facts).is_empty());
}

#[test]
fn finite_process_get_guidance_requires_issuer_proof_and_preserves_finite_evidence() {
    let facts = json!({"clusters":[{"protocol":"redis","operations":{"GET":1}}]});
    let hint = hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts)
        .into_iter()
        .find(|hint| hint.capability == "redis_finite_process_get")
        .unwrap();
    assert!(hint.hint.contains("not captured issuer provenance"));
    assert!(hint.hint.contains("sibling APIs using the same key"));
    assert!(hint.hint.contains("single-use"));
    assert!(hint.hint.contains("exhaustion fails"));
    assert!(hint.hint.contains("omitting initial_load_timeout_ms"));
    assert!(
        hint.hint
            .contains("snapshot seeds/hits cannot supply finite evidence")
    );
}

#[test]
fn global_mysql_content_has_no_per_select_read_back_planner() {
    let facts = json!({"source_entry":{"locations":[{"location":{"surface":"dependency.response","match":{"resource":{"protocol":"mysql"},"operation":"COM_QUERY"}},"source_response_kind":"resultset"}]}});
    assert!(hints(Path::new("/target"), QUERY_UNIFIED_RULE_CANDIDATES, &facts).is_empty());
}

#[test]
fn protocol_presence_unknown_operations_and_missing_observations_do_not_offer_rules() {
    for cluster in [
        json!({"protocol":"redis"}),
        json!({"protocol":"redis","operations":{"HGET":1,"GET":0}}),
        json!({"protocol":"http","operations":{"GET":1,"APPEND":1,"EXPIRE":1,"SELECT":1}}),
        json!({"protocol":"mysql","operations":{"GET":1,"COM_QUERY":1},"representative":{"difference":{"actual":{"presence":"present","signature":{"sql":"UPDATE records SET payload=?"}}}}}),
        json!({"protocol":"mysql","operations":{"COM_QUERY":1}}),
        json!({"protocol":"mysql","representative":{"difference":{"actual":{"presence":"missing","signature":{"command":"SELECT"}}}}}),
        json!({"protocol":"http","representative":{"difference":{"actual":{"presence":"present","signature":{"diagnostic":{"kind":"redis_append_stream_mismatch"}}}}}}),
    ] {
        assert!(capabilities(&json!({"clusters":[cluster]})).is_empty());
    }
    let facts = json!({"clusters":[{"protocol":"redis","operations":{"GET":1}}]});
    assert!(hints(Path::new("/target"), QUERY_REPRESENTATIVES, &facts).is_empty());
}

#[test]
fn planners_use_current_evidence_and_respect_issue_query_and_stale_policy_boundaries() {
    let root = Path::new("/target");
    let mut facts = json!({"clusters":[{"protocol":"redis","operations":{"APPEND":1,"EXPIRE":1,"GET":1,"LRANGE":1}},{"protocol":"mysql","operations":{"SELECT":1}}]});
    for issue in [
        RewriteIssueKind::Response,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Replay,
    ] {
        let planners = super::super::applicable_rule_planners(
            root,
            issue,
            QUERY_DIRTY_CLUSTERS,
            &facts,
            "current",
        );
        for capability in capabilities(&facts) {
            let planner = planners
                .iter()
                .find(|p| p.capability == capability)
                .unwrap();
            assert_eq!(planner.evidence_id, "current");
            assert!(planner.command.argv.contains(&"--file".into()));
            assert!(planner.command.argv.contains(&"--evidence".into()));
            assert!(planner.command.argv.contains(&"current".into()));
        }
        assert!(super::planners(root, issue, QUERY_REPRESENTATIVES, &facts, "current").is_empty());
    }
    facts["policy_freshness"] = json!({"requires_fresh_replay":true});
    assert!(
        super::super::applicable_rule_planners(
            root,
            RewriteIssueKind::Dependency,
            QUERY_DIRTY_CLUSTERS,
            &facts,
            "current"
        )
        .is_empty()
    );
    assert!(
        super::super::rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts)
            .iter()
            .all(|hint| !capabilities(&facts).contains(&hint.capability))
    );
}
