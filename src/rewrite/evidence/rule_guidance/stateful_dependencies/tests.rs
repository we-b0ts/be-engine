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
                "redis_read_back",
                "redis_read_commutation",
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
fn read_back_guidance_explains_additive_updates_and_distinct_count_authority() {
    let facts = json!({"clusters":[{"protocol":"redis","operations":{"GET":1}}]});
    let hints = hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts);
    let finite = hints
        .iter()
        .find(|h| h.capability == "redis_read_back")
        .unwrap();
    assert!(finite.hint.contains("Update the existing write rule"));
    assert!(finite.hint.contains("finite counts"));
    let state = hints
        .iter()
        .find(|h| h.capability == "redis_state_observations")
        .unwrap();
    assert!(state.hint.contains("add state_epochs proof"));
    assert!(state.hint.contains("otherwise unchanged declaration"));
    assert!(state.hint.contains("positive write-to-read witness"));
}

#[test]
fn mysql_read_back_requires_mysql_read_facts_and_preserves_source_causality() {
    let facts = json!({"clusters":[{"protocol":"mysql","operations":{"COM_STMT_EXECUTE":1},"representative":{"difference":{
        "expected":{"presence":"present","signature":{"sql_summary":"SELECT payload FROM records WHERE id=?"}}}}}]});
    assert_eq!(capabilities(&facts), vec!["mysql_read_back"]);
    let hint = &hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts)[0].hint;
    assert!(hint.contains("must already be an authorized reference"));
    assert!(hint.contains("completed before the Source read"));
    assert!(hint.contains("derived delivery is not independent Target evidence"));
    assert!(hint.contains("SELECTs remain finite"));
    assert!(hint.contains("Source-proven sharded ORM SELECT"));
    assert!(hint.contains("bounded table_series"));
    assert!(hint.contains("AS {{table}}_suffix"));
    assert!(hint.contains("Do not enumerate witnessed shards"));
    assert!(hint.contains("numeric object keys stay literal"));

    let facts = json!({"clusters":[{"protocol":"mysql","reason":"unused_recorded","operations":{"COM_QUERY":1},"representative":{"difference":{
        "expected":{"presence":"present","signature":{"sql_summary":{"preview":"SELECT records.payload AS records_payload, records.id AS records_id …","truncated":true,"select_body":{"preview":"FROM records WHERE id=?","truncated":false}}}}}}}]});
    assert_eq!(capabilities(&facts), vec!["mysql_read_back"]);
}

#[test]
fn unified_source_bindings_expose_supported_delivery_without_inventing_target_evidence() {
    let facts = json!({"source_entry":{"bindings":[
        {"binding":{"surface":"dependency.response","match":{"resource":{"protocol":"mysql"},"operation":"COM_QUERY"},"slot":{"sql_column":"payload"}},"source_intent_required":true},
        {"binding":{"surface":"dependency.request","match":{"resource":{"protocol":"redis"},"operation":"APPEND"},"slot":"value"}},
        {"binding":{"surface":"dependency.response","match":{"resource":{"protocol":"redis"},"operation":"GET"},"slot":"value"}}
    ]}});
    let root = Path::new("/target");
    let hints = hints(root, QUERY_UNIFIED_RULE_CANDIDATES, &facts);
    let found: Vec<_> = hints.iter().map(|hint| hint.capability.as_str()).collect();
    assert_eq!(
        found,
        vec![
            "mysql_read_back",
            "redis_append_stream",
            "redis_read_back",
            "redis_read_commutation",
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
            .any(|planner| planner.capability == "mysql_read_back")
    );
    assert!(capabilities(&facts).is_empty());
}

#[test]
fn source_mysql_resultsets_reveal_capability_before_a_value_contract_is_configured() {
    let mut facts = json!({"source_entry":{"bindings":[{"binding":{"surface":"dependency.response","match":{"resource":{"protocol":"mysql"},"operation":"COM_QUERY"}},"source_response_kind":"resultset","needs_sql_template":true,"needs_slot":true}]}});
    let root = Path::new("/target");
    assert_eq!(
        hints(root, QUERY_UNIFIED_RULE_CANDIDATES, &facts)[0].capability,
        "mysql_read_back"
    );
    for status in ["ok", "error", "unknown"] {
        facts["source_entry"]["bindings"][0]["source_response_kind"] = status.into();
        assert!(hints(root, QUERY_UNIFIED_RULE_CANDIDATES, &facts).is_empty());
    }
    facts["source_entry"]["bindings"][0]["source_response_kind"] = "resultset".into();
    facts["source_entry"]["bindings"][0]["binding"]["surface"] = "dependency.request".into();
    assert!(hints(root, QUERY_UNIFIED_RULE_CANDIDATES, &facts).is_empty());
    facts["source_entry"]["bindings"][0]["binding"]["surface"] = "dependency.response".into();
    facts["source_entry"]["bindings"][0]["binding"]["match"]["resource"]["protocol"] =
        "http".into();
    assert!(hints(root, QUERY_UNIFIED_RULE_CANDIDATES, &facts).is_empty());
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
