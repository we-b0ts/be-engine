use super::*;
use crate::evidence::{QUERY_DIRTY_CLUSTERS, rule_guidance};
use crate::model::RewriteIssueKind;

fn attach_default(facts: &mut Value) {
    attach(facts, crate::protocols::default_providers().report_codecs()).unwrap();
}
fn limitations(facts: &Value) -> Vec<String> {
    crate::protocols::default_providers()
        .report_codecs()
        .diagnose(facts)
        .unwrap()
        .limitations
}
fn next_step(facts: &Value) -> String {
    super::next_step(
        &crate::protocols::default_providers()
            .report_codecs()
            .diagnose(facts)
            .unwrap(),
    )
}

#[test]
fn unused_read_guidance_preserves_uncertainty_and_does_not_offer_a_time_fix() {
    let mut facts = json!({
        "clusters": [{"cluster_id":"unused", "protocol":"mysql", "reason":"unused_recorded", "operations":{"COM_QUERY":1}}],
        "dependency_request_candidates":[], "dynamic_capture_candidates":[]
    });
    let recorded_clusters = facts["clusters"].clone();
    attach_default(&mut facts);
    assert_eq!(facts["clusters"], recorded_clusters);
    let diagnosis = &facts["mysql_unused_diagnosis"];
    assert_eq!(diagnosis["cluster_ids"], json!(["unused"]));
    assert_eq!(diagnosis["ownership"], "unresolved");
    assert_eq!(diagnosis["observation"], "recorded_calls_not_consumed");
    assert!(!limitations(&facts).is_empty());
    assert!(next_step(&facts).contains("mysql_unused_diagnosis.source_checks"));
    for kind in [
        RewriteIssueKind::Replay,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Response,
    ] {
        let planners = rule_guidance::applicable_rule_planners(
            Path::new("/target"),
            kind,
            QUERY_DIRTY_CLUSTERS,
            &facts,
            "current",
        );
        assert!(
            planners
                .iter()
                .all(|p| p.capability != "resource_field_contract")
        );
    }
    let hints = rule_guidance::rule_hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts);
    let hint = hints
        .iter()
        .find(|h| h.capability == "api_triggered_process_traffic")
        .unwrap();
    assert!(hint.hint.contains("not evidence of process ownership"));
}

#[test]
fn mysql_guidance_is_scoped_without_hiding_other_dirty_reasons() {
    for cluster in [
        json!({"protocol":"mysql", "reason":"unmatched_target"}),
        json!({"protocol":"redis", "reason":"unused_recorded"}),
    ] {
        let mut facts = json!({"clusters":[cluster]});
        let original = facts.clone();
        attach_default(&mut facts);
        assert_eq!(facts, original);
        assert!(limitations(&facts).is_empty());
        assert!(!next_step(&facts).contains("mysql_unused_diagnosis"));
    }
    let mut facts = json!({"clusters":[
        {"cluster_id":"unused", "protocol":"mysql", "reason":"unused_recorded"},
        {"cluster_id":"unmatched", "protocol":"mysql", "reason":"unmatched_target"}
    ]});
    attach_default(&mut facts);
    assert_eq!(
        facts["mysql_unused_diagnosis"]["cluster_ids"],
        json!(["unused"])
    );
    let planners = rule_guidance::applicable_rule_planners(
        Path::new("/target"),
        RewriteIssueKind::Replay,
        QUERY_DIRTY_CLUSTERS,
        &facts,
        "current",
    );
    assert!(
        planners
            .iter()
            .any(|p| p.capability == "resource_field_contract")
    );
}

#[test]
fn unmatched_transaction_evidence_guides_the_write_interval_without_value_rules() {
    let cluster = json!({
        "cluster_id":"transaction", "protocol":"mysql", "reason":"unmatched_target", "count":1,
        "representative":{"difference":{"actual":{"signature":{
            "diagnostic":{"kind":"mysql_autocommit_transaction_coverage",
                "reason":"target_transaction_members_or_end_differ",
                "source_transactions":[{"write_count":2,"source_connection_id":"source-connection","first_write_query_sequence":5,
                    "last_query_sequence":9,"required_operation_count":4,"end":"commit",
                    "target_status_before":2,"target_status_after":2,
                    "member_comparison":{"first_difference":{"member_position":1,
                        "expected":{"source_query_sequence":6},"actual":{"source_query_sequence":8}}}}]}
        }}}}
    });
    let mut facts = json!({"clusters":[cluster.clone()]});
    attach_default(&mut facts);
    assert_eq!(facts["clusters"], json!([cluster]));
    assert!(facts.get("mysql_unused_diagnosis").is_none());
    let diagnosis = &facts["mysql_autocommit_diagnosis"];
    assert_eq!(
        diagnosis["clusters"][0]["transaction_evidence"]["source_transactions"][0]["write_count"],
        2
    );
    assert_eq!(
        diagnosis["clusters"][0]["connection_id"],
        "source-connection"
    );
    assert_eq!(diagnosis["clusters"][0]["query_sequence"], 9);
    let checks = diagnosis["target_checks"].to_string();
    for text in [
        "FIRST WRITE",
        "trailing",
        "Prefix",
        "0x0002",
        "with_transaction",
        "first_difference",
    ] {
        assert!(checks.contains(text), "missing {text}");
    }
    for text in [
        "affected_rows=0",
        "affected_rows>0",
        "UPDATE error",
        "failed end controls",
    ] {
        assert!(
            checks.contains(text),
            "missing single-UPDATE guidance: {text}"
        );
    }
    assert!(
        diagnosis["source_checks"]
            .to_string()
            .contains("autocommit_eligible")
    );
    assert!(!limitations(&facts).is_empty());
    assert!(next_step(&facts).contains("first-write-through-end"));
    assert_eq!(
        diagnosis["clusters"][0]["transaction_evidence"]["source_transactions"][0]["member_comparison"]
            ["first_difference"]["actual"]["source_query_sequence"],
        8
    );
    let planners = rule_guidance::applicable_rule_planners(
        Path::new("/target"),
        RewriteIssueKind::Replay,
        QUERY_DIRTY_CLUSTERS,
        &facts,
        "current",
    );
    assert!(planners.iter().all(|planner| !matches!(
        planner.capability.as_str(),
        "resource_field_contract" | "dynamic_value"
    )));
    // A distinct SQL mismatch still needs its ordinary rule discovery.
    facts["clusters"].as_array_mut().unwrap().push(json!({
        "protocol":"mysql", "reason":"unmatched_target", "count":1,
        "representative":{"difference":{"actual":{"signature":{"sql":"SELECT 1"}}}}
    }));
    assert!(has_value_difference(&facts));
    facts["clusters"].as_array_mut().unwrap().pop();
    facts["clusters"][0]["count"] = json!(2);
    assert!(has_value_difference(&facts));
}

struct CustomDiagnosis;
impl traffic_protocol::report::ReportCodec for CustomDiagnosis {
    fn diagnostics(&self) -> &dyn traffic_protocol::report::diagnostics::DiagnosticSchema {
        self
    }
}
impl traffic_protocol::report::diagnostics::DiagnosticSchema for CustomDiagnosis {
    fn diagnose(&self, facts: &Value) -> traffic_protocol::report::diagnostics::Diagnosis {
        traffic_protocol::report::diagnostics::Diagnosis {
            details: serde_json::Map::from_iter([(
                "vendor_diagnosis".into(),
                facts["clusters"].clone(),
            )]),
            limitations: vec!["vendor evidence is bounded".into()],
            next_steps: vec!["Inspect vendor Source framing".into()],
        }
    }
    fn has_value_difference(&self, _: &Value) -> bool {
        true
    }
}

#[test]
fn registered_native_diagnosis_reaches_rewrite_facts_and_guidance() {
    let mut codecs = CodecRegistry::default();
    codecs
        .register(
            traffic_protocol::ProtocolId::new("vendor"),
            std::sync::Arc::new(CustomDiagnosis),
        )
        .unwrap();
    let mut facts = json!({"clusters":[{"protocol":"vendor", "reason":"value_differs"}]});
    let original = facts.clone();
    let diagnosis = attach(&mut facts, &codecs).unwrap();
    assert_eq!(facts["clusters"], original["clusters"]);
    assert_eq!(facts["vendor_diagnosis"], original["clusters"]);
    assert!(super::next_step(&diagnosis).contains("Inspect vendor Source framing"));
    assert!(
        super::super::dirty_cluster_limitations(&diagnosis)
            .contains(&"vendor evidence is bounded".into())
    );
    assert!(codecs.has_value_difference(&facts));
    assert!(!CodecRegistry::default().has_value_difference(&facts));
    let before = facts.clone();
    assert!(attach(&mut facts, &codecs).is_err());
    assert_eq!(facts, before);
}

#[test]
fn native_diagnosis_name_conflicts_publish_no_partial_facts() {
    let mut codecs = CodecRegistry::default();
    for name in ["vendor-one", "vendor-two"] {
        codecs
            .register(
                traffic_protocol::ProtocolId::new(name),
                std::sync::Arc::new(CustomDiagnosis),
            )
            .unwrap();
    }
    let mut facts = json!({"clusters":[]});
    let before = facts.clone();
    assert!(attach(&mut facts, &codecs).is_err());
    assert_eq!(facts, before);
}

#[test]
fn standard_native_candidate_findings_reach_the_existing_hint_api() {
    let finding = json!({"policy":"fixture-extension","source_path":"/field",
        "native_location":"opaque-location","summary":"Native field differs",
        "hint":"Inspect Source generation at this location","proposal":null,"requirements":["source_semantics"]});
    let mut facts = json!({"clusters":[{"protocol":"vendor-rpc","reason":"unmatched_target",
    "representative":{"difference":{"actual":{"signature":{
        "target_observation_id":"observed-request",
        "candidate_comparisons":[{"source_reference":{"protocol":"vendor-rpc","native_id":"source-request"},
            "source_case_id":"case-a","source":"case","policy_findings":[finding]}]
    }}}}}]});
    attach(&mut facts, &CodecRegistry::default()).unwrap();
    assert_eq!(
        facts["policy_findings"][0]["origin"]["target_observation_id"],
        "observed-request"
    );
    let hints = rule_guidance::rule_hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts);
    let hint = hints
        .iter()
        .find(|hint| hint.rule == "fixture-extension")
        .unwrap();
    assert_eq!(hint.hint, "Inspect Source generation at this location");
}
