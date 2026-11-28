use super::*;
use crate::evidence::{QUERY_DIRTY_CLUSTERS, rule_guidance};
use crate::model::RewriteIssueKind;

fn attach_default(facts: &mut Value) {
    attach(facts, crate::protocols::default_providers().report_codecs()).unwrap();
}
#[test]
fn unused_mysql_read_does_not_offer_a_value_fix() {
    let mut facts = json!({
        "clusters": [{"cluster_id":"unused", "protocol":"mysql", "reason":"unused_recorded", "operations":{"COM_QUERY":1}}],
        "dependency_request_candidates":[], "dynamic_capture_candidates":[]
    });
    let original = facts.clone();
    attach_default(&mut facts);
    assert_eq!(facts, original);
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
    assert!(
        rule_guidance::rule_hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts).is_empty()
    );
}

#[test]
fn unmatched_transaction_evidence_remains_available_without_value_rules() {
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
    assert_eq!(facts, json!({"clusters":[cluster]}));
    let diagnostic =
        &facts["clusters"][0]["representative"]["difference"]["actual"]["signature"]["diagnostic"];
    let interval = &diagnostic["source_transactions"][0];
    assert_eq!(interval["write_count"], 2);
    assert_eq!(interval["source_connection_id"], "source-connection");
    assert_eq!(interval["last_query_sequence"], 9);
    assert_eq!(
        interval["member_comparison"]["first_difference"]["actual"]["source_query_sequence"],
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
