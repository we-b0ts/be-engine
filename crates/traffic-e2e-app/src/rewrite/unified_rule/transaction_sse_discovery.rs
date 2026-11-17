//! Public discovery must reach response evidence despite a large dependency trace.
use super::*;
use crate::{
    policy::{Slot, Surface},
    policy_evidence::{
        ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
        WitnessStore,
    },
    rewrite::model::RewriteIssueKind,
};

#[path = "transaction_sse_discovery/paging.rs"]
mod paging_tests;

fn install_dependencies(fixture: &Fixture) {
    let case = options(fixture).request.parent().unwrap().to_owned();
    let mut report: Value =
        serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    report["session_id"] = json!(session);
    let store = WitnessStore::new_bound(
        fixture.paths.replay.parent().unwrap(),
        &session,
        report["replay_policy"]["fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    let clocks = ClockPair {
        source: Some("2026-10-16T00:00:00Z".parse().unwrap()),
        target: Some("2026-10-16T00:01:00Z".parse().unwrap()),
    };
    let mut events = String::new();
    for sequence in 1..=300 {
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),
            "sequence":sequence,"timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
            "target_host":"cache.test","target_port":6379,"database":0,"command":"SET",
            "args":[raw_body(b"session"),raw_body(b"opaque")],"response":raw_body(b"+OK\r\n")});
        let source = crate::rewrite::unified_rule::preflight::dependency::source_witness(
            Surface::DependencyRequest,
            &event,
            &case,
        )
        .unwrap();
        store
            .record(
                WitnessMetadata {
                    surface: Surface::DependencyRequest,
                    source_role: SourceRole::DependencyRequest,
                    target_role: TargetRole::IndependentTargetObservation,
                    source: SourceIdentity {
                        case_id: "00000000-0000-4000-8000-000000000001".into(),
                        exchange_id: None,
                        connection_id: Some(uuid::Uuid::nil().to_string()),
                        sequence: Some(sequence),
                    },
                    resource: Some(
                        serde_json::from_value(json!({
                            "protocol":"redis","endpoint":"cache.test:6379","database":0
                        }))
                        .unwrap(),
                    ),
                    operation: "SET".into(),
                    slot: Slot::Value,
                    clocks: WitnessClocks {
                        case: clocks.clone(),
                        dependency: clocks.clone(),
                        delivery: clocks.clone(),
                    },
                },
                &case,
                &source,
                Some(&source),
            )
            .unwrap();
        events.push_str(&format!("{event}\n"));
    }
    fs::write(case.join("dependencies.jsonl"), events).unwrap();
    report["cases"][0]["target_request_started_at"] = json!(clocks.target);
    report["policy_witnesses"] = serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
    write(&fixture.paths.replay, report);
}

#[test]
fn response_discovery_reaches_sse_before_dependency_budget_is_exhausted() {
    let fixture = fixture();
    install_dependencies(&fixture);
    let mut state = fixture.state();
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
    fixture.store().save(&state).unwrap();
    let evidence = fixture.evidence();
    let facts = &evidence.facts;
    assert!(facts["coverage"]["recorded"].as_u64().unwrap() >= 300);
    assert_eq!(facts["bounded_analysis"]["limited"], true);
    assert!(facts["observations_examined"].as_u64().unwrap() <= 256);
    assert!(facts["candidates"].as_array().unwrap().iter().any(|c| {
        c["draft_policy"]["json"]["fields"]["/response/created_at"]["kind"] == "time"
    }));
    let binding = facts["source_entry"]["locations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["location"]["slot"]["sse_data"]["json_type"] == "response.output_item.added")
        .unwrap();
    assert_eq!(binding["source_intent_required"], true);
    assert!(
        binding["instruction"]
            .as_str()
            .unwrap()
            .contains("json.fields")
    );
    assert!(evidence.rule_hints.iter().any(|hint| {
        hint.capability == "sse_data_contract" && hint.hint.contains("terminal output")
    }));
    assert!(
        !facts["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["mechanism"] == "identity")
    );
    assert!(!serde_json::to_string(&evidence).unwrap().contains(PRIVATE));
}

#[test]
fn dependency_issue_retains_dependency_priority() {
    let fixture = fixture();
    install_dependencies(&fixture);
    let mut state = fixture.state();
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Dependency;
    fixture.store().save(&state).unwrap();
    let facts = fixture.evidence().facts;
    assert_eq!(
        facts["source_entry"]["locations"][0]["location"]["surface"],
        "dependency.request"
    );
    assert_eq!(facts["observations_examined"], 256);
    assert_eq!(facts["bounded_analysis"]["limited"], true);
}

#[test]
fn identity_only_differences_offer_source_guidance_without_inferred_permission() {
    let fixture = fixture();
    let mut target = stream(true);
    target["request_sent_at"] = json!("2026-10-16T00:00:00Z");
    target["interaction_started_at"] = json!("2026-10-16T00:00:00Z");
    for index in [0, 1, 6] {
        change_data(&mut target, index, |v| {
            v["response"]["created_at"] = json!(START)
        });
    }
    install(&fixture, stream(false), target);
    let evidence = fixture.evidence();
    assert_eq!(evidence.facts["candidate_count"], 0);
    assert!(
        !evidence.facts["source_entry"]["locations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let inventory = &evidence.facts["source_entry"]["identity_inventory"];
    assert_eq!(inventory["scope"], "case");
    assert_eq!(inventory["relationship"], "bijective_renaming");
    assert_eq!(inventory["observations_define_relations"], true);
    assert_eq!(inventory["automatic_permission"], false);
    for capability in ["sse_data_contract", "resource_field_contract"] {
        assert!(
            evidence
                .rule_hints
                .iter()
                .any(|hint| hint.capability == capability)
        );
    }
    assert!(
        evidence
            .applicable_rule_planners
            .iter()
            .any(|planner| planner.capability == "resource_field_contract")
    );
}

#[test]
fn stale_sse_evidence_keeps_discovery_but_routes_to_refresh_instead_of_plan() {
    let fixture = fixture();
    let plan = fixture.plan().unwrap();
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    let evidence = fixture.evidence();
    assert_eq!(
        evidence.facts["policy_freshness"]["requires_fresh_replay"],
        true
    );
    assert!(
        !evidence.facts["source_entry"]["locations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(evidence.applicable_rule_planners.is_empty());
    assert!(evidence.facts.get("plan").is_none());
    assert!(
        evidence
            .rule_hints
            .iter()
            .any(|hint| hint.capability == "fresh_replay")
    );
    assert!(
        !evidence
            .rule_hints
            .iter()
            .any(|hint| hint.capability == "sse_data_contract")
    );
    assert!(evidence.next_step.contains("refresh_command"));
    assert!(fixture.plan().is_err());
}
