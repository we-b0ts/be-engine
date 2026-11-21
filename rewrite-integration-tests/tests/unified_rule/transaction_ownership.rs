//! Whole-task proof may move a victim's unused inputs, never another used scope.
use super::*;
use crate::dependency::attribution::{AttributionProof, DependencyOwner};
use crate::{
    AttributionCommandOptions, AttributionRuleBinding, AttributionSubmission, ProposedAttribution,
    VerificationImpact, VerificationScope, apply_dependency_attribution,
    dependency_attribution_context,
};
use serde_json::Value;
use std::collections::BTreeSet;

fn fixture(unused: bool) -> Fixture {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |_, source| {
        let event = json!({"event_type":"http_exchange","id":uuid::Uuid::new_v4(),"timestamp":"2026-10-16T00:00:00Z","request_started_at":"2026-10-16T00:00:00Z","scheme":"http","method":"GET","uri":"/refresh","authority":"worker.test:80","request_headers":{},"request_body":body(json!({})),"response_status":200,"response_headers":{},"response_body":body(json!({})),"duration_ms":1});
        fs::write(
            source.join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl"),
            format!("{event}\n"),
        )
        .unwrap();
        vec![]
    });
    let revision = crate::workflow_test_support::install_source_snapshot(fixture.root());
    fs::write(fixture.policy(),format!("format: traffic-policy/v3\nsource_revision: {revision}\nprocess_dependencies:\n  tasks:\n    refresh:\n      requests:\n        - http: {{host: worker.test, method: GET, path: /refresh}}\n")).unwrap();
    let mut state = fixture.state();
    state.source_revision = Some(revision.clone());
    let latest = fixture.paths.replay.parent().unwrap().parent().unwrap();
    let index = latest
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "focused"))
        .unwrap()
        .parent()
        .unwrap()
        .join("case-groups.json");
    let mut canonical: Value = serde_json::from_slice(&fs::read(&index).unwrap()).unwrap();
    canonical["source_revision"] = json!(revision);
    write(&index, canonical);
    let runner_path = latest.join("state.yaml");
    let mut runner: Value =
        serde_yaml::from_str(&fs::read_to_string(&runner_path).unwrap()).unwrap();
    runner["source_revision"] = json!(revision);
    fs::write(runner_path, serde_yaml::to_string(&runner).unwrap()).unwrap();
    state.recording_run_id = "recording".into();
    state.phase = if unused {
        crate::RewritePhase::ImplementationRequired
    } else {
        crate::RewritePhase::SliceComplete
    };
    state.e2e_current = !unused;
    state.target_fingerprint = Some(fingerprint::repository_fingerprint(fixture.root()).unwrap());
    state.replay_identity = Some(fingerprint::replay_identity(fixture.root()).unwrap());
    state.attempts=vec![serde_json::from_value(json!({"attempt":1,"passed":!unused,"engine_fingerprint":crate::build_info::ENGINE_FINGERPRINT,"gates":{"responses":"passed","replay":"complete","dependencies":if unused{"dirty"}else{"clean"}},"counts":{"selected":1,"executed":1,"response_passed":1,"response_nonpassing":0,"response_incomplete":0}})).unwrap()];
    let mut other = state.api_inventory[0].clone();
    other.api = "POST /other".into();
    other.source_route = Some("/other".into());
    state.api_inventory.push(other);
    for api in &mut state.api_inventory {
        api.e2e_current = true;
        api.status = crate::RewriteApiStatus::Complete;
        api.verified_target_fingerprint = Some("unrelated-current".into());
    }
    fixture.store().save(&state).unwrap();
    let raw: Value = serde_json::from_str(
        fs::read_to_string(
            state
                .case_source
                .as_ref()
                .unwrap()
                .join("dependencies.jsonl"),
        )
        .unwrap()
        .lines()
        .next()
        .unwrap(),
    )
    .unwrap();
    let mut report: Value =
        serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
    report["session_id"] = json!(uuid::Uuid::new_v4());
    let event = json!({"case_id":"00000000-0000-4000-8000-000000000001","source_exchange_id":raw["capture"]["exchange_id"],"source_http_id":raw["id"]});
    report[if unused {
        "unused_case_http_exchanges"
    } else {
        "matched_http_exchanges"
    }] = json!([event]);
    write(&fixture.paths.replay, report);
    fixture
}

fn apply(fixture: &Fixture) {
    let state = fixture.state();
    let source = state.case_source.as_ref().unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(source.join("dependency-manifest.json")).unwrap())
            .unwrap();
    let context = dependency_attribution_context(fixture.context()).unwrap();
    let policy =
        crate::policy::parse_and_compile_policy(&fs::read_to_string(fixture.policy()).unwrap())
            .unwrap();
    let epoch = serde_json::from_value(manifest["process_epochs"][0].clone()).unwrap();
    let proposal = ProposedAttribution {
        claim_ids: BTreeSet::new(),
        source_exchange_ids: BTreeSet::new(),
        source_task: "refresh".into(),
        owner: DependencyOwner::Process {
            process_epoch: epoch,
            source_task: "refresh".into(),
            invocation: None,
        },
        proof: AttributionProof {
            source_revision: state.source_revision.clone().unwrap(),
            source_locations: vec!["src/refresh.rs:run".into()],
            call_chain: "Source startup spawns refresh and its GET /refresh request".into(),
            exclusive_scope: "Only refresh emits the exact worker request".into(),
        },
        impact: VerificationImpact::Classification,
        obligation_scope: VerificationScope::Process {
            source_task: "refresh".into(),
            process_epoch: epoch,
        },
        missing_evidence: None,
        rule_binding: AttributionRuleBinding {
            policy_fingerprint: policy.fingerprints.full,
            rule_ids: policy
                .native
                .iter()
                .map(|rule| rule.rule.id.clone())
                .collect(),
        },
    };
    let input = AttributionSubmission {
        schema: "dependency-attribution/v3".into(),
        assignment_id: context.assignment_id,
        expected_revision: context.revision,
        recording_run_id: context.recording_run_id,
        source_revision: context.source_revision,
        source_inventory_id: context.source_inventory_id,
        decisions: vec![proposal],
        investigation_resolutions: vec![],
        unresolved_claim_ids: BTreeSet::new(),
        claim_rejections: vec![],
    };
    let path = fixture.root().join(".traffic-e2e/local/ownership.json");
    fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    apply_dependency_attribution(AttributionCommandOptions {
        target_root: fixture.root().into(),
        file: path,
    })
    .unwrap();
}

#[test]
fn proved_foreign_unused_ownership_keeps_the_victim_free_of_extra_replay_debt() {
    let fixture = fixture(true);
    let before = fs::read(&fixture.paths.replay).unwrap();
    apply(&fixture);
    let state = fixture.state();
    assert_eq!(state.dependency_review.obligations.len(), 1);
    assert!(
        state
            .dependency_review
            .obligations
            .values()
            .all(|obligation| matches!(obligation.scope, VerificationScope::Process { .. }))
    );
    assert_eq!(fs::read(&fixture.paths.replay).unwrap(), before);
}

#[test]
fn moving_a_previously_used_case_scope_invalidates_that_method_and_preserves_unrelated_apis() {
    let fixture = fixture(false);
    let before = fs::read(&fixture.paths.replay).unwrap();
    apply(&fixture);
    let state = fixture.state();
    assert!(!state.e2e_current && state.target_fingerprint.is_none());
    assert!(state.dependency_review.obligations.values().any(|obligation|matches!(&obligation.scope,VerificationScope::Api{api,method,..} if api=="/api" && method.as_deref()==Some("GET"))));
    let other = state
        .api_inventory
        .iter()
        .find(|item| item.api == "POST /other")
        .unwrap();
    assert!(other.e2e_current);
    assert_eq!(
        other.verified_target_fingerprint.as_deref(),
        Some("unrelated-current")
    );
    assert_eq!(fs::read(&fixture.paths.replay).unwrap(), before);
}

#[test]
fn an_implementer_can_return_unused_traffic_without_proving_exclusion_or_passing_responses() {
    let fixture = fixture(true);
    fixture.confirm();
    let mut state = fixture.state();
    state.attempts[0].gates.responses = crate::E2eResponseGate::Nonpassing;
    state.attempts[0].counts.response_passed = 0;
    state.attempts[0].counts.response_nonpassing = 1;
    fixture.store().save(&state).unwrap();
    let raw: Value = serde_json::from_str(
        fs::read_to_string(
            state
                .case_source
                .as_ref()
                .unwrap()
                .join("dependencies.jsonl"),
        )
        .unwrap()
        .lines()
        .next()
        .unwrap(),
    )
    .unwrap();
    let path = fixture.root().join(".traffic-e2e/local/return-unused.json");
    write(
        &path,
        json!({"schema":"dependency-attribution/v3","api":"/api",
        "evidence_id":fixture.evidence().evidence_id,
        "source_exchange_ids":[raw["capture"]["exchange_id"]],"reason":"This concrete dependency is not part of my API"}),
    );
    let before = fs::read(&fixture.paths.replay).unwrap();
    let response = crate::claim_foreign_unused(AttributionCommandOptions {
        target_root: fixture.root().into(),
        file: path,
    })
    .unwrap();
    assert_eq!(response["owner"], "repository_analyst");
    assert_eq!(response["accepted"], false);
    let stored = fixture.state();
    let claim = stored.dependency_review.claims.values().next().unwrap();
    assert!(claim.exclusion.is_none());
    assert!(!claim.reason.is_empty());
    assert!(stored.dependency_review.receipts.is_empty());
    assert_eq!(fs::read(&fixture.paths.replay).unwrap(), before);
}
