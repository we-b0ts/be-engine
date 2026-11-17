//! Current recorder facts enter the real attribution transaction and query paths.
use super::*;
use crate::{
    dependency::attribution::AttributionProof,
    protocols::recording::events::{HttpExchangeEvent, RecorderEvent, RedisExchangeEvent},
    recorder::{Recorder, capture_body},
};
use uuid::Uuid;

mod shutdown;

const POLICY: &str = "format: traffic-policy/v3\nsource_revision: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nprocess_dependencies:\n  tasks:\n    refresh:\n      requests:\n        - http: {host: worker.test, method: GET, path: /refresh}\n        - redis: {operation: GET, keys: [{kind: exact, value: refresh}], ports: [6379]}\nrules: []\n";

fn http(path: &str) -> RecorderEvent {
    RecorderEvent::HttpExchange(HttpExchangeEvent {
        outcome: crate::DependencyExchangeOutcome::Response,
        id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        scheme: "http".into(),
        method: "GET".into(),
        uri: path.into(),
        authority: Some("worker.test:80".into()),
        request_headers: Default::default(),
        request_body: capture_body(b"", 16),
        response_status: Some(200),
        response_headers: Some(Default::default()),
        response_body: Some(capture_body(b"ok", 16)),
        response_stream: None,
        discovered_tcp_targets: vec![],
        duration_ms: 1,
        error: None,
    })
}

fn redis() -> RecorderEvent {
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: chrono::Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        target_host: "cache.test".into(),
        target_port: 6379,
        target_addr: "cache.test:6379".into(),
        upstream_addr: "cache.test:6379".into(),
        resp_version: 2,
        database: 0,
        username: None,
        command: "GET".into(),
        args: vec![capture_body(b"refresh", 16)],
        response_kind: "bulk_string".into(),
        response: capture_body(b"$1\r\n2\r\n", 16),
        rpc_callback_capture: None,
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: crate::DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: vec![],
    })
}

async fn fixture(count: usize) -> (tempfile::TempDir, RewriteState) {
    let target = crate::rewrite::worker::tests::configured_target();
    fs::write(target.path().join(".traffic-e2e/policy.yaml"), POLICY).unwrap();
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    for _ in 0..count {
        recorder
            .append_global_dependency(
                &http("/refresh"),
                "between_cases",
                "runtime",
                "unattributed",
            )
            .await
            .unwrap();
    }
    recorder
        .append_global_dependency(&redis(), "between_cases", "runtime", "unattributed")
        .await
        .unwrap();
    recorder.finish_run().await.unwrap();
    let mut state = crate::rewrite::test_support::test_state();
    state.case_source = Some(recorder.run_dir().as_ref().clone());
    state.recording_run_id = recorder
        .run_dir()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .into();
    state.source_revision =
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (target, state)
}

#[tokio::test]
async fn ownerless_context_matches_full_source_before_and_after_admission_inventory_is_cached() {
    let (target, mut state) = fixture(2).await;
    let full = context_for(target.path(), &state, &source::load(&state).unwrap()).unwrap();
    assert_eq!(full.unattributed_exchange_ids.len(), 3);
    for cached in [false, true] {
        if cached {
            analysis::refresh_inventory(target.path(), &mut state).unwrap();
        }
        let (identity, ids) = analysis::review_inventory(target.path(), &state).unwrap();
        let bounded =
            context_from_inventory(target.path(), &state, &identity, ids.into_owned()).unwrap();
        assert_eq!(
            serde_json::to_value(&bounded).unwrap(),
            serde_json::to_value(&full).unwrap()
        );
    }
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let context = super::super::RewriteContext {
        target_root: target.path().into(),
    };
    assert_eq!(
        dependency_attribution_context(context.clone())
            .unwrap()
            .unattributed_exchange_ids
            .len(),
        3
    );
    // Even a warmed admission projection cannot hide a changed sealed artifact.
    let central = state
        .case_source
        .as_ref()
        .unwrap()
        .join("dependencies.jsonl");
    let mut bytes = fs::read(&central).unwrap();
    bytes.push(b'\n');
    fs::write(central, bytes).unwrap();
    assert!(dependency_attribution_context(context).is_err());
}

#[tokio::test]
async fn unused_occurrence_projection_matches_full_source_and_retains_seal_checks() {
    let (_target, state) = fixture(2).await;
    let full = source::load(&state).unwrap();
    let projected = source::occurrences::load(&state).unwrap();
    let traversals = source::occurrences::ORIGINAL_TRAVERSALS.get();
    let cached = source::occurrences::load(&state).unwrap();
    assert_eq!(
        source::occurrences::ORIGINAL_TRAVERSALS.get(),
        traversals,
        "warm diagnostics must not traverse original payloads"
    );
    assert_eq!(cached.exchanges.len(), projected.exchanges.len());
    assert_eq!(cached.apis, projected.apis);
    let directory =
        crate::dependency_index::store::cache_directory(state.case_source.as_ref().unwrap());
    fs::write(
        directory.join("diagnostic-occurrences-v1.json"),
        b"broken cache",
    )
    .unwrap();
    let rebuilt = source::occurrences::load(&state).unwrap();
    assert_eq!(
        source::occurrences::ORIGINAL_TRAVERSALS.get(),
        traversals + 1
    );
    assert_eq!(rebuilt.exchanges.len(), projected.exchanges.len());
    assert_eq!(projected.identity, full.identity);
    assert_eq!(projected.apis, full.apis);
    assert_eq!(projected.case_defaults, full.case_defaults);
    assert_eq!(projected.exchanges.len(), full.exchanges.len());
    for (id, expected) in &full.exchanges {
        let actual = &projected.exchanges[id];
        assert_eq!(
            serde_json::to_value(&actual.capture).unwrap(),
            serde_json::to_value(&expected.capture).unwrap()
        );
        assert_eq!(actual.complete, expected.complete);
        assert_eq!(
            actual.selector["event_type"],
            expected.selector["event_type"]
        );
        assert!(actual.selector.get("uri").is_none());
        assert!(actual.selector.get("args").is_none());
    }
    let http = full
        .http
        .keys()
        .map(|id| json!({"case_id":"selected","source_http_id":id}))
        .collect::<Vec<_>>();
    let redis = full
        .native
        .keys()
        .filter(|(protocol, _, _)| protocol == "redis")
        .map(|(_, connection, sequence)| {
            json!({"case_id":"selected","connection_id":connection,"sequence":sequence,"command":"GET"})
        })
        .collect::<Vec<_>>();
    let report = json!({"unused_case_http_exchanges":http,"redis":{"unused_case":redis},
        "unused_case_exchanges":[{"case_id":"other","source_exchange_id":Uuid::new_v4()}]});
    let selected = BTreeSet::from(["selected".into()]);
    let expected = source::unused(&full, &report, &selected).unwrap();
    assert_eq!(expected.len(), 3);
    assert_eq!(projected.unused(&report, &selected).unwrap(), expected);
    let unknown = json!({"unused_case_exchanges":[{
        "case_id":"selected","source_exchange_id":Uuid::new_v4()}]});
    assert!(projected.unused(&unknown, &selected).is_err());
    let central = state
        .case_source
        .as_ref()
        .unwrap()
        .join("dependencies.jsonl");
    let mut bytes = fs::read(&central).unwrap();
    let modified = fs::metadata(&central).unwrap().modified().unwrap();
    let position = bytes
        .windows(b"worker.test".len())
        .position(|value| value == b"worker.test")
        .unwrap();
    bytes[position..position + b"worker.test".len()].copy_from_slice(b"tamper.test");
    fs::write(&central, bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(&central)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert!(source::occurrences::load(&state).is_err());
}

#[tokio::test]
async fn occurrence_metadata_from_another_recording_is_rebuilt() {
    let (_first_target, first) = fixture(1).await;
    let (_second_target, second) = fixture(4).await;
    let first_metadata = source::occurrences::load(&first).unwrap();
    let directory = |state: &RewriteState| {
        crate::dependency_index::store::cache_directory(state.case_source.as_ref().unwrap())
    };
    let second_directory = directory(&second);
    crate::dependency_index::store::private_directory(&second_directory).unwrap();
    fs::copy(
        directory(&first).join("diagnostic-occurrences-v1.json"),
        second_directory.join("diagnostic-occurrences-v1.json"),
    )
    .unwrap();
    let before = source::occurrences::ORIGINAL_TRAVERSALS.get();
    let second_metadata = source::occurrences::load(&second).unwrap();
    assert_ne!(first_metadata.identity, second_metadata.identity);
    assert_eq!(second_metadata.exchanges.len(), 5);
    assert_eq!(source::occurrences::ORIGINAL_TRAVERSALS.get(), before + 1);
}

#[tokio::test]
async fn issue_overview_and_empty_unused_detail_do_not_traverse_original_payloads() {
    let (target, mut state) = fixture(2).await;
    state.phase = super::super::RewritePhase::ImplementationRequired;
    state.active_issue = Some(serde_json::from_value(json!({"id":"issue","kind":"dependency",
        "owner":"target_code","summary":"unused dependencies","observed_target_fingerprint":"target",
        "attempt":1})).unwrap());
    super::super::worker::confirm_current_for_test(&mut state);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let context = super::super::RewriteContext {
        target_root: target.path().into(),
    };
    let before = source::occurrences::ORIGINAL_TRAVERSALS.get();
    let report = super::super::query_rewrite_evidence_for_scope(
        context.clone(),
        &super::super::RewriteWorkScope::Api { api: "/api".into() },
    )
    .unwrap();
    assert_eq!(source::occurrences::ORIGINAL_TRAVERSALS.get(), before);
    let detail_id = report.facts["api_information"]["query_id"]
        .as_str()
        .unwrap();
    let detail = super::super::query_rewrite_evidence(context, detail_id).unwrap();
    assert_eq!(source::occurrences::ORIGINAL_TRAVERSALS.get(), before);
    assert_eq!(detail.facts["schema"], "target-api-information/v3");
    assert_eq!(detail.facts["dependency_occurrences"]["available"], true);
    assert_eq!(detail.facts["dependency_occurrences"]["unused_total"], 0);
}

#[tokio::test]
async fn single_source_information_preserves_sealed_physical_identity_and_shape() {
    let (target, state) = fixture(2).await;
    let source = source::load(&state).unwrap();
    for (id, expected) in &source.exchanges {
        let actual = dependency_attribution_source_information(
            super::super::RewriteContext {
                target_root: target.path().into(),
            },
            &id.to_string(),
        )
        .unwrap();
        assert_eq!(actual["source_inventory_id"], source.identity);
        assert_eq!(
            actual["capture"],
            serde_json::to_value(&expected.capture).unwrap()
        );
        assert_eq!(actual["capture_complete"], expected.complete);
        assert_eq!(
            actual["request_shape"]["event_type"],
            expected.selector["event_type"]
        );
        assert!(actual.get("selector").is_none());
        assert!(actual["request_shape"].get("args").is_none());
        assert!(actual.get("response").is_none());
    }
    assert!(
        dependency_attribution_source_information(
            super::super::RewriteContext {
                target_root: target.path().into()
            },
            &Uuid::new_v4().to_string(),
        )
        .unwrap_err()
        .to_string()
        .contains("outside this immutable recording")
    );

    // A warmed index cannot authenticate bytes modified after the recording seal.
    let path = state
        .case_source
        .as_ref()
        .unwrap()
        .join("dependencies.jsonl");
    let mut bytes = fs::read(&path).unwrap();
    let position = bytes
        .windows(b"refresh".len())
        .position(|w| w == b"refresh")
        .unwrap();
    bytes[position] = b'R';
    fs::write(path, bytes).unwrap();
    assert!(
        dependency_attribution_source_information(
            super::super::RewriteContext {
                target_root: target.path().into()
            },
            &source.exchanges.keys().next().unwrap().to_string(),
        )
        .is_err(),
        "a warmed lookup must reject modified sealed Source bytes"
    );
}

fn proposal(
    source: &source::SourceSnapshot,
    policy: &crate::policy::CompiledPolicy,
) -> ProposedAttribution {
    let epoch = *source.epochs.first().unwrap();
    ProposedAttribution {
        claim_ids: BTreeSet::new(),
        source_exchange_ids: BTreeSet::new(),
        source_task: "refresh".into(),
        owner: DependencyOwner::Process {
            process_epoch: epoch,
            source_task: "refresh".into(),
            invocation: None,
        },
        proof: AttributionProof {
            source_revision:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            source_locations: vec!["src/refresh.rs:run".into()],
            call_chain:
                "startup starts refresh task, whose GET and Redis GET branches complete one iteration"
                    .into(),
            exclusive_scope: "Only refresh invokes these exact selectors".into(),
        },
        impact: super::super::verification_obligations::VerificationImpact::Classification,
        obligation_scope: VerificationScope::Process {
            source_task: "refresh".into(),
            process_epoch: epoch,
        },
        missing_evidence: None,
        rule_binding: AttributionRuleBinding {
            policy_fingerprint: policy.fingerprints.full.clone(),
            rule_ids: policy
                .native
                .iter()
                .map(|rule| rule.rule.id.clone())
                .collect(),
        },
    }
}

#[tokio::test]
async fn task_proof_binds_complete_cross_protocol_scope_and_keeps_original_inventory() {
    let (target, state) = fixture(1).await;
    let original = source::load(&state).unwrap();
    let bytes = fs::read(
        state
            .case_source
            .as_ref()
            .unwrap()
            .join("dependencies.jsonl"),
    )
    .unwrap();
    let policy = rules::load(target.path()).unwrap();
    let projected = crate::config::native_policy::project_source_policy(&policy.native).unwrap();
    assert_eq!(projected.process_dependency_tasks.len(), 2);
    assert!(
        projected
            .process_dependency_tasks
            .values()
            .all(|task| task == "refresh")
    );
    let mut partial = proposal(&original, &policy);
    partial.rule_binding.rule_ids.pop_first();
    assert!(rules::bind(target.path(), &state, &original, &mut partial).is_err());
    let mut selected = proposal(&original, &policy);
    rules::bind(target.path(), &state, &original, &mut selected).unwrap();
    assert_eq!(selected.source_exchange_ids.len(), 2);
    selected.source_exchange_ids.pop_first();
    assert!(rules::bind(target.path(), &state, &original, &mut selected).is_err());
    let context = dependency_attribution_context(super::super::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(context.unattributed_exchange_ids.len(), 2);
    assert!(context.task_groups.contains_key("refresh"));
    let input = AttributionSubmission {
        schema: SCHEMA.into(),
        assignment_id: context.assignment_id,
        expected_revision: context.revision,
        recording_run_id: context.recording_run_id,
        source_revision: context.source_revision,
        source_inventory_id: context.source_inventory_id,
        decisions: vec![proposal(&original, &policy)],
        investigation_resolutions: vec![],
        unresolved_claim_ids: BTreeSet::new(),
        claim_rejections: vec![],
    };
    let path = target.path().join(".traffic-e2e/local/attribution.json");
    fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    let options = || AttributionCommandOptions {
        target_root: target.path().into(),
        file: path.clone(),
    };
    let result = apply_dependency_attribution(options()).unwrap();
    assert_eq!(result["accepted_apis"], json!([]));
    assert_eq!(
        dependency_attribution_overlay(target.path(), &state.recording_run_id)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        fs::read(
            state
                .case_source
                .as_ref()
                .unwrap()
                .join("dependencies.jsonl")
        )
        .unwrap(),
        bytes
    );
    let mut stored = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(batch_pending(&stored)); // A real process execution still owns this debt.
    assert_eq!(stored.dependency_review.obligations.len(), 1);
    let decisions = serde_json::to_value(&stored.dependency_review.decisions).unwrap();
    stored.dependency_review.case_defaults_identity = None;
    super::analysis::refresh_inventory(target.path(), &mut stored).unwrap();
    assert_eq!(
        serde_json::to_value(&stored.dependency_review.decisions).unwrap(),
        decisions,
        "admission cache rebuilding preserves current authored ownership proofs"
    );
    assert!(
        stored
            .dependency_review
            .unresolved_source_exchange_ids
            .is_empty()
    );
    assert!(required_action(target.path(), &stored).is_none());
    assert!(
        apply_dependency_attribution(options())
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
    fs::write(
        target.path().join(".traffic-e2e/policy.yaml"),
        "format: traffic-policy/v3\nrules: []\n",
    )
    .unwrap();
    let expired = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(expired.dependency_review.decisions.is_empty());
    assert_eq!(expired.dependency_review.decision_history.len(), 2);
    assert!(required_action(target.path(), &expired).is_some());
}

#[tokio::test]
async fn authenticated_investigation_pages_have_executable_revision_fenced_continuations() {
    let (target, mut state) = fixture(21).await;
    let original = source::load(&state).unwrap();
    state.dependency_review.revision = 4;
    state.dependency_review.investigations.insert("investigation".into(),TargetInvestigation {
        id:"investigation".into(),kind:"target_request_investigation".into(),api:"/api".into(),method_api:"GET /api".into(),
        recording_run_id:state.recording_run_id.clone(),source_revision:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),source_inventory_id:original.identity,
        attempt:1,session_id:"actual-session".into(),report_sha256:"report".into(),target_observations:BTreeMap::from([("protected-target".into(),
            json!({"case_id":Uuid::new_v4(),"resource":{"protocol":"http","endpoint":"worker.test:80"},"operation":"GET"}))]),
        candidate_discovery:BTreeMap::new(),reason:"No current-case request matched".into(),status:ClaimStatus::Pending,resolution:None,
    });
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let context = || super::super::RewriteContext {
        target_root: target.path().into(),
    };
    let page =
        dependency_attribution_candidates(context(), "investigation", "protected-target", 4, 0)
            .unwrap();
    assert_eq!(page["total"], 21);
    assert_eq!(page["returned"], 20);
    assert_eq!(page["exact_match_evaluated"], false);
    assert!(
        page["next_command"]["argv"]
            .as_array()
            .unwrap()
            .contains(&json!("candidates"))
    );
    let last =
        dependency_attribution_candidates(context(), "investigation", "protected-target", 4, 20)
            .unwrap();
    assert_eq!(last["returned"], 1);
    assert!(last["next_command"].is_null());
    assert!(
        dependency_attribution_candidates(context(), "investigation", "protected-target", 3, 20)
            .is_err()
    );
    assert!(
        dependency_attribution_candidates(context(), "investigation", "unobserved-target", 4, 0)
            .is_err()
    );
}

async fn ready_batch_fixture() -> (tempfile::TempDir, RewriteState, String) {
    use crate::rewrite::{
        model::{RewriteApiProgress, RewriteApiStatus, RewritePhase},
        verification_obligations::{ScopeObligation, VerificationRequirement},
    };
    let target = crate::rewrite::worker::tests::configured_target();
    fs::write(target.path().join(".traffic-e2e/policy.yaml"), POLICY).unwrap();
    let mut config = crate::AppConfig::default();
    config
        .process_dependency_tasks
        .insert("source-refresh".into(), "refresh".into());
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    recorder
        .append_global_dependency(
            &http("/refresh"),
            "background_rule",
            "runtime",
            "source-refresh",
        )
        .await
        .unwrap();
    let case = crate::recorder::CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".into(),
        uri_group: None,
    };
    for (name, value) in [
        ("admission.json", json!({"fixture":true})),
        (
            "request.json",
            json!({"method":"GET","uri":"/api","timestamp":"2026-10-31T00:00:00Z","body":capture_body(b"{}",16)}),
        ),
        (
            "expected-response.json",
            json!({"status":200,"body":capture_body(b"{}",16)}),
        ),
    ] {
        recorder.write_case_json(&case, name, &value).await.unwrap();
    }
    recorder.publish_case(&case).await.unwrap();
    recorder.finish_run().await.unwrap();
    let mut state = crate::rewrite::test_support::test_state();
    state.case_source = Some(recorder.run_dir().as_ref().clone());
    state.recording_run_id = recorder
        .run_dir()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .into();
    state.source_revision =
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    state.phase = RewritePhase::SliceComplete;
    state.e2e_current = true;
    state.api_inventory = vec![RewriteApiProgress {
        api: "GET /api".into(),
        source_route: Some("/api".into()),
        status: RewriteApiStatus::Complete,
        attempts: 1,
        e2e_current: true,
        verified_target_fingerprint: None,
    }];
    let source = source::load(&state).unwrap();
    let epoch = *source.epochs.first().unwrap();
    state.dependency_review.recording_run_id = Some(state.recording_run_id.clone());
    state.dependency_review.source_inventory_id = Some(source.identity);
    state
        .dependency_review
        .required_method_apis
        .insert("GET /api".into());
    let id = "process-debt".to_string();
    state.dependency_review.obligations.insert(
        id.clone(),
        ScopeObligation {
            id: id.clone(),
            scope: VerificationScope::Process {
                source_task: "refresh".into(),
                process_epoch: epoch,
            },
            requirement: VerificationRequirement::Replay,
            source_revision: state.source_revision.clone().unwrap(),
            baseline_recording_run_id: state.recording_run_id.clone(),
            proof_id: "source-proof".into(),
            reason: "the actual process task still requires execution".into(),
            completed_by_session: None,
            retired_reason: None,
        },
    );
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (target, state, id)
}

#[tokio::test]
async fn process_debt_schedules_one_real_batch_without_accepting_focused_api_results() {
    let (target, state, id) = ready_batch_fixture().await;
    assert!(matches!(
        batch::required_action(target.path(), &state),
        Some(crate::rewrite::RewriteAction::AdvanceRequired {
            kind: crate::rewrite::RewriteAdvanceKind::BatchReplay,
            ..
        })
    ));
    assert!(batch_pending(&state));
    let result = verify_dependency_obligation(
        crate::rewrite::RewriteContext {
            target_root: target.path().into(),
        },
        &id,
    );
    assert!(result.is_err()); // No actual complete-round state exists.
    let stored = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(stored.dependency_review.obligations[&id].pending());
    assert!(stored.dependency_review.batch_receipt.is_none());
}

#[tokio::test]
async fn a_scoped_new_source_run_cannot_erase_another_required_workflow_method() {
    let (target, mut state, _) = ready_batch_fixture().await;
    state
        .dependency_review
        .required_method_apis
        .insert("POST /other".into());
    let action = batch::required_action(target.path(), &state).unwrap();
    let value = serde_json::to_value(action).unwrap();
    assert_eq!(value["kind"], "input_required");
    assert!(value.to_string().contains("POST /other"));
    assert!(!batch_verification::current(target.path(), &state).unwrap());
}

#[tokio::test]
async fn explicit_only_can_exclude_a_previous_workflow_method_from_final_scope() {
    let (target, mut state, _) = ready_batch_fixture().await;
    state
        .dependency_review
        .required_method_apis
        .insert("POST /other".into());
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "only: [/api]\n",
    )
    .unwrap();
    assert_eq!(
        workflow_verification::required_scope_methods(target.path(), &state).unwrap(),
        BTreeSet::from(["GET /api".into()])
    );
    assert!(matches!(
        batch::required_action(target.path(), &state),
        Some(crate::rewrite::RewriteAction::AdvanceRequired {
            kind: crate::rewrite::RewriteAdvanceKind::BatchReplay,
            ..
        })
    ));
    assert!(
        state
            .dependency_review
            .required_method_apis
            .contains("POST /other")
    );
    assert!(!batch_verification::current(target.path(), &state).unwrap());
}

#[path = "tests/ownership.rs"]
mod ownership;
