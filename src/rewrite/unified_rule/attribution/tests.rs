//! Public Source-only planning works before any Replay or implementation lease.
use super::*;
use crate::recorder::{CaseContext, HttpExchangeEvent, Recorder, RecorderEvent, capture_body};
use crate::rewrite::{apply_rewrite_rule, dependency_attribution_context};

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn fixture() -> (tempfile::TempDir, RewriteState, PathBuf) {
    let target = crate::rewrite::worker::tests::configured_target();
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    recorder
        .append_global_dependency(
            &RecorderEvent::HttpExchange(HttpExchangeEvent {
                outcome: crate::DependencyExchangeOutcome::Response,
                id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                request_started_at: chrono::Utc::now(),
                client_addr: None,
                scheme: "http".into(),
                method: "GET".into(),
                uri: "/refresh".into(),
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
            }),
            "outside_admission",
            "runtime",
            "",
        )
        .await
        .unwrap();
    let case = CaseContext {
        id: uuid::Uuid::new_v4(),
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
    state.case_source = Some(recorder.run_dir.as_ref().clone());
    state.recording_run_id = recorder
        .run_dir
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .into();
    state.source_revision = Some(REVISION.into());
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let proposal = target.path().join(".traffic-e2e/local/owner-rule.yaml");
    fs::write(&proposal,format!("format: traffic-policy/v3\nsource_revision: {REVISION}\nprocess_dependencies:\n  tasks:\n    refresh:\n      requests:\n        - http: {{host: worker.test, method: GET, path: /refresh}}\n          proof: {{source: 'source.py:refresh', fact: 'The independent refresh loop makes this exact request'}}\n")).unwrap();
    (target, state, proposal)
}

fn token(root: &Path) -> String {
    dependency_attribution_context(RewriteContext {
        target_root: root.into(),
    })
    .unwrap()
    .rule_planning["evidence_id"]
        .as_str()
        .unwrap()
        .into()
}

#[tokio::test]
async fn source_only_owner_rule_can_plan_and_apply_without_a_replay_or_api_worker() {
    let (target, state, file) = fixture().await;
    assert!(state.attempts.is_empty() && state.worker_bindings.is_empty());
    let source = state.case_source.as_ref().unwrap();
    let immutable = fs::read(source.join("dependencies.jsonl")).unwrap();
    let plan = plan_rewrite_unified_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        RewriteUnifiedRulePlanOptions {
            file,
            evidence_id: token(target.path()),
        },
    )
    .unwrap();
    assert_eq!(
        plan.traffic_e2e_report["evidence_scope"]["scope"],
        "attribution"
    );
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["independent_target_validations"],
        0
    );
    assert_eq!(
        plan.traffic_e2e_report["checks"]["immutable_attempt_and_witnesses"],
        false
    );
    assert!(
        plan.traffic_e2e_report["preflight"]["source_validations"]
            .as_u64()
            .unwrap()
            > 0
    );
    let pending = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(matches!(
        crate::rewrite::rule_plans::required_action(target.path(), &pending),
        Some(crate::rewrite::RewriteAction::PlanApplyRequired { .. })
    ));
    let applied = apply_rewrite_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        &plan.plan_id,
    )
    .unwrap();
    assert_eq!(applied.traffic_e2e_report["applied"], true);
    assert_eq!(applied.traffic_e2e_report["verified"], false);
    let after = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(after.attempts.is_empty() && after.worker_bindings.is_empty());
    assert!(after.dependency_review.decisions.is_empty());
    assert!(matches!(
        crate::rewrite::dependency_review::required_action(target.path(), &after),
        Some(crate::rewrite::RewriteAction::DependencyAttributionRequired { .. })
    ));
    assert_eq!(
        fs::read(source.join("dependencies.jsonl")).unwrap(),
        immutable
    );
}

#[tokio::test]
async fn source_owner_planning_rejects_stale_assignment_and_value_permissions() {
    let (target, mut state, file) = fixture().await;
    let old = token(target.path());
    state.dependency_review.revision += 1;
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let result = plan_rewrite_unified_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        RewriteUnifiedRulePlanOptions {
            file: file.clone(),
            evidence_id: old,
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("assignment or inventory changed")
    );
    fs::write(
        &file,
        "format: traffic-policy/v3\njson:\n  fields:\n    /values: {kind: unordered}\n",
    )
    .unwrap();
    let result = plan_rewrite_unified_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        RewriteUnifiedRulePlanOptions {
            file: file.clone(),
            evidence_id: token(target.path()),
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("cannot authorize value")
    );
    fs::write(&file,format!("format: traffic-policy/v3\nsource_revision: {REVISION}\nprocess_dependencies:\n  tasks:\n    cache_seed:\n      requests:\n        - redis: {{operation: GET, ports: [6379], keys: [{{kind: exact, value: seed}}], initial_load_timeout_ms: 100}}\n          proof: {{source: 'source.py:seed', fact: 'Source initializes a local snapshot'}}\n")).unwrap();
    let result = plan_rewrite_unified_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        RewriteUnifiedRulePlanOptions {
            file,
            evidence_id: token(target.path()),
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("ownership or async_api")
    );
    assert_eq!(
        fs::read_to_string(target.path().join(".traffic-e2e/policy.yaml")).unwrap(),
        crate::config::native_policy::empty_policy().unwrap()
    );
}

#[tokio::test]
async fn source_owner_plan_keeps_policy_compare_and_swap_without_target_evidence() {
    let (target, _, file) = fixture().await;
    let plan = plan_rewrite_unified_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        RewriteUnifiedRulePlanOptions {
            file,
            evidence_id: token(target.path()),
        },
    )
    .unwrap();
    let policy = target.path().join(".traffic-e2e/policy.yaml");
    let other = "format: traffic-policy/v3\n# another reviewed writer\n";
    fs::write(&policy, other).unwrap();
    assert!(
        apply_rewrite_rule(
            RewriteContext {
                target_root: target.path().into()
            },
            &plan.plan_id
        )
        .is_err()
    );
    assert_eq!(fs::read_to_string(policy).unwrap(), other);
}

#[tokio::test]
async fn historical_policy_header_does_not_rebind_a_new_owner_to_the_old_source() {
    let (target, _, file) = fixture().await;
    let older = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let policy = target.path().join(".traffic-e2e/policy.yaml");
    fs::write(
        &policy,
        format!("format: traffic-policy/v3\nsource_revision: {older}\nrules: []\n"),
    )
    .unwrap();
    let plan = plan_rewrite_unified_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        RewriteUnifiedRulePlanOptions {
            file,
            evidence_id: token(target.path()),
        },
    )
    .unwrap();
    apply_rewrite_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        &plan.plan_id,
    )
    .unwrap();
    let document = parse_policy(&fs::read_to_string(policy).unwrap()).unwrap();
    assert_eq!(document.source_revision.as_deref(), Some(older));
    let compiled = compile_policy(&document).unwrap();
    assert!(
        compiled
            .native
            .iter()
            .all(|rule| matches!(&rule.rule.effect,
        NativeEffect::ProcessOwned(effect) if effect.source_revision == REVISION))
    );
}

#[tokio::test]
async fn async_only_owner_plan_rechecks_sealed_source_bytes_at_apply() {
    let (target, state, file) = fixture().await;
    fs::write(&file, format!("format: traffic-policy/v3\nsource_revision: {REVISION}\nasync_api:\n  'GET /api':\n    end:\n      - http: {{method: GET, endpoint: 'worker.test:80', path: /refresh}}\n")).unwrap();
    let plan = plan_rewrite_unified_rule(
        RewriteContext {
            target_root: target.path().into(),
        },
        RewriteUnifiedRulePlanOptions {
            file,
            evidence_id: token(target.path()),
        },
    )
    .unwrap();
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["source_scope"],
        Value::Null
    );
    let central = state
        .case_source
        .as_ref()
        .unwrap()
        .join("dependencies.jsonl");
    let mut changed = fs::read(&central).unwrap();
    changed.push(b'\n');
    fs::write(central, changed).unwrap();
    assert!(
        apply_rewrite_rule(
            RewriteContext {
                target_root: target.path().into()
            },
            &plan.plan_id
        )
        .is_err()
    );
}
