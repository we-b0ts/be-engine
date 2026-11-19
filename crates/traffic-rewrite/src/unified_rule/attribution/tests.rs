//! Public Source-only planning works before any Replay or implementation lease.
use super::*;
use crate::dependency_index::recording::dependency_path;
use crate::policy::{NativeEffect, compile_policy, parse_policy};
use crate::protocols::recording::events::{HttpExchangeEvent, RecorderEvent};
use crate::recorder::{CaseContext, Recorder, capture_body};
use crate::{apply_rewrite_rule, dependency_attribution_context};
use traffic_rewrite_rules::rewrite::unified_rule::manifest::ArtifactMethods;

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn fixture() -> (tempfile::TempDir, RewriteState, PathBuf) {
    fixture_with_global("outside_admission", "runtime").await
}

async fn fixture_with_global(
    reason: &str,
    phase: &str,
) -> (tempfile::TempDir, RewriteState, PathBuf) {
    let target = crate::worker::tests::configured_target();
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
                upstream_addr: None,
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
            reason,
            phase,
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
    let mut state = crate::workflow_test_support::test_state();
    state.case_source = Some(recorder.run_dir().as_ref().clone());
    state.recording_run_id = recorder
        .run_dir()
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
    let immutable = fs::read(dependency_path(source)).unwrap();
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
        crate::rule_plans::required_action(target.path(), &pending),
        Some(crate::RewriteAction::PlanApplyRequired { .. })
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
        crate::dependency_review::required_action(target.path(), &after),
        Some(crate::RewriteAction::DependencyAttributionRequired { .. })
    ));
    assert_eq!(fs::read(dependency_path(source)).unwrap(), immutable);
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
        NativeEffect::ProcessOwned(effect) if effect.source_revision.is_empty()))
    );
    assert!(
        plan.traffic_e2e_report["preflight"]["source_validations"]
            .as_u64()
            .unwrap()
            > 0
    );
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(Identity::current(&state).unwrap().source_revision, REVISION);
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
    let central = dependency_path(state.case_source.as_ref().unwrap());
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

#[tokio::test]
async fn nested_async_rule_plan_publishes_policy_consumed_by_recording() {
    let (target, state, file) = fixture().await;
    let source = state.case_source.as_ref().unwrap();
    let frozen = [
        dependency_path(source),
        source.join("dependency-manifest.json"),
    ]
    .into_iter()
    .map(|path| {
        let bytes = fs::read(&path).unwrap();
        (path, bytes)
    })
    .collect::<Vec<_>>();
    fs::write(
        &file,
        format!("format: traffic-policy/v3\nsource_revision: {REVISION}\nrecording:\n  async_api:\n    'GET /api':\n      - when_response: {{'/status': queued}}\n        end:\n          - http: {{method: GET, endpoint: 'worker.test:80', path: /queued}}\n      - when: {{}}\n        end:\n          - http: {{method: GET, endpoint: 'worker.test:80', path: /refresh}}\n"),
    )
    .unwrap();
    let context = || RewriteContext {
        target_root: target.path().into(),
    };
    let plan = plan_rewrite_unified_rule(
        context(),
        RewriteUnifiedRulePlanOptions {
            file,
            evidence_id: token(target.path()),
        },
    )
    .unwrap();
    let applied = apply_rewrite_rule(context(), &plan.plan_id).unwrap();
    assert_eq!(applied.traffic_e2e_report["applied"], true);
    assert_eq!(applied.traffic_e2e_report["verified"], false);
    let path = target.path().join(".traffic-e2e/policy.yaml");
    let published = fs::read_to_string(&path).unwrap();
    let raw: serde_yaml::Value = serde_yaml::from_str(&published).unwrap();
    assert!(raw.get("async_api").is_none());
    assert!(raw["recording"].get("async_api").is_some());
    assert!(raw["recording"].get("case_paths").is_none());
    let compiled = crate::policy::parse_and_compile_policy(&published).unwrap();
    assert!(
        compiled.native.is_empty(),
        "async-only publication grants no HTTP acquisition"
    );
    let recording = crate::config::SourceTrafficPolicyConfig::load(&path).unwrap();
    assert_eq!(recording.async_api, compiled.async_api);
    let mut app = crate::AppConfig::default();
    recording.apply_to(&mut app).unwrap();
    assert_eq!(app.async_api, compiled.async_api);
    assert!(app.http_gateway.case_path_patterns.is_empty());
    let scope = crate::recorder::async_api::AsyncScope::for_primary(
        &app.async_api,
        &hyper::Method::GET,
        &"/api".parse().unwrap(),
        b"{}",
    )
    .unwrap();
    assert!(scope.scenario_index().is_none());
    assert!(scope.select_response(Some(&json!({}))).0);
    assert_eq!(scope.scenario_index(), Some(1));
    let mut ledger = crate::dependency_index::RecordStream::open(&dependency_path(source)).unwrap();
    let (_, bytes) = ledger.next().unwrap().unwrap();
    let event: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert!(ledger.next().unwrap().is_none());
    assert_eq!(
        scope.observe_recorded(&event).unwrap().unwrap().end_reason,
        crate::recorder::async_api::AsyncEndReason::Resource
    );
    assert!(scope.all_ends_matched());
    for (path, bytes) in frozen {
        assert_eq!(fs::read(&path).unwrap(), bytes, "{}", path.display());
    }
}

#[tokio::test]
async fn pending_owner_plan_status_does_not_hash_frozen_evidence() {
    use crate::unified_rule::manifest::{
        Artifact, artifact_capture_stats, reset_artifact_capture_stats,
    };
    use crate::{RewriteAction, status_rewrite};
    use std::collections::BTreeMap;
    use std::io::Write as _;

    // Startup ownership keeps the independent attribution gate from returning
    // before the pending-plan scheduler checks. The original Source stays sealed.
    let (target, initial, proposal) = fixture_with_global("bootstrap_window", "bootstrap").await;
    fs::write(&proposal, format!("format: traffic-policy/v3\nsource_revision: {REVISION}\nasync_api:\n  'GET /api':\n    end:\n      - http: {{method: GET, endpoint: 'worker.test:80', path: /refresh}}\n")).unwrap();
    let context = || RewriteContext {
        target_root: target.path().into(),
    };
    let plan = plan_rewrite_unified_rule(
        context(),
        RewriteUnifiedRulePlanOptions {
            file: proposal,
            evidence_id: token(target.path()),
        },
    )
    .unwrap();

    // A large additional frozen regular artifact exercises the same freshness
    // hashing as large Source evidence without generating or copying real traffic.
    let witness = target
        .path()
        .join(".traffic-e2e/local/source-proof-witness.bin");
    let mut output = fs::File::create(&witness).unwrap();
    let block = vec![b'x'; 1024 * 1024];
    for _ in 0..32 {
        output.write_all(&block).unwrap();
    }
    drop(output);
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = store.load().unwrap().unwrap();
    let record = state.rule_plan.as_mut().unwrap().unified.as_mut().unwrap();
    record.artifacts.push(Artifact::capture(&witness).unwrap());
    store.save(&state).unwrap();

    let assert_plan = |action: &RewriteAction, operation: &str| {
        let RewriteAction::PlanApplyRequired { command, .. } = action else {
            panic!("expected pending plan, got {action:?}");
        };
        assert!(command.argv.contains(&plan.plan_id));
        assert!(command.argv.iter().any(|part| part == operation));
    };
    reset_artifact_capture_stats();
    for _ in 0..3 {
        assert_plan(
            &crate::rule_plans::required_action(target.path(), &state).unwrap(),
            "apply",
        );
    }
    assert!(artifact_capture_stats().is_empty());

    let state_path = crate::internal_runtime::root(target.path()).join("rewrite/state.json");
    let policy_path = target.path().join(".traffic-e2e/policy.yaml");
    let source = initial.case_source.as_ref().unwrap();
    let frozen = [&state_path, &policy_path, &dependency_path(source)]
        .into_iter()
        .map(|path| (path.to_owned(), fs::read(path).unwrap()))
        .collect::<BTreeMap<_, _>>();
    reset_artifact_capture_stats();
    let mut first = None;
    for _ in 0..2 {
        let status = status_rewrite(context()).unwrap();
        assert_plan(&status.action, "apply");
        assert_eq!(status.pending, 1);
        assert!(!status.terminal_allowed);
        let value = serde_json::to_value(&status).unwrap();
        if let Some(first) = &first {
            assert_eq!(&value, first);
        } else {
            first = Some(value);
        }
        assert!(artifact_capture_stats().is_empty());
        for (path, bytes) in &frozen {
            assert_eq!(&fs::read(path).unwrap(), bytes, "{path:?}");
        }
    }
    // Read-only status does not authenticate the witness. Apply still rejects
    // a same-length mutation before publishing policy or a durable intent.
    fs::OpenOptions::new()
        .write(true)
        .open(&witness)
        .unwrap()
        .write_all(b"y")
        .unwrap();
    assert_plan(&status_rewrite(context()).unwrap().action, "apply");
    assert!(artifact_capture_stats().is_empty());
    let error = apply_rewrite_rule(context(), &plan.plan_id).unwrap_err();
    assert!(format!("{error:#}").contains("rule evidence changed after planning"));
    for (path, bytes) in &frozen {
        assert_eq!(&fs::read(path).unwrap(), bytes, "{path:?}");
    }
    crate::recover_rewrite_rule_plan(context(), &plan.plan_id).unwrap();
}
