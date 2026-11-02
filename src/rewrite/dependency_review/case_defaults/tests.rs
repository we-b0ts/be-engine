use super::*;
use crate::recorder::{CaseContext, RecorderEvent, RedisPubSubPushEvent, capture_body};
use crate::rewrite::{RewriteContext, model::RewriteState, store::RewriteStore};
use crate::{AppConfig, AppState};
use serde_json::json;

async fn historical(inside_window: bool) -> (tempfile::TempDir, RewriteState, Uuid, Vec<u8>) {
    let target = crate::rewrite::worker::tests::configured_target();
    let mut config = AppConfig::default();
    config.recording.output_dir = target.path().join(".traffic-e2e/local/recordings");
    config.tls.ca_cert_path = target.path().join("ca.pem");
    config.tls.ca_key_path = target.path().join("ca-key.pem");
    let app = AppState::new(config).await.unwrap();
    app.close_bootstrap("ready").await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "responses".into(),
        uri_group: None,
    };
    let guard = app.try_reserve_active_case(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    let now = Utc::now();
    app.recorder()
        .write_case_json(
            &case,
            "request.json",
            &json!({
                "timestamp":now-chrono::Duration::seconds(10),"method":"POST","uri":"/responses"
            }),
        )
        .await
        .unwrap();
    let channel = b"callback:channel:123";
    let raw = crate::redis::encode_array(&[b"message", channel, b"business input"]);
    for _ in 0..2 {
        let event = RecorderEvent::RedisPubSubPush(RedisPubSubPushEvent {
            timestamp: Utc::now(),
            target_host: "cache.test".into(),
            target_port: 6379,
            database: 0,
            username: None,
            connection_id: Uuid::from_u128(100),
            subscription_sequence: 1,
            rpc_request: None,
            response: capture_body(&raw, 1024),
            duration_ms: 1,
            replay_safe: true,
        });
        // Exercise the old Recorder's actual path, which retained the observed
        // Case but explicitly suppressed ordinary notification admission.
        let targets = app.inner.active_cases.unattributed_observation_targets();
        app.record_event_for_targets(event, targets);
    }
    let end = if inside_window {
        Utc::now()
    } else {
        now - chrono::Duration::seconds(1)
    };
    app.recorder()
        .write_case_json(
            &case,
            "expected-response.json",
            &json!({
                "timestamp":end,"status":200,"body":{"encoding":"utf8","data":""}
            }),
        )
        .await
        .unwrap();
    app.recorder().publish_case(&case).await.unwrap();
    drop(guard);
    app.recorder().finish_run().await.unwrap();
    let mut state = crate::rewrite::test_support::test_state();
    state.case_source = Some(app.recorder().run_dir.as_ref().clone());
    state.recording_run_id = app
        .recorder()
        .run_dir
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .into();
    state.source_revision = Some(format!("sha256:{}", "a".repeat(64)));
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let bytes = fs::read(app.recorder().run_dir.join("dependencies.jsonl")).unwrap();
    (target, state, case.id, bytes)
}

#[tokio::test]
async fn historical_case_inputs_bypass_analysis_and_freeze_as_finite_case_evidence() {
    let (target, mut state, case, original) = historical(true).await;
    let defaults = load(state.case_source.as_ref().unwrap(), Some(target.path())).unwrap();
    assert_eq!(defaults.len(), 2);
    assert!(defaults.values().all(|owner| matches!(owner,
        DependencyOwner::Case { origin_case_id, .. } if *origin_case_id==case)));
    assert!(super::super::analysis::required_action(target.path(), &state).is_none());
    super::super::analysis::refresh_inventory(target.path(), &mut state).unwrap();
    assert!(
        state
            .dependency_review
            .unresolved_source_exchange_ids
            .is_empty()
    );
    assert!(state.dependency_review.decisions.is_empty());
    assert!(state.dependency_review.receipts.is_empty());
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let context = super::super::dependency_attribution_context(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(context.unattributed_exchange_ids.is_empty());
    let (owners, identity) = super::super::snapshot::frozen(
        Some(target.path()),
        state.case_source.as_ref().unwrap(),
        &state.recording_run_id,
    )
    .unwrap();
    assert_eq!(owners, defaults);
    assert_eq!(
        identity,
        super::super::snapshot::identity(target.path(), &state.recording_run_id).unwrap()
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
        original
    );
    assert!(
        !state.e2e_current,
        "scope admission never certifies Target delivery"
    );
}

#[tokio::test]
async fn an_observed_case_after_its_primary_window_still_requires_analysis() {
    let (target, state, _, _) = historical(false).await;
    assert!(
        load(state.case_source.as_ref().unwrap(), Some(target.path()))
            .unwrap()
            .is_empty()
    );
    assert!(super::super::analysis::required_action(target.path(), &state).is_some());
}

#[tokio::test]
async fn existing_process_selector_takes_priority_over_historical_case_default() {
    let (target, state, _, _) = historical(true).await;
    fs::write(
        target.path().join(".traffic-e2e/policy.yaml"),
        r#"format: traffic-policy/v3
process_dependencies:
  tasks:
    callback_reader:
      requests:
        - redis:
            resource: {protocol: redis, endpoint: 'cache.test:6379', database: 0}
            operation: SUBSCRIBE
            arguments: ['callback:channel:123']
"#,
    )
    .unwrap();
    assert!(
        load(state.case_source.as_ref().unwrap(), Some(target.path()))
            .unwrap()
            .is_empty()
    );
    assert!(super::super::analysis::required_action(target.path(), &state).is_some());
}
