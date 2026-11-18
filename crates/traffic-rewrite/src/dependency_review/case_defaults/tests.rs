use super::load;
use crate::dependency::attribution::DependencyOwner;
use crate::protocols::recording::events::{RecorderEvent, RedisPubSubPushEvent};
use crate::recorder::{CaseContext, capture_body};
use crate::{AppConfig, AppState};
use crate::{RewriteContext, model::RewriteState, store::RewriteStore};
use chrono::Utc;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use uuid::Uuid;

async fn historical(inside_window: bool) -> (tempfile::TempDir, RewriteState, Uuid, Vec<u8>) {
    let target = crate::worker::tests::configured_target();
    let mut config = AppConfig::default();
    config.recording.output_dir = target.path().join(".traffic-e2e/local/recordings");
    config.tls.ca_cert_path = target.path().join("ca.pem");
    config.tls.ca_key_path = target.path().join("ca-key.pem");
    let app = AppState::new(config).await.unwrap();
    crate::test_support::close_bootstrap(&app, "ready")
        .await
        .unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "responses".into(),
        uri_group: None,
    };
    let guard = crate::test_support::reserve_active_case(&app, case.clone()).unwrap();
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
    let raw = traffic_protocol_redis::encode_array(&[b"message", channel, b"business input"]);
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
        crate::test_support::record_unattributed_observation(&app, event);
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
    let mut state = crate::workflow_test_support::test_state();
    state.case_source = Some(app.recorder().run_dir().as_ref().clone());
    state.recording_run_id = app
        .recorder()
        .run_dir()
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
    let bytes = fs::read(app.recorder().run_dir().join("dependencies.jsonl")).unwrap();
    (target, state, case.id, bytes)
}

#[tokio::test]
async fn unused_occurrence_projection_preserves_input_routes_and_notification_identities() {
    let (_target, state, case, _) = historical(true).await;
    let full = super::super::source::load(&state).unwrap();
    let projected = super::super::source::occurrences::load(&state).unwrap();
    assert_eq!(projected.apis, full.apis);
    assert_eq!(projected.apis[&case], "POST /responses");
    assert_eq!(projected.case_defaults, full.case_defaults);
    let notifications = full
        .exchanges
        .iter()
        .filter(|(_, event)| event.selector["event_type"] == "redis_pub_sub_push")
        .map(|(id, _)| {
            json!({"case_id":case.to_string(),"command":"PUBSUB_PUSH","source_exchange_id":id})
        })
        .collect::<Vec<_>>();
    assert_eq!(notifications.len(), 2);
    let report = json!({"redis":{"unused_case":notifications}});
    let selected = BTreeSet::from([case.to_string()]);
    assert_eq!(
        projected.unused(&report, &selected).unwrap(),
        super::super::source::unused(&full, &report, &selected).unwrap()
    );
    let mut missing = report.clone();
    missing["redis"]["unused_case"][0]
        .as_object_mut()
        .unwrap()
        .remove("source_exchange_id");
    assert!(projected.unused(&missing, &selected).is_err());
    let mut subset = report.clone();
    subset["redis"]["unused_case"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    let scoped =
        super::super::source::occurrences::for_api(&state, "POST /responses", &subset).unwrap();
    assert_eq!(scoped.exchanges.len(), 1);
    assert_eq!(
        scoped.unused(&subset, &selected).unwrap(),
        super::super::source::unused(&full, &subset, &selected).unwrap()
    );
    let traversals = super::super::source::occurrences::ORIGINAL_TRAVERSALS.get();
    let warm =
        super::super::source::occurrences::for_api(&state, "POST /responses", &subset).unwrap();
    assert_eq!(warm.case_defaults, full.case_defaults);
    assert_eq!(
        super::super::source::occurrences::ORIGINAL_TRAVERSALS.get(),
        traversals
    );
    let complete =
        super::super::source::occurrences::for_api(&state, "POST /responses", &report).unwrap();
    assert_eq!(complete.exchanges.len(), 2);
    assert_eq!(
        super::super::source::occurrences::ORIGINAL_TRAVERSALS.get(),
        traversals + 1,
        "another unused inventory must not reuse a narrower cache"
    );
    let path = full.inputs[&case].join("request.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b' ');
    fs::write(path, bytes).unwrap();
    assert!(super::super::source::occurrences::load(&state).is_err());
    assert!(
        super::super::source::occurrences::for_api(&state, "POST /responses", &subset).is_err()
    );
}

#[tokio::test]
async fn published_occurrence_diagnosis_uses_no_original_scan_and_missing_fields_backfill() {
    use super::super::source::occurrences::{ORIGINAL_TRAVERSALS, for_diagnosis};

    let (_target, state, case, _) = historical(true).await;
    let full = super::super::source::load(&state).unwrap();
    let (id, event) = full
        .exchanges
        .iter()
        .find(|(_, event)| event.selector["event_type"] == "redis_pub_sub_push")
        .unwrap();
    let mut report = json!({"finalized":true,"unused_source_inventory_id":full.identity,
    "redis":{"unused_case":[{
        "case_id":case,"command":"PUBSUB_PUSH","source_exchange_id":id,
        "source_occurrence":{"source_exchange_id":id,"captured_owner":event.capture.attribution,
            "capture_complete":event.complete}
    }]}});
    let before = ORIGINAL_TRAVERSALS.get();
    let published = for_diagnosis(&state, "POST /responses", &report).unwrap();
    assert_eq!(ORIGINAL_TRAVERSALS.get(), before);
    report["redis"]["unused_case"][0]
        .as_object_mut()
        .unwrap()
        .remove("source_occurrence");
    let rebuilt = for_diagnosis(&state, "POST /responses", &report).unwrap();
    assert_eq!(ORIGINAL_TRAVERSALS.get(), before + 1);
    assert_eq!(published.unused, rebuilt.unused);
    assert_eq!(published.case_defaults, rebuilt.case_defaults);
    assert_eq!(
        for_diagnosis(&state, "POST /responses", &report)
            .unwrap()
            .unused,
        rebuilt.unused
    );
    assert_eq!(ORIGINAL_TRAVERSALS.get(), before + 1);
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

#[tokio::test]
async fn a_new_process_selector_invalidates_previously_empty_case_admission() {
    let (target, mut state, _, original) = historical(true).await;
    super::super::analysis::refresh_inventory(target.path(), &mut state).unwrap();
    assert!(
        state
            .dependency_review
            .unresolved_source_exchange_ids
            .is_empty()
    );
    let admitted = state
        .dependency_review
        .case_defaults_identity
        .clone()
        .unwrap();
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
    // Read-only callers may still hold the prior admission cache.
    assert!(super::super::analysis::required_action(target.path(), &state).is_some());
    super::super::analysis::refresh_inventory(target.path(), &mut state).unwrap();
    assert_eq!(
        state.dependency_review.unresolved_source_exchange_ids.len(),
        2
    );
    assert_ne!(
        state.dependency_review.case_defaults_identity.as_ref(),
        Some(&admitted)
    );
    assert!(super::super::analysis::required_action(target.path(), &state).is_some());
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
}
