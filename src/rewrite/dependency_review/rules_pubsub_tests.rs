//! Old immutable notification inputs acquire only independently proven task owners.
use super::*;
use crate::recorder::{
    Recorder, RecorderEvent, RedisExchangeEvent, RedisPubSubPushEvent, capture_body,
};

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn source(
    subscription_channel: &str,
) -> (tempfile::TempDir, crate::rewrite::model::RewriteState) {
    let target = crate::rewrite::worker::tests::configured_target();
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    let connection = Uuid::new_v4();
    for (sequence, channel) in [(1, subscription_channel), (2, "presence")] {
        let response = format!(
            "*3\r\n$9\r\nsubscribe\r\n${}\r\n{channel}\r\n:1\r\n",
            channel.len()
        );
        let exchange = RecorderEvent::RedisExchange(RedisExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: connection,
            sequence,
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
            command: "SUBSCRIBE".into(),
            args: vec![capture_body(channel.as_bytes(), 1024)],
            response_kind: "array".into(),
            response: capture_body(response.as_bytes(), 1024),
            rpc_callback_capture: None,
            cache_snapshot_rule: None,
            cache_snapshot_hit: false,
            session_setup: false,
            outcome: crate::DependencyExchangeOutcome::Response,
            duration_ms: 1,
            replay_safe: true,
            parse_warnings: vec![],
        });
        recorder
            .append_global_dependency(&exchange, "outside_admission", "runtime", "")
            .await
            .unwrap();
    }
    for (sequence, channel) in [(1, "socketio"), (1, "socketio"), (2, "presence")] {
        let raw =
            crate::redis::encode_array(&[b"message", channel.as_bytes(), b"independent-input"]);
        let push = RecorderEvent::RedisPubSubPush(RedisPubSubPushEvent {
            timestamp: chrono::Utc::now(),
            target_host: "cache.test".into(),
            target_port: 6379,
            database: 0,
            username: None,
            connection_id: connection,
            subscription_sequence: sequence,
            rpc_request: None,
            response: capture_body(&raw, 1024),
            duration_ms: 1,
            replay_safe: true,
        });
        recorder
            .append_global_dependency(&push, "outside_admission", "runtime", "")
            .await
            .unwrap();
    }
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
    let raw = format!(
        "format: traffic-policy/v3\nsource_revision: {REVISION}\nprocess_dependencies:\n  tasks:\n    redis_reader:\n      requests:\n        - redis_pubsub:\n            resource: {{protocol: redis, endpoint: cache.test:6379, database: 0}}\n            channel: socketio\n            kind: message\n        - redis_pubsub:\n            resource: {{protocol: redis, endpoint: cache.test:6379, database: 0}}\n            channel: presence\n            kind: message\n"
    );
    fs::write(target.path().join(".traffic-e2e/policy.yaml"), raw).unwrap();
    (target, state)
}

fn proposal(source: &SourceSnapshot, policy: &CompiledPolicy) -> ProposedAttribution {
    let epoch = *source.epochs.first().unwrap();
    ProposedAttribution{
        claim_ids:BTreeSet::new(),source_exchange_ids:BTreeSet::new(),source_task:"redis_reader".into(),
        owner:DependencyOwner::Process{process_epoch:epoch,source_task:"redis_reader".into(),invocation:None},
        proof:crate::dependency::attribution::AttributionProof{source_revision:REVISION.into(),
            source_locations:vec!["src/subscriber.rs:receive".into()],call_chain:"start spawns the Redis subscriber, which reads each received native input".into(),
            exclusive_scope:"The receive task owns these exact endpoint/auth/channel inputs; external publisher identity remains unknown".into()},
        impact:crate::rewrite::verification_obligations::VerificationImpact::Classification,
        obligation_scope:crate::rewrite::verification_obligations::VerificationScope::Process{source_task:"redis_reader".into(),process_epoch:epoch},
        missing_evidence:None,rule_binding:super::super::model::AttributionRuleBinding{
            policy_fingerprint:policy.fingerprints.full.clone(),rule_ids:policy.native.iter().map(|rule|rule.rule.id.clone()).collect()},
    }
}

#[tokio::test]
async fn original_pubsub_inputs_bind_the_complete_receive_task_without_claiming_subscription_commands()
 {
    let (target, state) = source("socketio").await;
    let original = source::load(&state).unwrap();
    let before = fs::read(
        state
            .case_source
            .as_ref()
            .unwrap()
            .join("dependencies.jsonl"),
    )
    .unwrap();
    let policy = load(target.path()).unwrap();
    let mut selected = proposal(&original, &policy);
    bind(target.path(), &state, &original, &mut selected).unwrap();
    assert_eq!(selected.source_exchange_ids.len(), 3);
    assert!(
        selected
            .source_exchange_ids
            .iter()
            .all(|id| original.exchanges[id].selector["event_type"] == "redis_pub_sub_push")
    );
    assert!(original.exchanges.values().all(|event| matches!(
        event.capture.attribution,
        DependencyOwner::Unattributed { .. }
    )));
    assert_eq!(
        fs::read(
            state
                .case_source
                .as_ref()
                .unwrap()
                .join("dependencies.jsonl")
        )
        .unwrap(),
        before
    );
    let mut partial = proposal(&original, &policy);
    partial.rule_binding.rule_ids.pop_first();
    assert!(bind(target.path(), &state, &original, &mut partial).is_err());
    selected.source_exchange_ids.pop_first();
    assert!(bind(target.path(), &state, &original, &mut selected).is_err());
}

#[tokio::test]
async fn matching_channel_without_the_original_subscription_cannot_acquire_a_task_owner() {
    let (target, state) = source("different-channel").await;
    let original = source::load(&state).unwrap();
    let policy = load(target.path()).unwrap();
    let mut selected = proposal(&original, &policy);
    let error = bind(target.path(), &state, &original, &mut selected).unwrap_err();
    assert!(
        error.to_string().contains("subscription subject"),
        "{error:#}"
    );
}

#[tokio::test]
async fn notification_rules_validate_the_whole_sealed_source_without_a_prior_replay() {
    for valid in [false, true] {
        let (target, state) = source(if valid {
            "socketio"
        } else {
            "different-channel"
        })
        .await;
        let policy = load(target.path()).unwrap();
        let prepared = BTreeMap::new();
        let result = crate::config::native_policy::validate_source(
            crate::config::native_policy::NativeSourceScope {
                target_root: target.path(),
                case_source: state.case_source.as_ref().unwrap(),
                source_revision: REVISION,
                recording_run_id: &state.recording_run_id,
                prepared_cases: &prepared,
                replay_report: None,
                policy_rules: &policy.native,
            },
            &policy.native,
        );
        if valid {
            let result = result.unwrap();
            assert_eq!(result.rules.values().sum::<usize>(), 3);
            assert_eq!(
                result.obligations,
                BTreeSet::from([crate::config::native_policy::SourceObligation::AttributionReview])
            );
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("subscription subject")
            );
        }
    }
}
