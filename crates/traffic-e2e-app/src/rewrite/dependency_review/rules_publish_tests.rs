//! Source attribution selects complete probe publications even on a shared channel.
use super::*;
use crate::config::native_policy::{NativeSourceScope, SourceObligation, validate_source};
use crate::protocols::recording::events::{RecorderEvent, RedisExchangeEvent};
use crate::recorder::{Recorder, capture_body};

#[tokio::test]
async fn sealed_process_publish_ownership_matches_only_complete_probe_messages() {
    let document = r#"
format: traffic-policy/v3
process_dependencies:
  tasks:
    ack_probe:
      requests:
        - redis:
            ports: [6379]
            operation: PUBLISH
            keys: [{kind: exact, value: socketio}]
            when_message:
              /method: {equals: callback}
              /sid: {prefix: 'probe:'}
"#;
    let policy = crate::policy::parse_and_compile_policy(document).unwrap();
    let projected = crate::config::native_policy::project_source_policy(&policy.native).unwrap();
    let rule = &projected.process_owned_dependencies[0];
    assert!(!rule.uses_redis_snapshot());
    let target = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(target.path().join("recordings"))
        .await
        .unwrap();
    let connection = Uuid::new_v4();
    for (index, (channel, sid, method, reply, port)) in [
        ("socketio", "probe:one", "callback", ":1\r\n", 6379),
        ("socketio", "probe:two", "callback", ":0\r\n", 6379),
        ("socketio", "client:one", "callback", ":1\r\n", 6379),
        ("socketio", "probe:one", "emit", ":1\r\n", 6379),
        ("socketio", "probe:one", "callback", ":-1\r\n", 6379),
        ("socketio", "probe:one", "callback", ":1\r\n", 6380),
        ("other", "probe:one", "callback", ":1\r\n", 6379),
    ]
    .into_iter()
    .enumerate()
    {
        let message = json!({"method": method, "sid": sid, "id": index + 1});
        let now = chrono::Utc::now();
        let exchange = RecorderEvent::RedisExchange(RedisExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: connection,
            sequence: index as u64 + 1,
            timestamp: now,
            request_started_at: now,
            client_addr: None,
            target_host: "cache.test".into(),
            target_port: port,
            target_addr: format!("cache.test:{port}"),
            upstream_addr: format!("cache.test:{port}"),
            resp_version: 2,
            database: 0,
            username: None,
            command: "PUBLISH".into(),
            args: vec![
                capture_body(channel.as_bytes(), 1024),
                capture_body(message.to_string().as_bytes(), 1024),
            ],
            response_kind: "integer".into(),
            response: capture_body(reply.as_bytes(), 1024),
            rpc_callback_capture: None,
            cache_snapshot_rule: None,
            cache_snapshot_hit: false,
            session_setup: false,
            outcome: crate::DependencyExchangeOutcome::Response,
            duration_ms: 1,
            replay_safe: true,
            parse_warnings: vec![],
        });
        assert_eq!(rule.matches(&exchange), index < 2);
        recorder
            .append_global_dependency(&exchange, "outside_admission", "runtime", "")
            .await
            .unwrap();
    }
    recorder.finish_run().await.unwrap();
    let mut state = crate::rewrite::test_state();
    let case_source = recorder.run_dir.as_path();
    state.case_source = Some(case_source.to_path_buf());
    state.recording_run_id = case_source.file_name().unwrap().to_str().unwrap().into();
    state.source_revision = Some("test-source".into());

    let original = source::load(&state).unwrap();
    let attributed = process_matches(&original, &policy.native, None).unwrap();
    assert_eq!(
        attributed
            .iter()
            .map(|id| original.exchanges[id].selector["sequence"]
                .as_u64()
                .unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2])
    );
    let validation = validate_source(
        NativeSourceScope {
            target_root: target.path(),
            case_source,
            source_revision: "test-source",
            recording_run_id: &state.recording_run_id,
            prepared_cases: &BTreeMap::new(),
            replay_report: None,
            policy_rules: &policy.native,
        },
        &policy.native,
    )
    .unwrap();
    assert_eq!(validation.rules[rule.name()], 2);
    assert_eq!(
        validation.obligations,
        BTreeSet::from([SourceObligation::AttributionReview])
    );

    let snapshot = document.replace(
        "operation: PUBLISH",
        "operation: PUBLISH\n            initial_load_timeout_ms: 1000",
    );
    let invalid = crate::policy::parse_and_compile_policy(&snapshot).unwrap();
    assert!(crate::config::native_policy::project_source_policy(&invalid.native).is_err());
}
