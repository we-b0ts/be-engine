use super::*;

#[test]
fn process_owned_publish_keeps_the_original_payload_and_finite_subscriber_count() {
    let policy = crate::policy::parse_and_compile_policy(
        r#"
format: traffic-policy/v3
process_dependencies:
  tasks:
    monitor:
      requests:
        - redis:
            ports: [6379]
            operation: PUBLISH
            keys: [{kind: exact, value: health}]
            when_message:
              /kind: {equals: probe}
"#,
    )
    .unwrap();
    let projection = crate::config::native_policy::project_source_policy(&policy.native).unwrap();
    let message = r#"{"kind":"probe","id":1}"#;
    let mut state = RedisReplayState::default();
    state
        .register_exchange(
            RecordedExchange {
                lifecycle_cleanup: false,
                native: NativeRecordedExchange {
                    parse_warnings: Vec::new(),
                    rpc_callback_capture: None,
                    id: None,
                    timestamp: None,
                    request_started_at: None,
                    connection_id: Uuid::new_v4(),
                    sequence: 1,
                    target_host: "redis.test".into(),
                    target_port: 6379,
                    resp_version: 2,
                    database: 0,
                    username: None,
                    command: "PUBLISH".into(),
                    args: vec![capture("health"), capture(message)],
                    response_kind: "integer".into(),
                    response: capture(":2\r\n"),
                    outcome: DependencyExchangeOutcome::Response,
                    duration_ms: 1,
                    replay_safe: true,
                    cache_snapshot_rule: None,
                    cache_snapshot_hit: false,
                    session_setup: false,
                    capture: Some(crate::dependency::observation::fixture_capture("process")),
                },
            },
            ReplaySource::Process,
            None,
            &mut BTreeMap::new(),
            &projection.process_owned_dependencies,
        )
        .unwrap();
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let attempt = |state: &mut RedisReplayState, payload: &str| {
        state.match_redis(
            None,
            &target,
            TargetConnection::default(),
            2,
            0,
            None,
            "PUBLISH",
            &[b"health".to_vec(), payload.as_bytes().to_vec()],
        )
    };
    assert!(attempt(&mut state, r#"{"kind":"probe","id":2}"#).is_err());
    let matched = attempt(&mut state, message).unwrap();
    assert_eq!(matched.response, b":2\r\n");
    state.complete_exchange(&matched);
    assert_eq!(state.snapshot().matched_count, 1);
    assert!(attempt(&mut state, message).is_err());
}
