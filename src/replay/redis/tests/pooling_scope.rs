use super::*;

fn record(connection: Uuid, sequence: u64, command: &str) -> RecordedExchange {
    let (kind, response) = if command == "WATCH" {
        ("simple_string", "+OK\r\n")
    } else {
        ("bulk_string", "$1\r\n1\r\n")
    };
    serde_json::from_value(serde_json::json!({
        "connection_id":connection, "sequence":sequence, "target_host":"redis.test",
        "target_port":6379, "resp_version":2, "database":0, "username":null,
        "command":command, "args":[{"encoding":"utf8", "data":"key"}],
        "response_kind":kind, "response":{"encoding":"utf8", "data":response},
        "replay_safe":true,
    }))
    .unwrap()
}

fn register(state: &mut RedisReplayState, record: RecordedExchange, case: &str) {
    state
        .register_exchange(
            record,
            ReplaySource::Case,
            Some(case),
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap();
}

fn matched(
    state: &mut RedisReplayState,
    case: &str,
    target: &TargetKey,
    connection: TargetConnection,
    command: &str,
) -> std::result::Result<MatchedRedisExchange, crate::replay::report::command::CommandMatchDiagnostic>
{
    state.match_redis(
        Some(case),
        target,
        connection,
        2,
        0,
        None,
        command,
        &[b"key".to_vec()],
    )
}

#[test]
fn ordinary_pool_matching_keeps_case_and_endpoint_boundaries() {
    let mut state = RedisReplayState::default();
    register(&mut state, record(Uuid::new_v4(), 1, "GET"), "a");
    register(&mut state, record(Uuid::new_v4(), 1, "GET"), "b");
    let mut other_port = record(Uuid::new_v4(), 1, "GET");
    other_port.target_port = 6380;
    register(&mut state, other_port, "a");
    let mut target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let connection = TargetConnection::default();
    let first = matched(&mut state, "a", &target, connection, "GET").unwrap();
    assert!(!first.requires_binding);
    state.complete_exchange(&first);
    assert!(matched(&mut state, "a", &target, connection, "GET").is_err());
    let second = matched(&mut state, "b", &target, connection, "GET").unwrap();
    state.complete_exchange(&second);
    target.port = 6380;
    let third = matched(&mut state, "a", &target, connection, "GET").unwrap();
    state.complete_exchange(&third);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn stateful_ownership_is_exclusive_within_each_case() {
    let mut state = RedisReplayState::default();
    let source = Uuid::new_v4();
    for (case, offset) in [("a", 0), ("b", 2)] {
        register(&mut state, record(source, offset + 1, "WATCH"), case);
        register(&mut state, record(source, offset + 2, "GET"), case);
    }
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let first = TargetConnection::default();
    let second = TargetConnection::default();
    for (case, owner) in [("a", first), ("b", second)] {
        let watch = matched(&mut state, case, &target, owner, "WATCH").unwrap();
        assert!(watch.requires_binding);
        state.complete_exchange(&watch);
    }
    assert!(matched(&mut state, "a", &target, second, "GET").is_err());
    assert!(matched(&mut state, "b", &target, first, "GET").is_err());
    for (case, owner) in [("a", first), ("b", second)] {
        let read = matched(&mut state, case, &target, owner, "GET").unwrap();
        state.complete_exchange(&read);
    }
    assert!(state.snapshot().unused_case.is_empty());
}
