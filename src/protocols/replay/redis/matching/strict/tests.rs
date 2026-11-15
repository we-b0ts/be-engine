use super::*;
use crate::replay::command_matching::preferred_match_with_priority;
use serde_json::json;

fn add(
    state: &mut RedisReplayState,
    source: ReplaySource,
    case: Option<&str>,
    lane: u128,
    sequence: u64,
    command: &str,
    key: &str,
) {
    let (kind, response) = match command {
        "SUBSCRIBE" => (
            "array",
            format!("*3\r\n$9\r\nsubscribe\r\n${}\r\n{key}\r\n:1\r\n", key.len()),
        ),
        "AUTH" | "HELLO" => ("error", "-ERR recorded authentication failure\r\n".into()),
        "DEL" => ("integer", ":1\r\n".into()),
        _ => ("bulk_string", "$1\r\nx\r\n".into()),
    };
    let record = serde_json::from_value(json!({
        "connection_id":Uuid::from_u128(lane),"sequence":sequence,"target_host":"redis.test","target_port":6379,
        "resp_version":2,"database":0,"username":null,"command":command,
        "args":[{"encoding":"utf8","data":key}],"response_kind":kind,
        "response":{"encoding":"utf8","data":response},"replay_safe":true
    })).unwrap();
    state
        .register_exchange(record, source, case, &mut BTreeMap::new(), &[])
        .unwrap();
}

fn fixture(unrelated: usize) -> RedisReplayState {
    let mut state = RedisReplayState::default();
    for index in 0..unrelated {
        add(
            &mut state,
            ReplaySource::Case,
            Some(&format!("unrelated-{index}")),
            1000 + index as u128,
            1,
            "GET",
            "key",
        );
    }
    add(&mut state, ReplaySource::Startup, None, 10, 1, "GET", "key");
    add(&mut state, ReplaySource::Process, None, 11, 1, "GET", "key");
    add(
        &mut state,
        ReplaySource::Case,
        Some("active"),
        12,
        1,
        "GET",
        "key",
    );
    add(
        &mut state,
        ReplaySource::Case,
        Some("active"),
        12,
        2,
        "DEL",
        "key",
    );
    add(
        &mut state,
        ReplaySource::Case,
        Some("origin"),
        13,
        1,
        "SUBSCRIBE",
        "jobs",
    );
    state.exchanges[unrelated + 4].subscription_alias = true;
    state
}

fn compare(
    state: &mut RedisReplayState,
    case: Option<&str>,
    command: &str,
    argument: &str,
) -> PreferredMatch {
    state.candidates.register(&state.exchanges);
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let arguments = [argument.as_bytes().to_vec()];
    let connection = TargetConnection {
        id: Uuid::from_u128(100),
        bound: None,
    };
    let request = Request {
        case,
        target: &target,
        connection,
        resp_version: 2,
        database: 0,
        username: None,
        command,
        args: &arguments,
    };
    // This uses the existing whole-inventory traversal and native predicate,
    // not a second implementation of the new index key or candidate filter.
    let scanned = preferred_match_with_priority(
        &state.exchanges,
        case,
        |exchange| request.matches(state, exchange),
        |exchange| request.priority(state, exchange),
    );
    let indexed = state.match_strict_redis(
        case, &target, connection, 2, 0, None, command, &arguments, None, None, false,
    );
    assert_eq!(indexed, scanned);
    indexed
}

#[test]
fn strict_redis_index_matches_scan_for_case_run_lane_alias_and_snapshot_states() {
    let mut state = fixture(0);
    assert_eq!(
        compare(&mut state, Some("active"), "GET", "key"),
        PreferredMatch::Matched(2)
    );
    assert_eq!(
        compare(&mut state, None, "GET", "key"),
        PreferredMatch::Matched(0)
    );
    assert_eq!(
        compare(&mut state, Some("active"), "DEL", "key"),
        PreferredMatch::LaneBlocked {
            candidate: 3,
            blocker: 2
        }
    );
    state.exchanges[2].status = ReplayExchangeStatus::Responding;
    assert_eq!(
        compare(&mut state, Some("active"), "DEL", "key"),
        PreferredMatch::Matched(3)
    );
    state.exchanges[2].status = ReplayExchangeStatus::Failed;
    assert_eq!(
        compare(&mut state, Some("active"), "GET", "key"),
        PreferredMatch::Matched(0)
    );
    assert_eq!(
        compare(&mut state, None, "SUBSCRIBE", "jobs"),
        PreferredMatch::Matched(4)
    );
    state.exchanges[0].status = ReplayExchangeStatus::Failed;
    state.exchanges[1].status = ReplayExchangeStatus::Consumed;
    state.exchanges[1].reusable_snapshot = true;
    state.exchanges[1].matched_once = true;
    assert_eq!(
        compare(&mut state, Some("active"), "GET", "key"),
        PreferredMatch::Matched(1)
    );
    assert_eq!(
        compare(&mut state, Some("active"), "GET", "wrong"),
        PreferredMatch::NotFound
    );
}

#[test]
fn strict_redis_walk_is_case_local_with_thousands_of_unrelated_commands() {
    let mut state = fixture(2048);
    assert_eq!(
        compare(&mut state, Some("active"), "GET", "key"),
        PreferredMatch::Matched(2050)
    );
    let candidates = state
        .candidates
        .select(
            ReplaySource::Case,
            Some("active"),
            &TargetKey {
                host: "redis.test".into(),
                port: 6379,
            },
            2,
            0,
            None,
            "GET",
        )
        .collect::<Vec<_>>();
    assert_eq!(candidates, [2050]);
}

#[test]
fn blocked_publish_keeps_its_first_match_and_can_fall_back_to_another_lane() {
    let mut state = RedisReplayState::default();
    let case = Some("active");
    add(
        &mut state,
        ReplaySource::Case,
        case,
        10,
        1,
        "PUBLISH",
        "before",
    );
    add(
        &mut state,
        ReplaySource::Case,
        case,
        10,
        2,
        "PUBLISH",
        "event",
    );
    for sequence in 3..1027 {
        add(
            &mut state,
            ReplaySource::Case,
            case,
            10,
            sequence,
            "PUBLISH",
            "event",
        );
    }
    assert_eq!(
        compare(&mut state, case, "PUBLISH", "event"),
        PreferredMatch::LaneBlocked {
            candidate: 1,
            blocker: 0
        }
    );

    add(
        &mut state,
        ReplaySource::Case,
        case,
        20,
        1,
        "PUBLISH",
        "event",
    );
    assert_eq!(
        compare(&mut state, case, "PUBLISH", "event"),
        PreferredMatch::Matched(1026)
    );
}

#[test]
fn required_subscription_keeps_priority_and_its_cross_command_lane_barrier() {
    let mut state = RedisReplayState::default();
    add(
        &mut state,
        ReplaySource::Case,
        Some("active"),
        10,
        1,
        "SUBSCRIBE",
        "jobs",
    );
    add(
        &mut state,
        ReplaySource::Case,
        Some("active"),
        20,
        1,
        "GET",
        "before",
    );
    add(
        &mut state,
        ReplaySource::Case,
        Some("active"),
        20,
        2,
        "SUBSCRIBE",
        "jobs",
    );
    let host = "30b6569f34c2486dafd3bf29b09a071f";
    let callback = serde_json::to_vec(&json!({
        "method":"callback", "host_id":host, "sid":"peer", "namespace":"/rpc",
        "id":1, "args":[{"success":true}]
    }))
    .unwrap();
    let push = crate::redis::encode_array(&[b"message", b"jobs", &callback]);
    state
        .pubsub
        .register(
            serde_json::from_value(json!({
                "connection_id":Uuid::from_u128(20), "subscription_sequence":2,
                "target_host":"redis.test", "target_port":6379, "database":0, "username":null,
                "rpc_request":{"connection_id":Uuid::from_u128(30), "sequence":1},
                "response":{"encoding":"utf8", "data":String::from_utf8(push).unwrap()},
                "duration_ms":0, "replay_safe":true
            }))
            .unwrap(),
            ReplaySource::Case,
            Some("active"),
        )
        .unwrap();
    let request = json!({
        "method":"emit", "event":"example:run", "data":[], "binary":false,
        "namespace":"/rpc", "room":"peer", "skip_sid":null,
        "callback":["peer", "/rpc", 1], "host_id":host
    })
    .to_string();
    state
        .register_exchange(
            serde_json::from_value(json!({
                "connection_id":Uuid::from_u128(30), "sequence":1,
                "target_host":"redis.test", "target_port":6379, "resp_version":2,
                "database":0, "username":null, "command":"PUBLISH",
                "args":[{"encoding":"utf8", "data":"jobs"}, {"encoding":"utf8", "data":request}],
                "response_kind":"integer", "response":{"encoding":"utf8", "data":":1\r\n"},
                "replay_safe":true
            }))
            .unwrap(),
            ReplaySource::Case,
            Some("active"),
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap();
    // Callback linkage, rather than an injected priority flag, establishes the
    // required subscriber. The earlier optional lane must never hide its fence.
    assert!(!state.pubsub.is_callback_subscription(&state.exchanges[0]));
    assert!(state.pubsub.is_callback_subscription(&state.exchanges[2]));
    let blocked = PreferredMatch::LaneBlocked {
        candidate: 2,
        blocker: 1,
    };
    assert_eq!(
        compare(&mut state, Some("active"), "SUBSCRIBE", "jobs"),
        blocked
    );
    state.exchanges[1].status = ReplayExchangeStatus::Responding;
    assert_eq!(
        compare(&mut state, Some("active"), "SUBSCRIBE", "jobs"),
        PreferredMatch::Matched(2)
    );
    state.exchanges[1].status = ReplayExchangeStatus::Failed;
    assert_eq!(
        compare(&mut state, Some("active"), "SUBSCRIBE", "jobs"),
        blocked
    );
}

#[test]
fn indexed_builtin_failure_keeps_auth_argument_wildcards_and_cross_command_barriers() {
    let mut state = RedisReplayState::default();
    add(
        &mut state,
        ReplaySource::Case,
        Some("active"),
        1,
        1,
        "GET",
        "key",
    );
    add(
        &mut state,
        ReplaySource::Case,
        Some("active"),
        1,
        2,
        "AUTH",
        "source-secret",
    );
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let command = RedisCommand {
        name: "AUTH".into(),
        args: vec![b"different-target-secret".to_vec()],
    };
    let connection = TargetConnection {
        id: Uuid::from_u128(100),
        bound: None,
    };
    assert!(
        state
            .match_redis_builtin_failure(Some("active"), &target, connection, 2, 0, None, &command)
            .is_none()
    );
    state.exchanges[0].status = ReplayExchangeStatus::Responding;
    let matched = state
        .match_redis_builtin_failure(Some("active"), &target, connection, 2, 0, None, &command)
        .unwrap();
    assert_eq!(matched.index, 1);
    assert_eq!(
        matched.response,
        b"-ERR recorded authentication failure\r\n"
    );
}
