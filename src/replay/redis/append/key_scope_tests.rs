//! A key declaration discovers physical Source lanes without merging them.
use super::tests::{event, state_with_policy};
use super::*;
use serde_json::{Value, json};

fn rules() -> Vec<Value> {
    [
        ("append", "APPEND", "redis_append_stream"),
        ("refresh", "EXPIRE", "redis_expiry_refresh"),
    ]
    .into_iter()
    .map(|(id, operation, kind)| {
        json!({"id":id,
            "match":{"operation":operation,"key":{"kind":"affix","prefix":"content:"}},
            "effect":{"kind":kind}})
    })
    .collect()
}

fn events() -> Vec<Value> {
    let mut events = Vec::new();
    for (lane, host, database, user, bytes) in [
        (0, "first.test", 0, "writer", b"abc".as_slice()),
        (1, "second.test", 1, "reader", b"xyz".as_slice()),
    ] {
        for (offset, (command, args, response)) in [
            (
                "APPEND",
                vec![b"content:same".as_slice(), bytes],
                b":3\r\n".as_slice(),
            ),
            (
                "EXPIRE",
                vec![b"content:same".as_slice(), b"60".as_slice()],
                b":1\r\n".as_slice(),
            ),
            (
                "GET",
                vec![b"content:same".as_slice()],
                if lane == 0 {
                    b"$3\r\nabc\r\n".as_slice()
                } else {
                    b"$3\r\nxyz\r\n".as_slice()
                },
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut recorded = event((lane * 3 + offset + 1) as u64, command, &args, response);
            recorded["target_host"] = json!(host);
            recorded["database"] = json!(database);
            recorded["username"] = json!(user);
            recorded["connection_id"] = json!(Uuid::from_u128(lane as u128 + 1));
            events.push(recorded);
        }
    }
    events
}

fn request(
    state: &mut RedisReplayState,
    host: &str,
    database: i64,
    user: &str,
    command: &str,
    values: &[&[u8]],
) -> std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic> {
    state.match_redis(
        Some("case"),
        &TargetKey {
            host: host.into(),
            port: 6379,
        },
        TargetConnection::default(),
        2,
        database,
        Some(user),
        command,
        &values
            .iter()
            .map(|value| value.to_vec())
            .collect::<Vec<_>>(),
    )
}

fn perform(
    state: &mut RedisReplayState,
    host: &str,
    database: i64,
    user: &str,
    command: &str,
    values: &[&[u8]],
) -> Vec<u8> {
    let matched = request(state, host, database, user, command, values).unwrap();
    let response = matched.response.clone();
    state.complete_exchange(&matched);
    response
}

#[test]
fn one_key_rule_partitions_source_endpoints_databases_and_users_before_rechunking() {
    let (_root, mut state) = state_with_policy(
        &events(),
        json!({"format":"traffic-policy/v3","rules":rules()}),
    );
    for (host, database, user, chunk) in [
        ("second.test", 1, "reader", b"a".as_slice()),
        ("first.test", 1, "writer", b"a".as_slice()),
        ("first.test", 0, "reader", b"a".as_slice()),
    ] {
        assert!(
            request(
                &mut state,
                host,
                database,
                user,
                "APPEND",
                &[b"content:same", chunk]
            )
            .is_err()
        );
    }
    for (offset, chunk) in [b"a", b"b", b"c"].into_iter().enumerate() {
        assert_eq!(
            perform(
                &mut state,
                "first.test",
                0,
                "writer",
                "APPEND",
                &[b"content:same", chunk]
            ),
            format!(":{}\r\n", offset + 1).into_bytes()
        );
    }
    for _ in 0..2 {
        assert_eq!(
            perform(
                &mut state,
                "first.test",
                0,
                "writer",
                "EXPIRE",
                &[b"content:same", b"60"]
            ),
            b":1\r\n"
        );
    }
    assert_eq!(
        perform(
            &mut state,
            "first.test",
            0,
            "writer",
            "GET",
            &[b"content:same"]
        ),
        b"$3\r\nabc\r\n"
    );
    assert_eq!(
        perform(
            &mut state,
            "second.test",
            1,
            "reader",
            "APPEND",
            &[b"content:same", b"xyz"]
        ),
        b":3\r\n"
    );
    perform(
        &mut state,
        "second.test",
        1,
        "reader",
        "EXPIRE",
        &[b"content:same", b"60"],
    );
    assert_eq!(
        perform(
            &mut state,
            "second.test",
            1,
            "reader",
            "GET",
            &[b"content:same"]
        ),
        b"$3\r\nxyz\r\n"
    );
    assert!(state.snapshot().unused_case.is_empty());
    assert_eq!(state.append_streams.profiles.len(), 2);
}

#[test]
fn global_key_behavior_keeps_each_physical_database_inventory_independent() {
    let (_root, mut state) = state_with_policy(
        &events(),
        json!({"format":"traffic-policy/v3",
        "rules":rules()}),
    );
    assert_eq!(
        perform(
            &mut state,
            "second.test",
            1,
            "reader",
            "APPEND",
            &[b"content:same", b"x"]
        ),
        b":1\r\n"
    );
    assert_eq!(
        perform(
            &mut state,
            "second.test",
            1,
            "reader",
            "APPEND",
            &[b"content:same", b"yz"]
        ),
        b":3\r\n"
    );
    assert_eq!(state.append_streams.profiles.len(), 2);
    assert!(
        state
            .append_streams
            .profiles
            .iter()
            .any(|profile| profile.database == 0)
    );
    assert!(
        state
            .append_streams
            .profiles
            .iter()
            .any(|profile| profile.database == 1)
    );
}
