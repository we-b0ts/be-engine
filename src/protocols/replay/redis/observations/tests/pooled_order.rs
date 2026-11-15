//! Pooled requests can arrive before a delivered predecessor finishes bookkeeping.
use super::*;
use crate::protocols::replay::redis::report::RedisDiagnostic;

fn list_event(sequence: u64, command: &str, args: &[&[u8]], response: &[u8]) -> Value {
    let mut recorded = event(sequence, command, args, response);
    recorded["connection_id"] = json!(Uuid::from_u128(if command == "LRANGE" { 1 } else { 2 }));
    recorded["response_kind"] = json!(match response[0] {
        b'*' => "array",
        b'+' => "simple_string",
        _ => "integer",
    });
    recorded
}

fn request_on(
    state: &mut RedisReplayState,
    connection: u128,
    command: &str,
    args: &[&[u8]],
) -> std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic> {
    state.match_redis(
        Some("case"),
        &TargetKey {
            host: "redis.test".into(),
            port: 6379,
        },
        TargetConnection {
            id: Uuid::from_u128(connection),
            ..Default::default()
        },
        2,
        0,
        None,
        command,
        &args.iter().map(|arg| arg.to_vec()).collect::<Vec<_>>(),
    )
}

fn read_then_write(command: &str, args: &[&[u8]], response: &[u8]) -> Vec<Value> {
    vec![
        list_event(
            1,
            "LRANGE",
            &[b"content:1", b"0", b"-1"],
            b"*1\r\n$3\r\nold\r\n",
        ),
        list_event(2, command, args, response),
        list_event(3, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ]
}

fn read_write_read() -> Vec<Value> {
    vec![
        list_event(
            1,
            "LRANGE",
            &[b"content:1", b"0", b"-1"],
            b"*1\r\n$3\r\nold\r\n",
        ),
        list_event(2, "LSET", &[b"content:1", b"0", b"new"], b"+OK\r\n"),
        list_event(
            3,
            "LRANGE",
            &[b"content:1", b"0", b"-1"],
            b"*1\r\n$3\r\nnew\r\n",
        ),
        list_event(4, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ]
}

#[test]
fn pooled_list_writes_accept_a_responding_read_without_consuming_it() {
    for (command, args, response) in [
        (
            "LSET",
            vec![b"content:1".as_slice(), b"0", b"new"],
            b"+OK\r\n".as_slice(),
        ),
        (
            "RPUSH",
            vec![b"content:1".as_slice(), b"new"],
            b":2\r\n".as_slice(),
        ),
    ] {
        let events = read_then_write(command, &args, response);
        let (_root, mut state) = state(&events, vec![refresh_rule()]);
        assert!(request_on(&mut state, 20, command, &args).is_err());
        let read = request_on(&mut state, 10, "LRANGE", &[b"content:1", b"0", b"-1"]).unwrap();
        let mut wrong_args = args.clone();
        *wrong_args.last_mut().unwrap() = b"wrong";
        assert!(request_on(&mut state, 20, command, &wrong_args).is_err());
        let write = request_on(&mut state, 20, command, &args).unwrap();
        assert_eq!(write.response, response);
        assert_eq!(
            state.exchanges[read.index].status,
            ReplayExchangeStatus::Responding
        );
        assert_eq!(state.events.matched_count, 0);
        assert!(state.has_case_in_flight());
        state.complete_exchange(&write);
        assert!(state.has_case_in_flight());
        state.complete_exchange(&read);
        perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
        assert!(!state.has_case_in_flight());
        assert!(!state.case_is_dirty("case"));
        assert!(state.snapshot().unused_case.is_empty());
    }
}

#[test]
fn pooled_list_read_accepts_a_responding_write_and_keeps_refresh_delivery_fenced() {
    let events = read_write_read();
    let (_root, mut state) = state(&events, vec![refresh_rule()]);
    perform(&mut state, "LRANGE", &[b"content:1", b"0", b"-1"]);
    assert!(request_on(&mut state, 10, "LRANGE", &[b"content:1", b"0", b"-1"]).is_err());
    let write = request_on(&mut state, 20, "LSET", &[b"content:1", b"0", b"new"]).unwrap();
    let read = request_on(&mut state, 10, "LRANGE", &[b"content:1", b"0", b"-1"]).unwrap();
    assert_eq!(read.response, b"*1\r\n$3\r\nnew\r\n");
    state.complete_exchange(&read);
    assert_eq!(
        state.exchanges[write.index].status,
        ReplayExchangeStatus::Responding
    );
    assert!(state.has_case_in_flight());
    assert!(request_on(&mut state, 20, "EXPIRE", &[b"content:1", b"60"]).is_err());
    state.complete_exchange(&write);
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn pooled_list_update_and_append_each_accept_their_responding_read() {
    let events = [
        list_event(
            1,
            "LRANGE",
            &[b"content:1", b"0", b"-1"],
            b"*1\r\n$3\r\nold\r\n",
        ),
        list_event(2, "LSET", &[b"content:1", b"0", b"new"], b"+OK\r\n"),
        list_event(3, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
        list_event(
            4,
            "LRANGE",
            &[b"content:1", b"0", b"-1"],
            b"*1\r\n$3\r\nnew\r\n",
        ),
        list_event(5, "RPUSH", &[b"content:1", b"tail"], b":2\r\n"),
        list_event(6, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![refresh_rule()]);
    for (command, args) in [
        ("LSET", vec![b"content:1".as_slice(), b"0", b"new"]),
        ("RPUSH", vec![b"content:1".as_slice(), b"tail"]),
    ] {
        let read = request_on(&mut state, 10, "LRANGE", &[b"content:1", b"0", b"-1"]).unwrap();
        let write = request_on(&mut state, 20, command, &args).unwrap();
        state.complete_exchange(&write);
        state.complete_exchange(&read);
        perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    }
    assert!(state.snapshot().unused_case.is_empty());
    assert!(!state.case_is_dirty("case"));
}

#[test]
fn pooled_initial_accesses_still_reject_unclaimed_failed_and_terminating_predecessors() {
    for status in [
        ReplayExchangeStatus::Available,
        ReplayExchangeStatus::Failed,
        ReplayExchangeStatus::AwaitingClientTermination,
    ] {
        for write_first in [false, true] {
            let events = if write_first {
                read_write_read()
            } else {
                read_then_write("LSET", &[b"content:1", b"0", b"new"], b"+OK\r\n")
            };
            let (_root, mut state) = state(&events, vec![refresh_rule()]);
            state.prepare_observations("case").unwrap();
            let (predecessor, command, args) = if write_first {
                perform(&mut state, "LRANGE", &[b"content:1", b"0", b"-1"]);
                (1, "LRANGE", vec![b"content:1".as_slice(), b"0", b"-1"])
            } else {
                (0, "LSET", vec![b"content:1".as_slice(), b"0", b"new"])
            };
            state.exchanges[predecessor].status = status;
            let error = request_on(
                &mut state,
                if write_first { 10 } else { 20 },
                command,
                &args,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                CommandMatchDiagnostic::Native(RedisDiagnostic::StateObservation { .. })
            ));
        }
    }
}

#[test]
fn repeated_initial_list_reads_keep_their_finite_slots_while_responding() {
    let events = [
        list_event(
            1,
            "LRANGE",
            &[b"content:1", b"0", b"-1"],
            b"*1\r\n$3\r\nold\r\n",
        ),
        list_event(
            2,
            "LRANGE",
            &[b"content:1", b"0", b"-1"],
            b"*1\r\n$3\r\nold\r\n",
        ),
        list_event(3, "LSET", &[b"content:1", b"0", b"new"], b"+OK\r\n"),
        list_event(4, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![refresh_rule()]);
    let first = request_on(&mut state, 10, "LRANGE", &[b"content:1", b"0", b"-1"]).unwrap();
    let second = request_on(&mut state, 11, "LRANGE", &[b"content:1", b"0", b"-1"]).unwrap();
    assert_ne!(first.index, second.index);
    assert!(request_on(&mut state, 12, "LRANGE", &[b"content:1", b"0", b"-1"]).is_err());
    let write = request_on(&mut state, 20, "LSET", &[b"content:1", b"0", b"new"]).unwrap();
    state.complete_exchange(&write);
    state.complete_exchange(&second);
    assert_eq!(state.events.matched_count, 2);
    assert!(state.has_case_in_flight());
    state.complete_exchange(&first);
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn a_predecessor_delivery_failure_stays_dirty_after_a_pooled_write_is_admitted() {
    let events = read_then_write("LSET", &[b"content:1", b"0", b"new"], b"+OK\r\n");
    let (_root, mut state) = state(&events, vec![refresh_rule()]);
    let read = request_on(&mut state, 10, "LRANGE", &[b"content:1", b"0", b"-1"]).unwrap();
    let write = request_on(&mut state, 20, "LSET", &[b"content:1", b"0", b"new"]).unwrap();
    state.complete_exchange(&write);
    state.fail_exchange(&read, "response transport failed".into());
    assert_eq!(
        state.exchanges[read.index].status,
        ReplayExchangeStatus::Failed
    );
    assert!(state.case_is_dirty("case"));
    assert!(!state.has_case_in_flight());
    assert_eq!(state.events.matched_count, 1);
    assert_eq!(state.snapshot().unsafe_events.len(), 1);
    assert!(!state.snapshot().unused_case.is_empty());
    assert!(request_on(&mut state, 20, "EXPIRE", &[b"content:1", b"60"]).is_err());
}
