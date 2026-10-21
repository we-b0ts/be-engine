//! Stateful matching regressions use genuine RESP records and complete policy scopes.
use super::*;
use serde_json::{Value, json};

pub(super) fn rule() -> Value {
    json!({"id":"append","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},
        "operation":"APPEND","key":{"kind":"affix","prefix":"content:"}},"effect":{"kind":"redis_append_stream"},
        "proof":{"source":"session.py:20","fact":"Source buffers nonempty ordered text into variable APPEND batches; only read/reset boundaries observe the value"}})
}

pub(in crate::replay::redis) fn event(
    seq: u64,
    command: &str,
    args: &[&[u8]],
    response: &[u8],
) -> Value {
    let capture =
        |bytes: &[u8]| json!({"encoding":"base64","data":STANDARD.encode(bytes),"truncated":false});
    json!({"event_type":"redis_exchange","connection_id":Uuid::nil(),"sequence":seq,
        "timestamp":format!("2020-01-01T00:00:{seq:02}Z"),"request_started_at":format!("2020-01-01T00:00:{seq:02}Z"),
        "duration_ms":0,"outcome":"response","target_host":"redis.test","target_port":6379,"database":0,"resp_version":2,
        "command":command,"args":args.iter().map(|v|capture(v)).collect::<Vec<_>>(),"response":capture(response),
        "response_kind":if command=="SET" {"simple_string"}else if command=="GET" {"bulk_string"}else{"integer"},"replay_safe":true})
}

fn state(events: &[Value], rules: Vec<Value>) -> (tempfile::TempDir, RedisReplayState) {
    let root = tempfile::tempdir().unwrap();
    let case = root.path().join("case");
    std::fs::create_dir(&case).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    std::fs::write(
        case.join("dependencies.jsonl"),
        events.iter().map(|v| format!("{v}\n")).collect::<String>(),
    )
    .unwrap();
    let policy = root.path().join("policy.yaml");
    std::fs::write(
        &policy,
        json!({"format":"traffic-policy/v1","rules":rules}).to_string(),
    )
    .unwrap();
    let runtime = crate::replay::ReplayPolicyRuntime::load(
        &policy,
        &BTreeMap::from([(
            "case".into(),
            crate::replay::ReplayCase {
                id: "case".into(),
                dir: case.clone(),
                dependencies_path: case.join("dependencies.jsonl"),
                status: crate::replay::ReplayCaseStatus::Pending,
            },
        )]),
    )
    .unwrap();
    let mut state = RedisReplayState {
        request_contracts: runtime.request_contracts.clone(),
        dynamic_values: runtime.dynamic_values.clone(),
        ..Default::default()
    };
    let mut targets = BTreeMap::new();
    for event in events {
        state
            .register_exchange(
                serde_json::from_value(event.clone()).unwrap(),
                ReplaySource::Case,
                Some("case"),
                &mut targets,
                &[],
            )
            .unwrap();
    }
    (root, state)
}

fn request(
    state: &mut RedisReplayState,
    command: &str,
    args: &[&[u8]],
) -> std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic> {
    state.match_redis(
        Some("case"),
        &TargetKey {
            host: "redis.test".into(),
            port: 6379,
        },
        TargetConnection::default(),
        2,
        0,
        None,
        command,
        &args.iter().map(|v| v.to_vec()).collect::<Vec<_>>(),
    )
}

#[test]
fn split_merge_returns_actual_lengths_and_consumes_source_only_after_delivery() {
    let events = [
        event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
        event(2, "APPEND", &[b"content:1", b"cdef"], b":6\r\n"),
        event(3, "GET", &[b"content:1"], b"$6\r\nabcdef\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    let a = request(&mut state, "APPEND", &[b"content:1", b"a"]).unwrap();
    assert_eq!(a.response, b":1\r\n");
    state.complete_exchange(&a);
    assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Responding);
    assert!(!state.has_case_in_flight());
    assert!(request(&mut state, "GET", &[b"content:1"]).is_err());
    let b = request(&mut state, "APPEND", &[b"content:1", b"bcd"]).unwrap();
    assert_eq!(b.response, b":4\r\n");
    state.complete_exchange(&b);
    assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Consumed);
    assert_eq!(state.exchanges[1].status, ReplayExchangeStatus::Responding);
    let c = request(&mut state, "APPEND", &[b"content:1", b"ef"]).unwrap();
    assert_eq!(c.response, b":6\r\n");
    state.complete_exchange(&c);
    let read = request(&mut state, "GET", &[b"content:1"]).unwrap();
    assert_eq!(read.response, b"$6\r\nabcdef\r\n");
    state.complete_exchange(&read);
    assert!(state.snapshot().unused_case.is_empty());
    assert!(request(&mut state, "APPEND", &[b"content:1", b"g"]).is_err());
    let report = serde_json::to_value(state.snapshot()).unwrap();
    assert_eq!(
        report["append_streams"][1]["fragments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(!report.to_string().contains("abcdef"));
}

#[test]
fn byte_mismatch_does_not_claim_any_prefix_and_unfinished_sources_remain_unused() {
    let events = [event(1, "APPEND", &[b"content:1", b"abcd"], b":4\r\n")];
    let (_root, mut state) = state(&events, vec![rule()]);
    for bad in [b"ax".as_slice(), b"abcdx", b"", b"ba"] {
        assert!(request(&mut state, "APPEND", &[b"content:1", bad]).is_err());
        assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Available);
    }
    let a = request(&mut state, "APPEND", &[b"content:1", b"ab"]).unwrap();
    state.complete_exchange(&a);
    assert_eq!(state.snapshot().unused_case.len(), 1);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"dc"]).is_err());
    let b = request(&mut state, "APPEND", &[b"content:1", b"cd"]).unwrap();
    state.complete_exchange(&b);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn byte_mismatch_reports_the_validated_source_cursor_without_payloads() {
    let events = [
        event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
        event(2, "APPEND", &[b"content:1", b"cdef"], b":6\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    let first = request(&mut state, "APPEND", &[b"content:1", b"abc"]).unwrap();
    state.complete_exchange(&first);
    let error = request(&mut state, "APPEND", &[b"content:1", b"dXf"]).unwrap_err();
    assert!(matches!(
        error,
        CommandMatchDiagnostic::RedisAppendStreamMismatch { .. }
    ));
    let diagnostic = serde_json::to_value(error).unwrap();
    assert_eq!(diagnostic["kind"], "redis_append_stream_mismatch");
    assert_eq!(diagnostic["rule_id"], "append");
    assert_eq!(diagnostic["source_offset"], 3);
    assert_eq!(diagnostic["first_difference_offset"], 4);
    assert_eq!(diagnostic["source_bytes_remaining"], 3);
    assert_eq!(diagnostic["target_bytes"], 3);
    assert_eq!(diagnostic["next_source"]["sequence"], 2);
    assert_eq!(diagnostic["next_source"]["command"], "APPEND");
    assert_eq!(diagnostic["next_source"]["case_id"], "case");
    assert_eq!(
        diagnostic["payload_fingerprint"],
        crate::policy_evidence::digest(b"dXf")
    );
    assert!(!diagnostic.to_string().contains("dXf"));
    assert!(!diagnostic.to_string().contains("content:1"));
    assert_eq!(state.exchanges[1].status, ReplayExchangeStatus::Responding);
    assert_eq!(state.append_streams.profiles[0].reserved, 3);
    let rest = request(&mut state, "APPEND", &[b"content:1", b"def"]).unwrap();
    state.complete_exchange(&rest);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn byte_overrun_and_exhausted_source_are_mismatches_not_missing_evidence() {
    let events = [event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n")];
    let (_root, mut state) = state(&events, vec![rule()]);
    let error = request(&mut state, "APPEND", &[b"content:1", b"abc"]).unwrap_err();
    let diagnostic = serde_json::to_value(error).unwrap();
    assert_eq!(diagnostic["kind"], "redis_append_stream_mismatch");
    assert_eq!(diagnostic["source_offset"], 0);
    assert_eq!(diagnostic["source_bytes_remaining"], 2);
    assert_eq!(diagnostic["first_difference_offset"], 2);
    assert_eq!(diagnostic["next_source"]["sequence"], 1);
    assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Available);
    let good = request(&mut state, "APPEND", &[b"content:1", b"ab"]).unwrap();
    state.complete_exchange(&good);
    assert!(state.append_streams.profiles[0].bytes.is_empty());
    let error = request(&mut state, "APPEND", &[b"content:1", b"x"]).unwrap_err();
    let diagnostic = serde_json::to_value(error).unwrap();
    assert_eq!(diagnostic["kind"], "redis_append_stream_mismatch");
    assert_eq!(diagnostic["source_offset"], 2);
    assert_eq!(diagnostic["source_bytes_remaining"], 0);
    assert_eq!(diagnostic["first_difference_offset"], 2);
    assert!(diagnostic["next_source"].is_null());
    assert_eq!(state.snapshot().matched_count, 1);
}

#[test]
fn unavailable_append_source_evidence_keeps_its_original_classification() {
    let error = diagnostic(anyhow::anyhow!("Source accesses overlap"));
    let diagnostic = serde_json::to_value(error).unwrap();
    assert_eq!(diagnostic["kind"], "evidence_unavailable");
    assert!(
        diagnostic["reason"]
            .as_str()
            .unwrap()
            .contains("Source accesses overlap")
    );
}

#[test]
fn reads_and_resets_fence_bytes_while_expiry_keeps_ordinary_finite_matching() {
    let events = [
        event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
        event(2, "EXPIRE", &[b"content:1", b"3600"], b":1\r\n"),
        event(3, "GET", &[b"content:1"], b"$2\r\nab\r\n"),
        event(4, "APPEND", &[b"content:1", b"cd"], b":4\r\n"),
        event(5, "DEL", &[b"content:1"], b":1\r\n"),
        event(6, "APPEND", &[b"content:1", b"x"], b":1\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"abcd"]).is_err());
    let a = request(&mut state, "APPEND", &[b"content:1", b"ab"]).unwrap();
    state.complete_exchange(&a);
    assert!(request(&mut state, "EXPIRE", &[b"content:1", b"3601"]).is_err());
    let a = request(&mut state, "EXPIRE", &[b"content:1", b"3600"]).unwrap();
    state.complete_exchange(&a);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"cd"]).is_err());
    let a = request(&mut state, "GET", &[b"content:1"]).unwrap();
    state.complete_exchange(&a);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"cdx"]).is_err());
    let a = request(&mut state, "APPEND", &[b"content:1", b"cd"]).unwrap();
    state.complete_exchange(&a);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"x"]).is_err());
    let a = request(&mut state, "DEL", &[b"content:1"]).unwrap();
    state.complete_exchange(&a);
    let a = request(&mut state, "APPEND", &[b"content:1", b"x"]).unwrap();
    assert_eq!(a.response, b":1\r\n");
    state.complete_exchange(&a);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn successful_reset_keeps_its_exact_initial_value() {
    let events = [
        event(1, "SET", &[b"content:1", b"prefix"], b"+OK\r\n"),
        event(2, "APPEND", &[b"content:1", b"ab"], b":8\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"a"]).is_err());
    let set = request(&mut state, "SET", &[b"content:1", b"prefix"]).unwrap();
    state.complete_exchange(&set);
    let a = request(&mut state, "APPEND", &[b"content:1", b"a"]).unwrap();
    assert_eq!(a.response, b":7\r\n");
    state.complete_exchange(&a);
    let a = request(&mut state, "APPEND", &[b"content:1", b"b"]).unwrap();
    assert_eq!(a.response, b":8\r\n");
    state.complete_exchange(&a);
}

#[test]
fn delivery_failure_never_consumes_pending_source_and_disables_stream() {
    let events = [event(1, "APPEND", &[b"content:1", b"abcd"], b":4\r\n")];
    let (_root, mut state) = state(&events, vec![rule()]);
    let a = request(&mut state, "APPEND", &[b"content:1", b"ab"]).unwrap();
    state.fail_exchange(&a, "closed transport".into());
    assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Failed);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"cd"]).is_err());
    assert_eq!(state.snapshot().unused_case.len(), 1);
}

#[test]
fn source_lengths_errors_transactions_and_mutations_do_not_gain_permissions() {
    for events in [
        vec![event(1, "APPEND", &[b"content:1", b"ab"], b":3\r\n")],
        vec![event(1, "APPEND", &[b"content:1", b"ab"], b"-ERR bad\r\n")],
        vec![
            event(1, "MULTI", &[], b"+OK\r\n"),
            event(2, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
        ],
        vec![
            event(1, "SETRANGE", &[b"content:1", b"0", b"x"], b":1\r\n"),
            event(2, "APPEND", &[b"content:1", b"ab"], b":3\r\n"),
        ],
    ] {
        let (_root, mut state) = state(&events, vec![rule()]);
        assert!(request(&mut state, "APPEND", &[b"content:1", b"ab"]).is_err());
        assert!(
            state
                .exchanges
                .iter()
                .all(|e| e.status == ReplayExchangeStatus::Available)
        );
    }
}

#[test]
fn missing_rule_other_api_resource_and_key_keep_exact_matching() {
    for scenario in ["absent", "api", "database", "username", "key"] {
        let mut declared = rule();
        match scenario {
            "api" => declared["match"]["api"] = json!("GET /tasks"),
            "database" => declared["match"]["resource"]["database"] = json!(1),
            "username" => declared["match"]["resource"]["username"] = json!("other"),
            "key" => declared["match"]["key"] = json!({"kind":"exact","value":"another"}),
            _ => (),
        }
        let events = [event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n")];
        let rules = if scenario == "absent" {
            vec![]
        } else {
            vec![declared]
        };
        let (_root, mut state) = state(&events, rules);
        assert!(
            request(&mut state, "APPEND", &[b"content:1", b"a"]).is_err(),
            "{scenario}"
        );
        let a = request(&mut state, "APPEND", &[b"content:1", b"ab"]).unwrap();
        state.complete_exchange(&a);
        assert!(state.snapshot().unused_case.is_empty());
    }
}

#[test]
fn pooled_connections_keep_one_ordered_stream_and_utf8_lengths_count_bytes() {
    let mut second = event(2, "APPEND", &[b"content:1", "好".as_bytes()], b":6\r\n");
    second["connection_id"] = json!(Uuid::new_v4());
    second["sequence"] = json!(1);
    let events = [
        event(1, "APPEND", &[b"content:1", "你".as_bytes()], b":3\r\n"),
        second,
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    let a = request(&mut state, "APPEND", &[b"content:1", "你好".as_bytes()]).unwrap();
    assert_eq!(a.response, b":6\r\n");
    state.complete_exchange(&a);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn mget_fences_every_selected_key_and_partial_out_of_order_delivery_stays_unconsumed() {
    let events = [
        event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
        event(2, "APPEND", &[b"content:2", b"xy"], b":2\r\n"),
        event(
            3,
            "MGET",
            &[b"content:1", b"content:2"],
            b"*2\r\n$2\r\nab\r\n$2\r\nxy\r\n",
        ),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    let a = request(&mut state, "APPEND", &[b"content:1", b"a"]).unwrap();
    let b = request(&mut state, "APPEND", &[b"content:1", b"b"]).unwrap();
    state.complete_exchange(&b);
    assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Responding);
    assert!(state.has_case_in_flight());
    state.complete_exchange(&a);
    assert!(!state.has_case_in_flight());
    assert!(request(&mut state, "MGET", &[b"content:1", b"content:2"]).is_err());
    let a = request(&mut state, "APPEND", &[b"content:2", b"xy"]).unwrap();
    state.complete_exchange(&a);
    let a = request(&mut state, "MGET", &[b"content:1", b"content:2"]).unwrap();
    state.complete_exchange(&a);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn reset_preserves_literal_bytes_even_when_ordinary_set_would_compare_json_semantically() {
    let events = [
        event(1, "SET", &[b"content:1", br#"{"a":1,"b":2}"#], b"+OK\r\n"),
        event(2, "APPEND", &[b"content:1", b"x"], b":14\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    assert!(request(&mut state, "SET", &[b"content:1", br#"{"b":2,"a":1}"#]).is_err());
    assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Available);
}

#[test]
fn a_global_or_foreign_case_touch_cannot_be_borrowed_by_an_append_rule() {
    for source in [ReplaySource::Case, ReplaySource::Global] {
        let events = [event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n")];
        let (_root, mut state) = state(&events, vec![rule()]);
        let other = event(2, "GET", &[b"content:1"], b"$-1\r\n");
        state
            .register_exchange(
                serde_json::from_value(other).unwrap(),
                source,
                if source == ReplaySource::Case {
                    Some("other")
                } else {
                    None
                },
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
        assert!(request(&mut state, "APPEND", &[b"content:1", b"ab"]).is_err());
        assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Available);
    }
}

#[test]
fn overlapping_source_accesses_and_other_authenticated_writers_are_rejected() {
    for scenario in ["writer", "read", "reset", "username"] {
        let mut other = match scenario {
            "writer" => event(2, "APPEND", &[b"content:1", b"cd"], b":4\r\n"),
            "reset" => event(2, "DEL", &[b"content:1"], b":1\r\n"),
            _ => event(2, "GET", &[b"content:1"], b"$2\r\nab\r\n"),
        };
        other["connection_id"] = json!(Uuid::new_v4());
        if scenario == "username" {
            other["username"] = json!("foreign");
        } else {
            other["request_started_at"] = json!("2020-01-01T00:00:00Z");
            other["sequence"] = json!(1);
        }
        let events = [event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n"), other];
        let (_root, mut state) = state(&events, vec![rule()]);
        assert!(
            request(&mut state, "APPEND", &[b"content:1", b"ab"]).is_err(),
            "{scenario}"
        );
    }
}

#[test]
fn stateful_source_lane_is_owned_by_one_target_connection_even_across_split_chunks() {
    let events = [
        event(1, "CLIENT", &[b"GETNAME"], b"$-1\r\n"),
        event(2, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    let owner = TargetConnection::default();
    let call = |state: &mut RedisReplayState, connection, bytes: &[u8]| {
        state.match_redis(
            Some("case"),
            &TargetKey {
                host: "redis.test".into(),
                port: 6379,
            },
            connection,
            2,
            0,
            None,
            "APPEND",
            &[b"content:1".to_vec(), bytes.to_vec()],
        )
    };
    let first = call(&mut state, owner, b"a").unwrap();
    assert!(first.requires_binding);
    state.complete_exchange(&first);
    assert!(call(&mut state, TargetConnection::default(), b"b").is_err());
    let second = call(
        &mut state,
        TargetConnection {
            bound: Some(first.connection_id),
            ..owner
        },
        b"b",
    )
    .unwrap();
    state.complete_exchange(&second);
    assert_eq!(state.exchanges[1].status, ReplayExchangeStatus::Consumed);
}

#[test]
fn declared_script_keys_preserve_fences_and_unproven_key_inventories_stay_conservative() {
    let args = |items: &[&[u8]]| items.iter().map(|v| v.to_vec()).collect::<Vec<_>>();
    assert!(!trace::touches(
        "EVALSHA",
        &args(&[b"digest", b"1", b"lock:1", b"token"]),
        b"content:1"
    ));
    assert!(trace::touches(
        "EVAL",
        &args(&[b"script", b"2", b"lock:1", b"content:1"]),
        b"content:1"
    ));
    for declaration in [b"0".as_slice(), b"-1", b"3", b"invalid"] {
        assert!(trace::touches(
            "EVAL",
            &args(&[b"script", declaration, b"lock:1"]),
            b"content:1"
        ));
    }
    assert!(!trace::touches(
        "SCRIPT",
        &args(&[b"LOAD", b"script"]),
        b"content:1"
    ));
    assert!(trace::touches(
        "SCRIPT",
        &args(&[b"DEBUG", b"yes"]),
        b"content:1"
    ));
    assert!(trace::touches(
        "UNRECOGNIZED",
        &args(&[b"other"]),
        b"content:1"
    ));
}

#[test]
fn prepared_inventory_cannot_gain_late_case_or_global_touches() {
    for source in [ReplaySource::Case, ReplaySource::Global] {
        let events = [event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n")];
        let (_root, mut state) = state(&events, vec![rule()]);
        state.prepare_append_case("case").unwrap();
        assert!(
            state
                .register_exchange(
                    serde_json::from_value(event(2, "GET", &[b"content:1"], b"$2\r\nab\r\n"))
                        .unwrap(),
                    source,
                    Some("other"),
                    &mut BTreeMap::new(),
                    &[],
                )
                .is_err()
        );
    }
}
