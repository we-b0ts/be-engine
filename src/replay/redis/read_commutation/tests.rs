//! Capability boundaries preserve finite reads and strict unrelated writes.
use super::*;
use crate::replay::redis::append::tests::event;
use crate::replay::report::command::CommandMatchDiagnostic;
use serde_json::{Value, json};

pub(in crate::replay::redis) fn rule() -> Value {
    json!({"id":"poll","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},
        "operation":"GET","key":{"kind":"numeric","prefix":"cancel:"}},
        "effect":{"kind":"redis_read_commutation"},"proof":{"source":"poller.py:1; flush.py:2",
        "fact":"Independent cancellation polling races with delayed writes; nil observations have no ordering relation to unrelated keys, and each read remains required"}})
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
fn reads_commute_both_directions_but_counts_and_writes_stay_finite() {
    let events = [
        event(1, "SET", &[b"content:1", b"x"], b"+OK\r\n"),
        event(2, "GET", &[b"cancel:1"], b"$-1\r\n"),
        event(3, "EXPIRE", &[b"content:1", b"3600"], b":1\r\n"),
        event(4, "GET", &[b"cancel:1"], b"$-1\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    // A read can arrive before the first unrelated write.
    let read = request(&mut state, "GET", &[b"cancel:1"]).unwrap();
    assert_eq!(read.index, 1);
    assert_eq!(read.rule_ids, vec!["poll"]);
    assert_eq!(read.response, b"$-1\r\n");
    state.complete_exchange(&read);
    assert!(request(&mut state, "EXPIRE", &[b"content:1", b"3600"]).is_err());
    let write = request(&mut state, "SET", &[b"content:1", b"x"]).unwrap();
    state.complete_exchange(&write);
    // The second read is still required, but never fences unrelated writes.
    let expiry = request(&mut state, "EXPIRE", &[b"content:1", b"3600"]).unwrap();
    state.complete_exchange(&expiry);
    assert_eq!(state.snapshot().unused_case.len(), 1);
    let read = request(&mut state, "GET", &[b"cancel:1"]).unwrap();
    state.complete_exchange(&read);
    assert!(state.snapshot().unused_case.is_empty());
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    assert!(request(&mut state, "GET", &[b"cancel:2"]).is_err());
}

#[test]
fn changed_values_mutations_and_unknown_key_effects_never_install_partial_permission() {
    for bad in [
        event(3, "GET", &[b"cancel:2"], b"$4\r\ntrue\r\n"),
        event(3, "SET", &[b"cancel:1", b"true"], b"+OK\r\n"),
        event(3, "DEL", &[b"cancel:1"], b":1\r\n"),
        event(3, "EVAL", &[b"return nil", b"0"], b"$-1\r\n"),
        event(3, "FLUSHDB", &[], b"+OK\r\n"),
        event(3, "MGET", &[b"cancel:1", b"other"], b"*2\r\n$-1\r\n$-1\r\n"),
    ] {
        let events = [
            event(1, "GET", &[b"cancel:1"], b"$-1\r\n"),
            event(2, "GET", &[b"cancel:2"], b"$-1\r\n"),
            bad,
        ];
        let (_root, mut state) = state(&events, vec![rule()]);
        assert!(state.prepare_read_commutation("case").is_err());
        assert!(
            state
                .exchanges
                .iter()
                .all(|e| e.read_commutation_rule.is_none() && e.status.is_available())
        );
        assert!(state.read_commutation.profiles.is_empty());
    }
}

#[test]
fn no_op_cleanup_stays_ordered_and_delivery_failure_remains_dirty() {
    let events = [
        event(1, "DEL", &[b"cancel:1"], b":0\r\n"),
        event(2, "GET", &[b"cancel:1"], b"$-1\r\n"),
        event(3, "SET", &[b"other", b"x"], b"+OK\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    assert!(request(&mut state, "SET", &[b"other", b"x"]).is_err());
    let read = request(&mut state, "GET", &[b"cancel:1"]).unwrap();
    state.fail_exchange(&read, "client closed".into());
    assert!(state.snapshot().is_dirty());
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    let cleanup = request(&mut state, "DEL", &[b"cancel:1"]).unwrap();
    state.complete_exchange(&cleanup);
    assert!(request(&mut state, "SET", &[b"other", b"x"]).is_ok());
}

#[test]
fn missing_rule_other_api_and_other_resource_keep_lane_order() {
    for change in ["none", "api", "endpoint", "database", "username", "key"] {
        let mut rule = rule();
        let events = [
            event(1, "GET", &[b"cancel:1"], b"$-1\r\n"),
            event(2, "SET", &[b"other", b"x"], b"+OK\r\n"),
        ];
        match change {
            "api" => rule["match"]["api"] = json!("POST /other"),
            "endpoint" => rule["match"]["resource"]["endpoint"] = json!("elsewhere.test:6379"),
            "database" => rule["match"]["resource"]["database"] = json!(1),
            "username" => rule["match"]["resource"]["username"] = json!("other"),
            "key" => rule["match"]["key"]["prefix"] = json!("another:"),
            _ => (),
        }
        let (_root, mut state) = state(&events, if change == "none" { vec![] } else { vec![rule] });
        assert!(
            request(&mut state, "SET", &[b"other", b"x"]).is_err(),
            "{change}"
        );
    }
}

#[test]
fn foreign_global_transactional_and_late_inventory_cannot_borrow_proof() {
    for foreign in [ReplaySource::Case, ReplaySource::Global] {
        let (_root, mut state) =
            state(&[event(1, "GET", &[b"cancel:1"], b"$-1\r\n")], vec![rule()]);
        state
            .register_exchange(
                serde_json::from_value(event(2, "GET", &[b"cancel:1"], b"$-1\r\n")).unwrap(),
                foreign,
                Some("foreign"),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
        assert!(state.prepare_read_commutation("case").is_err());
    }
    let events = [
        event(1, "WATCH", &[b"other"], b"+OK\r\n"),
        event(2, "GET", &[b"cancel:1"], b"$-1\r\n"),
    ];
    let (_root, mut transaction) = state(&events, vec![rule()]);
    assert!(transaction.prepare_read_commutation("case").is_err());
    let (_root, mut prepared) = state(&events[1..], vec![rule()]);
    prepared.prepare_read_commutation("case").unwrap();
    assert!(
        prepared
            .register_exchange(
                serde_json::from_value(event(3, "SET", &[b"other", b"x"], b"+OK\r\n")).unwrap(),
                ReplaySource::Case,
                Some("case"),
                &mut BTreeMap::new(),
                &[]
            )
            .is_err()
    );
    assert!(
        prepared
            .register_exchange(
                serde_json::from_value(event(3, "SET", &[b"cancel:1", b"true"], b"+OK\r\n"))
                    .unwrap(),
                ReplaySource::Global,
                None,
                &mut BTreeMap::new(),
                &[]
            )
            .is_err()
    );
}
