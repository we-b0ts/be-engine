use super::*;
use crate::replay::redis::append::tests::state_with_policy;

fn global_state(events: &[Value]) -> (tempfile::TempDir, RedisReplayState) {
    let mut rule = read_rule(true);
    rule["match"].as_object_mut().unwrap().remove("resource");
    rule["match"].as_object_mut().unwrap().remove("api");
    rule["effect"]["references"] = json!([]);
    state_with_policy(
        events,
        json!({"format":"traffic-policy/v2","redis":{"keys":{
        "current:*":{"kind":"identity","formats":["string"]}}},"rules":[rule]}),
    )
}

#[test]
fn historical_only_reads_stay_finite_without_inventing_a_write_epoch() {
    for response in [b"$3\r\nold\r\n".as_slice(), b"$-1\r\n".as_slice()] {
        let events = [
            event(1, "GET", &[b"current:1"], response),
            event(2, "GET", &[b"current:1"], response),
        ];
        let (_root, mut state) = global_state(&events);
        state.prepare_observations("case").unwrap();
        assert!(state.observations.profiles.is_empty());
        assert!(
            state
                .exchanges
                .iter()
                .all(|exchange| exchange.observation_rule.is_none())
        );
        assert_eq!(perform(&mut state, "GET", &[b"current:1"]), response);
        assert_eq!(perform(&mut state, "GET", &[b"current:1"]), response);
        assert!(request(&mut state, "GET", &[b"current:1"]).is_err());
        let new_write =
            serde_json::from_value(event(3, "SET", &[b"current:1", b"new"], b"+OK\r\n")).unwrap();
        assert!(
            state
                .register_exchange(
                    new_write,
                    ReplaySource::Case,
                    Some("case"),
                    &mut BTreeMap::new(),
                    &[]
                )
                .is_err()
        );
    }
}

#[test]
fn a_historical_read_followed_by_a_write_without_a_read_witness_stays_finite() {
    let mut events = prefixed_events();
    events.pop();
    let (_root, mut state) = global_state(&events);
    assert_eq!(
        perform(&mut state, "GET", &[b"current:1"]),
        b"$3\r\nold\r\n"
    );
    perform(&mut state, "SET", &[b"current:1", b"target"]);
    assert!(state.observations.profiles.is_empty());
    assert!(request(&mut state, "GET", &[b"current:1"]).is_err());
}

fn prefixed_events() -> Vec<Value> {
    let prefix = event(1, "GET", &[b"current:1"], b"$3\r\nold\r\n");
    let mut write = event(2, "SET", &[b"current:1", b"source"], b"+OK\r\n");
    let mut read = event(3, "GET", &[b"current:1"], b"$6\r\nsource\r\n");
    write["connection_id"] = json!(Uuid::from_u128(2));
    read["connection_id"] = json!(Uuid::from_u128(2));
    vec![prefix, write, read]
}

#[test]
fn historical_prefix_must_deliver_before_a_pooled_set_establishes_virtual_reads() {
    let (_root, mut state) = global_state(&prefixed_events());
    assert!(request(&mut state, "SET", &[b"current:1", b"target"]).is_err());
    assert_eq!(state.observations.profiles[0].finite_prefix, vec![0]);
    assert!(state.exchanges[0].observation_rule.is_none());
    let prefix = request(&mut state, "GET", &[b"current:1"]).unwrap();
    assert!(
        prefix.observation.is_none(),
        "historical state is an ordinary finite read"
    );
    assert_eq!(prefix.response, b"$3\r\nold\r\n");
    assert!(
        request(&mut state, "SET", &[b"current:1", b"target"]).is_err(),
        "a claimed but undelivered prefix cannot authorize the write"
    );
    state.complete_exchange(&prefix);
    assert!(
        request(&mut state, "GET", &[b"current:1"]).is_err(),
        "a future epoch cannot satisfy an extra prefix read"
    );
    perform(&mut state, "SET", &[b"current:1", b"target"]);
    for _ in 0..3 {
        assert_eq!(
            perform(&mut state, "GET", &[b"current:1"]),
            b"$6\r\ntarget\r\n"
        );
    }
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn prefix_support_preserves_expiry_writer_capture_and_cross_case_failures() {
    for change in [
        "writer",
        "prefix_writer",
        "ttl_observer",
        "bad_read",
        "cross_case",
        "bad_prefix",
        "overlap",
    ] {
        let mut events = prefixed_events();
        match change {
            "writer" => events.push(event(
                4,
                "GETSET",
                &[b"current:1", b"next"],
                b"$6\r\nsource\r\n",
            )),
            "prefix_writer" => {
                events[1]["timestamp"] = json!("2020-01-01T00:00:03Z");
                events[1]["request_started_at"] = json!("2020-01-01T00:00:03Z");
                events[1]["sequence"] = json!(3);
                events[2]["timestamp"] = json!("2020-01-01T00:00:04Z");
                events[2]["request_started_at"] = json!("2020-01-01T00:00:04Z");
                events[2]["sequence"] = json!(4);
                events.insert(
                    1,
                    event(2, "GETSET", &[b"current:1", b"other"], b"$3\r\nold\r\n"),
                );
            }
            "ttl_observer" => events.push(event(4, "TTL", &[b"current:1"], b":30\r\n")),
            "bad_read" => events[2] = event(3, "GET", &[b"current:1"], b"$-1\r\n"),
            _ => (),
        }
        for event in &mut events {
            if event["command"] == "GETSET" {
                event["response_kind"] = json!("bulk_string");
            }
        }
        let (_root, mut state) = global_state(&events);
        if change == "cross_case" {
            state.exchanges[2].case_id = Some("other-case".into());
        }
        if change == "bad_prefix" {
            state.exchanges[0].response = b"$3\r\nold".to_vec();
        }
        if change == "overlap" {
            state.exchanges[0].record.timestamp = Some("2020-01-01T00:00:10Z".parse().unwrap());
        }
        assert!(
            state.prepare_observations("case").is_err(),
            "accepted {change}"
        );
        assert!(
            state
                .exchanges
                .iter()
                .all(|exchange| exchange.observation_rule.is_none()),
            "failed Source proof cannot partially install permission"
        );
    }
    let mut events = prefixed_events();
    events[1] = event(
        2,
        "SET",
        &[b"current:1", b"source", b"EX", b"1"],
        b"+OK\r\n",
    );
    let (_root, mut state) = global_state(&events);
    assert!(
        state.prepare_observations("case").is_err(),
        "excluding the prefix cannot waive expiry during the owned lifetime"
    );
}
