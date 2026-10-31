use super::*;
use crate::replay::redis::append::tests::{event, request, state};
use crate::replay::redis::observations::tests::refresh_rule;
use serde_json::{Value, json};

fn events() -> Vec<Value> {
    vec![
        event(
            1,
            "SET",
            &[b"content:marker", b"block", b"EX", b"60"],
            b"+OK\r\n",
        ),
        event(2, "GET", &[b"content:marker"], b"$5\r\nblock\r\n"),
        event(3, "EXPIRE", &[b"content:marker", b"60"], b":1\r\n"),
        event(4, "DEL", &[b"content:marker"], b":1\r\n"),
    ]
}

fn perform(s: &mut RedisReplayState, command: &str, args: &[&[u8]]) {
    let m = request(s, command, args).unwrap();
    s.complete_exchange(&m);
}

fn create(s: &mut RedisReplayState) {
    perform(s, "SET", &[b"content:marker", b"block", b"EX", b"60"]);
}

#[test]
fn initial_expiry_covers_refresh_only_after_real_read_and_delete_delivery() {
    let (_root, mut s) = state(&events(), vec![refresh_rule()]);
    create(&mut s);
    perform(&mut s, "GET", &[b"content:marker"]);
    assert!(!s.exchanges[2].status.is_consumed());
    let deletion = request(&mut s, "DEL", &[b"content:marker"]).unwrap();
    assert!(
        !s.exchanges[2].status.is_consumed(),
        "admission is not delivery"
    );
    s.complete_exchange(&deletion);
    assert!(s.snapshot().unused_case.is_empty());
    let audit = serde_json::to_value(&s.observations.audits).unwrap();
    assert_eq!(audit[0]["coverage"]["kind"], "initial_expiry_until_delete");
    assert_eq!(audit[0]["coverage"]["source_deletion"]["sequence"], 4);
    assert_eq!(audit[0]["source_witness"]["sequence"], 3);
    assert_eq!(audit[0]["covered_source_observations"], 1);
    assert!(!audit.to_string().contains("content:marker"));
}

#[test]
fn open_lifetimes_and_missing_reads_do_not_gain_refresh_coverage() {
    let (_root, mut s) = state(&events(), vec![refresh_rule()]);
    create(&mut s);
    if let Ok(deletion) = request(&mut s, "DEL", &[b"content:marker"]) {
        s.complete_exchange(&deletion);
    }
    assert!(!s.exchanges[1].status.is_consumed());
    assert!(!s.exchanges[2].status.is_consumed());
    let mut trace = events();
    trace.pop();
    let (_root, mut s) = state(&trace, vec![refresh_rule()]);
    create(&mut s);
    perform(&mut s, "GET", &[b"content:marker"]);
    assert!(!s.exchanges[2].status.is_consumed());
}

#[test]
fn wrong_target_ttl_options_or_missing_creation_cannot_borrow_a_refresh() {
    for args in [
        vec![b"content:marker".as_slice(), b"block", b"EX", b"61"],
        vec![b"content:marker".as_slice(), b"block"],
        vec![b"content:marker".as_slice(), b"block", b"EX", b"60", b"NX"],
    ] {
        let (_root, mut s) = state(&events(), vec![refresh_rule()]);
        assert!(request(&mut s, "SET", &args).is_err());
        assert!(!s.exchanges[2].status.is_consumed());
    }
}

#[test]
fn bare_set_different_ttl_or_aggregate_delete_keeps_refresh_finite() {
    for variant in 0..3 {
        let mut trace = events();
        match variant {
            0 => {
                trace[0] = event(1, "SET", &[b"content:marker", b"block"], b"+OK\r\n");
            }
            1 => {
                trace[0] = event(
                    1,
                    "SET",
                    &[b"content:marker", b"block", b"EX", b"120"],
                    b"+OK\r\n",
                );
            }
            _ => {
                trace[3] = event(4, "DEL", &[b"content:marker", b"other"], b":1\r\n");
            }
        }
        let (_root, mut s) = state(&trace, vec![refresh_rule()]);
        for e in [&trace[0], &trace[1], &trace[3]] {
            let args = e["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| crate::api_trigger::decode(v).unwrap())
                .collect::<Vec<_>>();
            perform(
                &mut s,
                e["command"].as_str().unwrap(),
                &args.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            );
        }
        assert!(!s.exchanges[2].status.is_consumed());
    }
}

#[test]
fn actual_transport_failure_or_pending_read_never_becomes_omission_success() {
    for failure in ["SET", "GET", "DEL", "EXPIRE"] {
        let (_root, mut s) = state(&events(), vec![refresh_rule()]);
        let m = request(&mut s, "SET", &[b"content:marker", b"block", b"EX", b"60"]).unwrap();
        if failure == "SET" {
            s.fail_exchange(&m, "transport failed".into());
        } else {
            s.complete_exchange(&m);
        }
        for command in ["GET", "EXPIRE", "DEL"] {
            if command == "EXPIRE" && failure != "EXPIRE" {
                continue;
            }
            let args: &[&[u8]] = if command == "EXPIRE" {
                &[b"content:marker", b"60"]
            } else {
                &[b"content:marker"]
            };
            if let Ok(m) = request(&mut s, command, args) {
                if command == failure {
                    s.fail_exchange(&m, "transport failed".into());
                } else {
                    s.complete_exchange(&m);
                }
            }
        }
        assert!(!s.exchanges[2].status.is_consumed(), "failed {failure}");
        assert!(s.case_is_dirty("case"));
    }
    let (_root, mut s) = state(&events(), vec![refresh_rule()]);
    create(&mut s);
    let read = request(&mut s, "GET", &[b"content:marker"]).unwrap();
    perform(&mut s, "DEL", &[b"content:marker"]);
    assert!(!s.exchanges[2].status.is_consumed());
    s.fail_exchange(&read, "read failed after delete".into());
    assert!(!s.exchanges[2].status.is_consumed());
}

#[test]
fn a_repeated_read_with_an_already_consumed_witness_still_blocks_closure_credit() {
    for fails in [false, true] {
        let mut read = crate::replay::redis::observations::tests::read_rule(true);
        read["match"]["key"]["prefix"] = json!("content:");
        let (_root, mut s) = state(&events(), vec![refresh_rule(), read]);
        create(&mut s);
        perform(&mut s, "GET", &[b"content:marker"]);
        assert!(s.exchanges[1].status.is_consumed());
        let pending = request(&mut s, "GET", &[b"content:marker"]).unwrap();
        perform(&mut s, "DEL", &[b"content:marker"]);
        assert!(!s.exchanges[2].status.is_consumed());
        if fails {
            s.fail_exchange(&pending, "repeated read delivery failed".into());
        } else {
            s.complete_exchange(&pending);
        }
        assert_eq!(s.exchanges[2].status.is_consumed(), !fails);
        assert_eq!(s.case_is_dirty("case"), fails);
    }
}

#[tokio::test(start_paused = true)]
async fn deletion_at_the_initial_ttl_deadline_cannot_cover_refresh() {
    for delay in [59, 60, 61] {
        let (_root, mut s) = state(&events(), vec![refresh_rule()]);
        create(&mut s);
        perform(&mut s, "GET", &[b"content:marker"]);
        tokio::time::advance(Duration::from_secs(delay)).await;
        perform(&mut s, "DEL", &[b"content:marker"]);
        assert_eq!(s.exchanges[2].status.is_consumed(), delay < 60);
    }
}

#[test]
fn reconstruction_and_later_lifetimes_cannot_cover_an_unclosed_earlier_state() {
    let mut trace = events();
    trace[3] = event(
        4,
        "SET",
        &[b"content:marker", b"next", b"PX", b"60000"],
        b"+OK\r\n",
    );
    trace.extend([
        event(5, "EXPIRE", &[b"content:marker", b"60"], b":1\r\n"),
        event(6, "DEL", &[b"content:marker"], b":1\r\n"),
    ]);
    let (_root, mut s) = state(&trace, vec![refresh_rule()]);
    create(&mut s);
    perform(&mut s, "GET", &[b"content:marker"]);
    perform(
        &mut s,
        "SET",
        &[b"content:marker", b"next", b"PX", b"60000"],
    );
    perform(&mut s, "DEL", &[b"content:marker"]);
    assert!(!s.exchanges[2].status.is_consumed());
    assert!(s.exchanges[4].status.is_consumed());
}

#[test]
fn source_expiry_observers_foreign_writers_or_inconsistent_reads_grant_no_omission() {
    for observer in ["TTL", "PTTL"] {
        let mut trace = events();
        trace.insert(2, event(2, observer, &[b"content:marker"], b":60\r\n"));
        for (index, event) in trace.iter_mut().enumerate() {
            event["sequence"] = json!(index + 1);
            event["timestamp"] = json!(format!("2020-01-01T00:00:{:02}Z", index + 1));
            event["request_started_at"] = event["timestamp"].clone();
        }
        let (_root, mut s) = state(&trace, vec![refresh_rule()]);
        let error = s.prepare_observations("case").unwrap_err();
        assert!(format!("{error:#}").contains("expiry observation"));
        assert!(s.observations.profiles.is_empty());
    }
    let mut trace = events();
    trace[1]["response"]["data"] = json!(STANDARD.encode(b"$5\r\nother\r\n"));
    let (_root, mut s) = state(&trace, vec![refresh_rule()]);
    s.prepare_observations("case").unwrap();
    assert!(s.observations.profiles[0].closed_expiry.is_empty());
    let (_root, mut s) = state(&events(), vec![refresh_rule()]);
    s.exchanges[1].source = ReplaySource::Startup;
    assert!(s.prepare_observations("case").is_err());
}
