use super::*;
use crate::protocols::replay::redis::append::tests::{event, request, state};
use crate::protocols::replay::redis::observations::tests::refresh_rule;
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
        event(3, "DEL", &[b"content:marker"], b":1\r\n"),
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
fn source_without_expire_admits_exact_refreshes_and_keeps_every_finite_dependency() {
    let (_root, mut s) = state(&events(), vec![refresh_rule()]);
    create(&mut s);
    for _ in 0..2 {
        let m = request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).unwrap();
        assert_eq!(m.response, b":1\r\n");
        s.complete_exchange(&m);
    }
    assert_eq!(s.exchanges.len(), 3, "never manufacture a Source EXPIRE");
    assert!(s.case_is_dirty("case"));
    assert!(!s.exchanges[1].status.is_consumed());
    assert!(!s.exchanges[2].status.is_consumed());
    perform(&mut s, "GET", &[b"content:marker"]);
    perform(&mut s, "DEL", &[b"content:marker"]);
    assert!(!s.case_is_dirty("case"));
    assert!(request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).is_err());
    let report = serde_json::to_value(s.snapshot()).unwrap();
    let audits = report["state_observations"].as_array().unwrap();
    assert_eq!(audits.len(), 2);
    assert_eq!(audits[0]["source_witness"]["command"], "SET");
    assert_eq!(audits[0]["covered_source_observations"], 0);
    assert_eq!(audits[0]["coverage"]["kind"], "initial_expiry_refresh");
    assert_eq!(audits[0]["coverage"]["source_deletion"]["sequence"], 3);
    assert_eq!(audits[0]["target_event_index"], 1);
    assert!(!report.to_string().contains("content:marker"));
}

#[test]
fn pending_creation_wrong_ttl_options_key_and_call_bound_do_not_gain_permission() {
    let (_root, mut s) = state(&events(), vec![refresh_rule()]);
    assert!(request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).is_err());
    let creation = request(&mut s, "SET", &[b"content:marker", b"block", b"EX", b"60"]).unwrap();
    assert!(request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).is_err());
    s.complete_exchange(&creation);
    for args in [
        vec![b"content:marker".as_slice(), b"61"],
        vec![b"content:marker", b"60", b"NX"],
        vec![b"content:other", b"60"],
        vec![b"content:marker", b"060"],
    ] {
        assert!(request(&mut s, "EXPIRE", &args).is_err());
    }
    s.observations.calls.insert("case".into(), MAX_CALLS);
    assert!(request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).is_err());
    assert_eq!(s.observations.in_flight.len(), 0);
}

#[test]
fn absent_permission_and_foreign_scope_keep_refresh_unmatched() {
    for variant in ["none", "case", "endpoint", "database", "user", "protocol"] {
        let rules = if variant == "none" {
            vec![]
        } else {
            vec![refresh_rule()]
        };
        let (_root, mut s) = state(&events(), rules);
        create(&mut s);
        let result = s.match_redis(
            Some(if variant == "case" { "other" } else { "case" }),
            &TargetKey {
                host: if variant == "endpoint" {
                    "other"
                } else {
                    "redis.test"
                }
                .into(),
                port: 6379,
            },
            TargetConnection::default(),
            if variant == "protocol" { 3 } else { 2 },
            i64::from(variant == "database"),
            (variant == "user").then_some("other"),
            "EXPIRE",
            &[b"content:marker".to_vec(), b"60".to_vec()],
        );
        assert!(result.is_err(), "{variant}");
        assert!(s.observations.in_flight.is_empty());
    }
}

#[test]
fn missing_or_ambiguous_source_proof_retains_finite_matching_without_extra_refreshes() {
    for variant in [
        "bare",
        "open",
        "aggregate",
        "read",
        "mutation",
        "ttl",
        "clock",
        "foreign",
    ] {
        let mut trace = events();
        match variant {
            "bare" => trace[0] = event(1, "SET", &[b"content:marker", b"block"], b"+OK\r\n"),
            "open" => {
                trace.pop();
            }
            "aggregate" => trace[2] = event(3, "DEL", &[b"content:marker", b"other"], b":1\r\n"),
            "read" => trace[1] = event(2, "GET", &[b"content:marker"], b"$5\r\nother\r\n"),
            "mutation" => trace[1] = event(2, "APPEND", &[b"content:marker", b"x"], b":6\r\n"),
            "ttl" => trace[1] = event(2, "TTL", &[b"content:marker"], b":59\r\n"),
            "clock" => {
                trace[2]["timestamp"] = json!("2020-01-01T00:01:01Z");
                trace[2]["request_started_at"] = trace[2]["timestamp"].clone();
            }
            _ => trace[1]["username"] = json!("other"),
        }
        let (_root, mut s) = state(&trace, vec![refresh_rule()]);
        let args = trace[0]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| crate::api_trigger::decode(v).unwrap())
            .collect::<Vec<_>>();
        perform(
            &mut s,
            "SET",
            &args.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        );
        assert!(
            request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).is_err(),
            "{variant}"
        );
        assert!(s.observations.profiles.is_empty(), "{variant}");
    }
}

#[test]
fn pending_or_failed_refresh_delivery_cannot_certify_a_closed_case() {
    for fails in [false, true] {
        let (_root, mut s) = state(&events(), vec![refresh_rule()]);
        create(&mut s);
        let refresh = request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).unwrap();
        perform(&mut s, "GET", &[b"content:marker"]);
        perform(&mut s, "DEL", &[b"content:marker"]);
        assert!(s.case_is_dirty("case"), "pending real delivery");
        if fails {
            s.fail_exchange(&refresh, "transport failed".into());
        } else {
            s.complete_exchange(&refresh);
        }
        assert_eq!(s.case_is_dirty("case"), fails);
    }
}

#[tokio::test(start_paused = true)]
async fn refresh_or_closure_at_original_ttl_deadline_stays_dirty() {
    for delay in [59, 60, 61] {
        let (_root, mut s) = state(&events(), vec![refresh_rule()]);
        create(&mut s);
        perform(&mut s, "EXPIRE", &[b"content:marker", b"60"]);
        perform(&mut s, "GET", &[b"content:marker"]);
        tokio::time::advance(Duration::from_secs(delay)).await;
        assert_eq!(
            request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).is_ok(),
            delay < 60
        );
        // A separate fixture proves closure without leaving a probe in flight.
        let (_root, mut s) = state(&events(), vec![refresh_rule()]);
        create(&mut s);
        perform(&mut s, "EXPIRE", &[b"content:marker", b"60"]);
        perform(&mut s, "GET", &[b"content:marker"]);
        tokio::time::advance(Duration::from_secs(delay)).await;
        perform(&mut s, "DEL", &[b"content:marker"]);
        assert!(s.snapshot().unused_case.is_empty());
        assert_eq!(s.case_is_dirty("case"), delay >= 60);
        assert_eq!(s.snapshot().case_is_dirty("case"), delay >= 60);
    }
}

#[test]
fn a_future_closed_lifetime_cannot_supply_an_earlier_refresh() {
    let mut trace = events();
    trace[2] = event(
        3,
        "SET",
        &[b"content:marker", b"next", b"EX", b"60"],
        b"+OK\r\n",
    );
    trace.push(event(4, "GET", &[b"content:marker"], b"$4\r\nnext\r\n"));
    trace.push(event(5, "DEL", &[b"content:marker"], b":1\r\n"));
    let (_root, mut s) = state(&trace, vec![refresh_rule()]);
    create(&mut s);
    assert!(request(&mut s, "EXPIRE", &[b"content:marker", b"60"]).is_err());
    perform(&mut s, "GET", &[b"content:marker"]);
    perform(&mut s, "SET", &[b"content:marker", b"next", b"EX", b"60"]);
    perform(&mut s, "EXPIRE", &[b"content:marker", b"60"]);
    perform(&mut s, "GET", &[b"content:marker"]);
    perform(&mut s, "DEL", &[b"content:marker"]);
    assert!(!s.case_is_dirty("case"));
}

#[test]
fn native_source_preflight_counts_real_closed_lifetime_instead_of_inventing_expire() {
    let events = events();
    let compiled = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v3","rules":[refresh_rule()]}).to_string(),
    )
    .and_then(|p| crate::policy::compile_policy(&p))
    .unwrap();
    let (root, _state) = state(&events, vec![refresh_rule()]);
    let dir = root.path().join("case");
    let request: Value =
        serde_json::from_slice(&std::fs::read(dir.join("request.json")).unwrap()).unwrap();
    let checked = crate::policy::runtime::validate_native_source_dependencies(
        &compiled,
        &BTreeSet::from(["ttl-refresh".into()]),
        root.path(),
        &[crate::policy::runtime::NativeSourceCase {
            id: "case",
            dir: &dir,
            request: &request,
            events: &events,
        }],
    )
    .unwrap();
    assert_eq!(checked.rules["ttl-refresh"], 1);
}
