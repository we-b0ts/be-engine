use super::super::append::tests::{event, request, rule as append_rule, state};
use super::*;
use serde_json::{Value, json};
mod applicability;
mod case_scope;
mod foreign_reads;
mod pooled_order;
mod provisional_keys;

#[test]
fn concurrent_identity_reads_retain_their_state_transition_causal_fence() {
    let mut events = vec![
        event(1, "SET", &[b"current:1", b"old"], b"+OK\r\n"),
        event(2, "GET", &[b"current:1"], b"$3\r\nold\r\n"),
    ];
    events[0]["timestamp"] = json!("2020-01-01T00:00:02.500Z");
    events[1]["connection_id"] = json!(Uuid::from_u128(1));
    let (_root, mut state) = state(&events, vec![read_rule(true)]);
    assert!(state.prepare_observations("case").is_err());
    assert!(state.observations.profiles.is_empty());
}

pub(super) fn read_rule(epochs: bool) -> Value {
    let mut r = json!({"id":"current-state","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},"operation":"SET","key":{"kind":"affix","prefix":"current:"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
          "references":[{"resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0}}],
          "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1}]},
        "proof":{"source":"session.py:1","fact":"Source reads the current block identity and changes it only through SET and DEL"}});
    if epochs {
        r["effect"]["read_back"][0]["state_epochs"] = json!(true);
    }
    r
}

pub(in crate::replay::redis) fn refresh_rule() -> Value {
    json!({"id":"ttl-refresh","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},"operation":"EXPIRE","key":{"kind":"affix","prefix":"content:"}},
      "effect":{"kind":"redis_expiry_refresh"},"proof":{"source":"session.py:20","fact":"Every buffered append refreshes the same positive TTL; scheduling changes refresh counts without exposing expiry"}})
}

pub(super) fn perform(state: &mut RedisReplayState, command: &str, args: &[&[u8]]) -> Vec<u8> {
    let matched = request(state, command, args).unwrap();
    let response = matched.response.clone();
    state.complete_exchange(&matched);
    response
}

#[test]
fn split_append_companion_reads_and_refreshes_preserve_state_switches_and_bytes() {
    let events = [
        event(1, "GET", &[b"current:1"], b"$-1\r\n"),
        event(2, "SET", &[b"current:1", b"source"], b"+OK\r\n"),
        event(3, "GET", &[b"current:1"], b"$6\r\nsource\r\n"),
        event(4, "APPEND", &[b"content:1", b"abcdef"], b":6\r\n"),
        event(5, "EXPIRE", &[b"content:1", b"3600"], b":1\r\n"),
        event(6, "GET", &[b"current:1"], b"$6\r\nsource\r\n"),
        event(7, "DEL", &[b"current:1"], b":1\r\n"),
        event(8, "GET", &[b"current:1"], b"$-1\r\n"),
        event(9, "GET", &[b"content:1"], b"$6\r\nabcdef\r\n"),
    ];
    let (_root, mut s) = state(
        &events,
        vec![read_rule(true), append_rule(), refresh_rule()],
    );
    assert_eq!(perform(&mut s, "GET", &[b"current:1"]), b"$-1\r\n");
    perform(&mut s, "SET", &[b"current:1", b"target"]);
    assert_eq!(perform(&mut s, "GET", &[b"current:1"]), b"$6\r\ntarget\r\n");
    perform(&mut s, "APPEND", &[b"content:1", b"abc"]);
    perform(&mut s, "EXPIRE", &[b"content:1", b"3600"]);
    assert_eq!(perform(&mut s, "GET", &[b"current:1"]), b"$6\r\ntarget\r\n");
    perform(&mut s, "APPEND", &[b"content:1", b"def"]);
    perform(&mut s, "EXPIRE", &[b"content:1", b"3600"]);
    perform(&mut s, "DEL", &[b"current:1"]);
    assert_eq!(perform(&mut s, "GET", &[b"current:1"]), b"$-1\r\n");
    perform(&mut s, "GET", &[b"content:1"]);
    assert!(s.snapshot().unused_case.is_empty());
    assert_eq!(
        s.observations
            .audits
            .iter()
            .map(|e| e.covered_source_observations)
            .sum::<usize>(),
        5
    );
}

#[test]
fn unconfigured_read_back_keeps_finite_consumption() {
    let events = [
        event(1, "SET", &[b"current:1", b"old"], b"+OK\r\n"),
        event(2, "GET", &[b"current:1"], b"$3\r\nold\r\n"),
    ];
    let (_root, mut s) = state(&events, vec![read_rule(false)]);
    perform(&mut s, "SET", &[b"current:1", b"new"]);
    perform(&mut s, "GET", &[b"current:1"]);
    assert!(request(&mut s, "GET", &[b"current:1"]).is_err());
}

#[test]
fn state_changes_never_reuse_a_previous_or_future_value() {
    let events = [
        event(1, "GET", &[b"current:1"], b"$-1\r\n"),
        event(2, "SET", &[b"current:1", b"one"], b"+OK\r\n"),
        event(3, "GET", &[b"current:1"], b"$3\r\none\r\n"),
        event(4, "DEL", &[b"current:1"], b":1\r\n"),
        event(5, "SET", &[b"current:1", b"two"], b"+OK\r\n"),
        event(6, "GET", &[b"current:1"], b"$3\r\ntwo\r\n"),
    ];
    let (_root, mut s) = state(&events, vec![read_rule(true)]);
    perform(&mut s, "GET", &[b"current:1"]);
    perform(&mut s, "SET", &[b"current:1", b"aaa"]);
    assert_eq!(perform(&mut s, "GET", &[b"current:1"]), b"$3\r\naaa\r\n");
    perform(&mut s, "DEL", &[b"current:1"]);
    assert!(
        request(&mut s, "GET", &[b"current:1"]).is_err(),
        "no absent read witness between DEL and the next SET"
    );
    perform(&mut s, "SET", &[b"current:1", b"bbb"]);
    assert_eq!(perform(&mut s, "GET", &[b"current:1"]), b"$3\r\nbbb\r\n");
}

#[test]
fn source_inconsistency_or_ttl_observation_installs_no_permission() {
    for bad in [
        event(4, "GET", &[b"current:1"], b"$-1\r\n"),
        event(4, "TTL", &[b"current:1"], b":30\r\n"),
    ] {
        let events = [
            event(1, "GET", &[b"current:1"], b"$-1\r\n"),
            event(2, "SET", &[b"current:1", b"old"], b"+OK\r\n"),
            event(3, "GET", &[b"current:1"], b"$3\r\nold\r\n"),
            bad,
        ];
        let (_root, mut s) = state(&events, vec![read_rule(true)]);
        assert!(s.prepare_observations("case").is_err());
        assert!(s.exchanges.iter().all(|e| e.observation_rule.is_none()));
    }
}

#[test]
fn refresh_rejects_wrong_ttl_and_never_survives_deletion() {
    let events = [
        event(1, "APPEND", &[b"content:1", b"x"], b":1\r\n"),
        event(2, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
        event(3, "DEL", &[b"content:1"], b":1\r\n"),
    ];
    let (_root, mut s) = state(&events, vec![refresh_rule()]);
    assert!(request(&mut s, "EXPIRE", &[b"content:1", b"60"]).is_err());
    perform(&mut s, "APPEND", &[b"content:1", b"x"]);
    assert!(request(&mut s, "EXPIRE", &[b"content:1", b"61"]).is_err());
    perform(&mut s, "EXPIRE", &[b"content:1", b"60"]);
    perform(&mut s, "EXPIRE", &[b"content:1", b"60"]);
    perform(&mut s, "DEL", &[b"content:1"]);
    assert!(request(&mut s, "EXPIRE", &[b"content:1", b"60"]).is_err());
}

#[test]
fn delivery_failure_and_concurrent_requests_retain_real_in_flight_and_dirty_state() {
    let events = [
        event(1, "SET", &[b"current:1", b"old"], b"+OK\r\n"),
        event(2, "GET", &[b"current:1"], b"$3\r\nold\r\n"),
    ];
    let (_root, mut s) = state(&events, vec![read_rule(true)]);
    perform(&mut s, "SET", &[b"current:1", b"new"]);
    let a = request(&mut s, "GET", &[b"current:1"]).unwrap();
    let b = request(&mut s, "GET", &[b"current:1"]).unwrap();
    s.complete_exchange(&a);
    assert!(s.has_case_in_flight());
    let pending = s.case_in_flight_diagnostic();
    assert_eq!(pending["observations"]["count"], 1);
    assert_eq!(pending["observations"]["cases"][0], "case");
    assert!(!pending.to_string().contains("current:1"));
    assert!(!pending.to_string().contains("new"));
    s.fail_exchange(&b, "transport failed".into());
    assert!(!s.has_case_in_flight());
    assert_eq!(s.case_in_flight_diagnostic()["observations"]["count"], 0);
    assert!(s.case_is_dirty("case"));
    assert!(request(&mut s, "GET", &[b"current:1"]).is_err());
}

#[test]
fn merged_batches_cover_equivalent_reads_and_refreshes_but_require_an_observation_per_state() {
    let events = [
        event(1, "GET", &[b"current:1"], b"$-1\r\n"),
        event(2, "SET", &[b"current:1", b"old"], b"+OK\r\n"),
        event(3, "GET", &[b"current:1"], b"$3\r\nold\r\n"),
        event(4, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
        event(5, "EXPIRE", &[b"content:1", b"3600"], b":1\r\n"),
        event(6, "GET", &[b"current:1"], b"$3\r\nold\r\n"),
        event(7, "APPEND", &[b"content:1", b"cd"], b":4\r\n"),
        event(8, "EXPIRE", &[b"content:1", b"3600"], b":1\r\n"),
        event(9, "GET", &[b"content:1"], b"$4\r\nabcd\r\n"),
    ];
    let (_root, mut s) = state(
        &events,
        vec![read_rule(true), append_rule(), refresh_rule()],
    );
    // Skipping the initial absent observation never makes it an optional call.
    perform(&mut s, "SET", &[b"current:1", b"new"]);
    perform(&mut s, "GET", &[b"current:1"]);
    perform(&mut s, "APPEND", &[b"content:1", b"abcd"]);
    perform(&mut s, "EXPIRE", &[b"content:1", b"3600"]);
    perform(&mut s, "GET", &[b"content:1"]);
    let unused = s.snapshot().unused_case;
    assert_eq!(unused.len(), 1);
    assert_eq!(unused[0].sequence, 1);
    assert!(request(&mut s, "SET", &[b"current:1", b"another"]).is_err());
    assert!(request(&mut s, "APPEND", &[b"content:1", b"extra"]).is_err());
}

#[test]
fn foreign_inventory_unknown_writers_and_late_additions_cannot_extend_the_proof() {
    let base = [
        event(1, "SET", &[b"current:1", b"old"], b"+OK\r\n"),
        event(2, "GET", &[b"current:1"], b"$3\r\nold\r\n"),
    ];
    let mut overlap = base.to_vec();
    overlap.push(event(3, "GET", &[b"current:1"], b"$3\r\nold\r\n"));
    let (_root, mut s) = state(&overlap, vec![read_rule(true)]);
    s.exchanges[2].source = ReplaySource::Startup;
    assert!(s.prepare_observations("case").is_err());
    assert!(s.exchanges.iter().all(|e| e.observation_rule.is_none()));
    let mut events = base.to_vec();
    events.push(event(
        3,
        "GETSET",
        &[b"current:1", b"other"],
        b"$3\r\nold\r\n",
    ));
    let (_root, mut s) = state(&events, vec![read_rule(true)]);
    assert!(s.prepare_observations("case").is_err());
    let (_root, mut s) = state(&base, vec![read_rule(true)]);
    s.prepare_observations("case").unwrap();
    let extra = serde_json::from_value(event(3, "GET", &[b"current:1"], b"$3\r\nold\r\n")).unwrap();
    assert!(
        s.register_exchange(
            extra,
            ReplaySource::Case,
            Some("case"),
            &mut BTreeMap::new(),
            &[]
        )
        .is_err()
    );
}

#[test]
fn ttl_window_and_limits_reject_with_state_diagnostics() {
    let events = [
        event(1, "APPEND", &[b"content:1", b"x"], b":1\r\n"),
        event(2, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let (_root, mut s) = state(&events, vec![refresh_rule()]);
    perform(&mut s, "APPEND", &[b"content:1", b"x"]);
    s.observations
        .mutations_at
        .insert(0, chrono::Utc::now() - chrono::TimeDelta::seconds(61));
    let error = request(&mut s, "EXPIRE", &[b"content:1", b"60"]).unwrap_err();
    let error = serde_json::to_value(error).unwrap();
    assert_eq!(error["kind"], "redis_state_observation_mismatch");
    assert_eq!(error["source_epoch_mutation"]["sequence"], 1);
    s.observations.mutations_at.insert(0, chrono::Utc::now());
    s.observations.calls.insert("case".into(), MAX_CALLS);
    assert!(request(&mut s, "EXPIRE", &[b"content:1", b"60"]).is_err());
    assert!(!s.exchanges[1].status.is_consumed());
}

#[test]
fn a_nil_only_case_key_cannot_gain_a_write_or_a_future_identity() {
    let events = [
        event(1, "GET", &[b"current:1"], b"$-1\r\n"),
        event(2, "GET", &[b"current:1"], b"$-1\r\n"),
        event(3, "SET", &[b"current:2", b"old"], b"+OK\r\n"),
        event(4, "GET", &[b"current:2"], b"$3\r\nold\r\n"),
    ];
    let (_root, mut s) = state(&events, vec![read_rule(true)]);
    assert_eq!(perform(&mut s, "GET", &[b"current:1"]), b"$-1\r\n");
    assert_eq!(perform(&mut s, "GET", &[b"current:1"]), b"$-1\r\n");
    assert!(request(&mut s, "GET", &[b"current:1"]).is_err());
    assert!(request(&mut s, "SET", &[b"current:1", b"new"]).is_err());
    assert!(request(&mut s, "GET", &[b"current:2"]).is_err());
}

#[test]
fn state_observation_schema_is_closed_and_plan_proof_is_separate_from_runtime() {
    let compile = |r: Value| {
        crate::policy::parse_policy(&json!({"format":"traffic-policy/v3","rules":[r]}).to_string())
            .and_then(|p| crate::policy::compile_policy(&p))
    };
    let mut read = read_rule(true);
    read["effect"]["read_back"][0]["state_epochs"] = json!({"fact":""});
    assert!(compile(read).is_err());
    let mut read = read_rule(true);
    read["effect"]["capture"]["json_pointer"] = json!("/id");
    assert!(compile(read).is_err());
    let mut resource_rule = refresh_rule();
    resource_rule["match"]
        .as_object_mut()
        .unwrap()
        .remove("api");
    assert!(compile(resource_rule).is_ok());
    for pointer in ["/match/resource/database", "/match/key"] {
        let mut r = refresh_rule();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        r.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(compile(r).is_err());
    }
    let mut no_proof = refresh_rule();
    no_proof.as_object_mut().unwrap().remove("proof");
    assert!(compile(no_proof.clone()).is_ok());
    let document = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v3","rules":[no_proof]}).to_string(),
    )
    .unwrap();
    assert!(crate::policy::require_source_proofs(&document).is_err());
    let mut r = refresh_rule();
    r["effect"]["optional"] = json!(true);
    assert!(compile(r).is_err());
    let mut r = refresh_rule();
    r["match"]["operation"] = json!("GET");
    assert!(compile(r).is_err());
}
