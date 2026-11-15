//! Ordinary Case state and expiry witnesses never leak through a shared key.
use super::*;

fn fixture(own: &[Value], other: &[Value]) -> (tempfile::TempDir, RedisReplayState) {
    let root = tempfile::tempdir().unwrap();
    let policy = root.path().join("policy.yaml");
    let mut rule = refresh_rule();
    rule["match"].as_object_mut().unwrap().remove("api");
    std::fs::write(
        &policy,
        json!({"format":"traffic-policy/v3","rules":[rule]}).to_string(),
    )
    .unwrap();
    let mut cases = BTreeMap::new();
    for (case, events) in [("case", own), ("other", other)] {
        let dir = root.path().join(case);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("request.json"),
            json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"}).to_string(),
        )
        .unwrap();
        std::fs::write(dir.join("expected-response.json"), "{}").unwrap();
        std::fs::write(
            dir.join("dependencies.jsonl"),
            events
                .iter()
                .map(|event| format!("{event}\n"))
                .collect::<String>(),
        )
        .unwrap();
        cases.insert(
            case.into(),
            crate::replay::ReplayCase {
                id: case.into(),
                dependencies_path: dir.join("dependencies.jsonl"),
                dir,
                status: crate::replay::ReplayCaseStatus::Pending,
            },
        );
    }
    let runtime = crate::policy::runtime::ReplayPolicyRuntime::load(&policy, &cases).unwrap();
    let mut state = RedisReplayState {
        request_contracts: runtime.request_contracts.clone(),
        dynamic_values: runtime.dynamic_values.clone(),
        ..Default::default()
    };
    add(&mut state, "case", own);
    add(&mut state, "other", other);
    (root, state)
}

fn add(state: &mut RedisReplayState, case: &str, events: &[Value]) {
    for event in events {
        state
            .register_exchange(
                serde_json::from_value(event.clone()).unwrap(),
                ReplaySource::Case,
                Some(case),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
    }
}

fn request_in(
    state: &mut RedisReplayState,
    case: &str,
    command: &str,
    args: &[&[u8]],
) -> std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic> {
    state.match_redis(
        Some(case),
        &TargetKey {
            host: "redis.test".into(),
            port: 6379,
        },
        TargetConnection::default(),
        2,
        0,
        None,
        command,
        &args.iter().map(|arg| arg.to_vec()).collect::<Vec<_>>(),
    )
}

fn perform_in(state: &mut RedisReplayState, case: &str, command: &str, args: &[&[u8]]) {
    let matched = request_in(state, case, command, args).unwrap();
    state.complete_exchange(&matched);
}

#[test]
fn existing_key_refreshes_and_other_case_mutations_are_independent_when_loaded_eagerly_or_lazily() {
    let own = [
        event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
        event(2, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
        event(3, "DEL", &[b"content:1"], b":1\r\n"),
    ];
    let other = [
        event(
            4,
            "SET",
            &[b"content:1", b"other", b"EX", b"120"],
            b"+OK\r\n",
        ),
        event(5, "EXPIRE", &[b"content:1", b"120"], b":1\r\n"),
        event(6, "DEL", &[b"content:1"], b":1\r\n"),
    ];
    for lazy in [false, true] {
        let (_root, mut state) = fixture(&own, if lazy { &[] } else { &other });
        state.prepare_observations("case").unwrap();
        if lazy {
            add(&mut state, "other", &other);
        }
        assert!(state.exchanges[..2].iter().all(|e| !e.status.is_consumed()));
        perform_in(&mut state, "case", "EXPIRE", &[b"content:1", b"60"]);
        assert!(state.exchanges[..2].iter().all(|e| e.status.is_consumed()));
        assert!(state.exchanges[3..].iter().all(|e| !e.status.is_consumed()));

        state.request_contracts.begin_case("other");
        perform_in(
            &mut state,
            "other",
            "SET",
            &[b"content:1", b"other", b"EX", b"120"],
        );
        perform_in(&mut state, "other", "EXPIRE", &[b"content:1", b"120"]);
        perform_in(&mut state, "other", "DEL", &[b"content:1"]);
        state.request_contracts.begin_case("case");
        perform_in(&mut state, "case", "EXPIRE", &[b"content:1", b"60"]);
        perform_in(&mut state, "case", "DEL", &[b"content:1"]);
        assert!(request_in(&mut state, "case", "EXPIRE", &[b"content:1", b"60"]).is_err());
        assert!(state.snapshot().unused_case.is_empty());
    }
}

#[test]
fn multi_case_source_preflight_counts_only_each_cases_own_refresh_witnesses() {
    let own = [
        event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
        event(2, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let other = [event(3, "EXPIRE", &[b"content:1", b"120"], b":1\r\n")];
    let (root, state) = fixture(&own, &other);
    let request = json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"});
    let own_dir = root.path().join("case");
    let other_dir = root.path().join("other");
    let cases = [
        crate::policy::runtime::NativeSourceCase {
            id: "case",
            dir: &own_dir,
            request: &request,
            events: &own,
        },
        crate::policy::runtime::NativeSourceCase {
            id: "other",
            dir: &other_dir,
            request: &request,
            events: &other,
        },
    ];
    let counts = super::super::validate_source(&state.request_contracts, &cases).unwrap();
    assert_eq!(counts["ttl-refresh"], 3);
}

#[test]
fn an_existing_list_update_is_finite_and_must_deliver_before_initial_refresh() {
    let mut update = event(1, "LSET", &[b"content:1", b"0", b"value"], b"+OK\r\n");
    update["response_kind"] = json!("simple_string");
    let own = [
        update,
        event(2, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let (_root, mut state) = fixture(&own, &[]);
    assert!(request(&mut state, "EXPIRE", &[b"content:1", b"60"]).is_err());
    let update = request(&mut state, "LSET", &[b"content:1", b"0", b"value"]).unwrap();
    assert!(update.observation.is_none());
    assert!(request(&mut state, "EXPIRE", &[b"content:1", b"60"]).is_err());
    state.complete_exchange(&update);
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn initial_existing_key_window_starts_with_actual_target_refresh_and_does_not_slide() {
    let own = [event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n")];
    let (_root, mut state) = fixture(&own, &[]);
    state.prepare_observations("case").unwrap();
    state.observations.profiles[0].prepared_at =
        chrono::Utc::now() - chrono::TimeDelta::seconds(120);
    assert!(state.observations.initial_expiry_at.is_empty());
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    let established = state.observations.initial_expiry_at[&0];
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    assert_eq!(state.observations.initial_expiry_at[&0], established);
    state
        .observations
        .initial_expiry_at
        .insert(0, chrono::Utc::now() - chrono::TimeDelta::seconds(61));
    assert!(request(&mut state, "EXPIRE", &[b"content:1", b"60"]).is_err());
}

#[test]
fn initial_existing_key_context_does_not_waive_ttl_arguments_or_source_success() {
    let own = [event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n")];
    let (_root, mut state) = fixture(&own, &[]);
    assert!(request(&mut state, "EXPIRE", &[b"content:1", b"61"]).is_err());
    assert!(state.observations.initial_expiry_at.is_empty());
    assert!(!state.exchanges[0].status.is_consumed());
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);

    for own in [
        vec![event(1, "EXPIRE", &[b"content:1", b"60"], b":0\r\n")],
        vec![
            event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
            event(2, "EXPIRE", &[b"content:1", b"61"], b":1\r\n"),
        ],
    ] {
        let (_root, mut state) = fixture(&own, &[]);
        assert!(state.prepare_observations("case").is_err());
        assert!(state.observations.profiles.is_empty());
        assert!(state.exchanges.iter().all(|e| !e.status.is_consumed()));
    }
}

#[test]
fn initial_refresh_failure_or_omission_never_covers_source_refreshes() {
    let own = [
        event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
        event(2, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
        event(3, "DEL", &[b"content:1"], b":1\r\n"),
    ];
    let (_root, mut state) = fixture(&own, &[]);
    perform(&mut state, "DEL", &[b"content:1"]);
    assert!(state.exchanges[..2].iter().all(|e| !e.status.is_consumed()));
    assert!(state.case_is_dirty("case"));

    let (_root, mut state) = fixture(&own, &[]);
    let refresh = request(&mut state, "EXPIRE", &[b"content:1", b"60"]).unwrap();
    assert!(state.exchanges[..2].iter().all(|e| !e.status.is_consumed()));
    state.fail_exchange(&refresh, "transport failure".into());
    assert!(state.exchanges[..2].iter().all(|e| !e.status.is_consumed()));
    assert!(request(&mut state, "EXPIRE", &[b"content:1", b"60"]).is_err());
    assert!(state.case_is_dirty("case"));
}

#[test]
fn another_case_cannot_supply_an_expiry_witness_or_recreate_a_deleted_key() {
    let other = [
        event(4, "SET", &[b"content:1", b"other"], b"+OK\r\n"),
        event(5, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let own = [event(1, "GET", &[b"content:1"], b"$3\r\nold\r\n")];
    let (_root, mut state) = fixture(&own, &other);
    perform(&mut state, "GET", &[b"content:1"]);
    assert!(request(&mut state, "EXPIRE", &[b"content:1", b"60"]).is_err());
    assert!(!state.exchanges[2].status.is_consumed());

    let own = [
        event(1, "DEL", &[b"content:1"], b":0\r\n"),
        event(2, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let (_root, mut state) = fixture(&own, &other);
    assert!(state.prepare_observations("case").is_err());
    assert!(state.observations.profiles.is_empty());
}

#[test]
fn an_initial_existing_key_can_be_deleted_before_an_owned_new_lifetime() {
    let own = [
        event(1, "DEL", &[b"content:1"], b":1\r\n"),
        event(2, "SET", &[b"content:1", b"new"], b"+OK\r\n"),
        event(3, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let (_root, mut state) = fixture(&own, &[]);
    assert!(request(&mut state, "SET", &[b"content:1", b"new"]).is_err());
    perform(&mut state, "DEL", &[b"content:1"]);
    perform(&mut state, "SET", &[b"content:1", b"new"]);
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn pooled_initial_read_must_be_claimed_before_deletion_and_recreation() {
    let mut own = [
        event(1, "GET", &[b"content:1"], b"$3\r\nold\r\n"),
        event(2, "DEL", &[b"content:1"], b":1\r\n"),
        event(3, "SET", &[b"content:1", b"new"], b"+OK\r\n"),
        event(4, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    for event in &mut own[1..] {
        event["connection_id"] = json!(Uuid::from_u128(2));
    }
    let (_root, mut state) = fixture(&own, &[]);
    assert!(request(&mut state, "DEL", &[b"content:1"]).is_err());
    assert!(request(&mut state, "SET", &[b"content:1", b"new"]).is_err());
    let read = request(&mut state, "GET", &[b"content:1"]).unwrap();
    assert_eq!(read.response, b"$3\r\nold\r\n");
    let deletion = request(&mut state, "DEL", &[b"content:1"]).unwrap();
    assert_eq!(
        state.exchanges[read.index].status,
        ReplayExchangeStatus::Responding
    );
    state.complete_exchange(&deletion);
    assert!(state.has_case_in_flight());
    state.complete_exchange(&read);
    perform(&mut state, "SET", &[b"content:1", b"new"]);
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn pooled_initial_list_update_and_reads_keep_their_finite_order() {
    let mut first_read = event(
        1,
        "LRANGE",
        &[b"content:1", b"0", b"-1"],
        b"*1\r\n$3\r\nold\r\n",
    );
    first_read["response_kind"] = json!("array");
    let mut update = event(2, "LSET", &[b"content:1", b"0", b"new"], b"+OK\r\n");
    update["response_kind"] = json!("simple_string");
    update["connection_id"] = json!(Uuid::from_u128(2));
    let mut second_read = event(
        3,
        "LRANGE",
        &[b"content:1", b"0", b"-1"],
        b"*1\r\n$3\r\nnew\r\n",
    );
    second_read["response_kind"] = json!("array");
    let own = [
        first_read,
        update,
        second_read,
        event(4, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
    ];
    let (_root, mut state) = fixture(&own, &[]);
    assert!(request(&mut state, "LSET", &[b"content:1", b"0", b"new"]).is_err());
    assert_eq!(
        perform(&mut state, "LRANGE", &[b"content:1", b"0", b"-1"]),
        b"*1\r\n$3\r\nold\r\n"
    );
    assert!(request(&mut state, "LRANGE", &[b"content:1", b"0", b"-1"]).is_err());
    let update = request(&mut state, "LSET", &[b"content:1", b"0", b"new"]).unwrap();
    let read = request(&mut state, "LRANGE", &[b"content:1", b"0", b"-1"]).unwrap();
    assert_eq!(read.response, b"*1\r\n$3\r\nnew\r\n");
    assert_eq!(
        state.exchanges[update.index].status,
        ReplayExchangeStatus::Responding
    );
    state.complete_exchange(&read);
    assert!(state.has_case_in_flight());
    state.complete_exchange(&update);
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn initial_refresh_does_not_wait_for_a_later_finite_read() {
    let mut read = event(2, "GET", &[b"content:1"], b"$3\r\nold\r\n");
    read["connection_id"] = json!(Uuid::from_u128(2));
    let own = [event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"), read];
    let (_root, mut state) = fixture(&own, &[]);
    perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
    assert_eq!(
        perform(&mut state, "GET", &[b"content:1"]),
        b"$3\r\nold\r\n"
    );
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn initial_positive_expiry_cannot_hide_a_later_missing_key_observation() {
    for (command, args, response, response_kind) in [
        (
            "GET",
            vec![b"content:1".as_slice()],
            b"$-1\r\n".as_slice(),
            "null",
        ),
        (
            "GET",
            vec![b"content:1".as_slice()],
            b"_\r\n".as_slice(),
            "null",
        ),
        (
            "EXISTS",
            vec![b"content:1".as_slice()],
            b":0\r\n".as_slice(),
            "integer",
        ),
        (
            "LLEN",
            vec![b"content:1".as_slice()],
            b":0\r\n".as_slice(),
            "integer",
        ),
        (
            "TYPE",
            vec![b"content:1".as_slice()],
            b"+none\r\n".as_slice(),
            "simple_string",
        ),
        (
            "LRANGE",
            vec![b"content:1".as_slice(), b"0", b"-1"],
            b"*0\r\n".as_slice(),
            "array",
        ),
    ] {
        let mut observation = event(2, command, &args, response);
        observation["response_kind"] = json!(response_kind);
        let mut own = [
            event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
            observation,
        ];
        if response == b"_\r\n" {
            for event in &mut own {
                event["resp_version"] = json!(3);
            }
        }
        let (_root, mut state) = fixture(&own, &[]);
        let error = state.prepare_observations("case").unwrap_err();
        assert!(format!("{error:#}").contains("absent-key observation"));
        assert!(state.observations.profiles.is_empty());
    }
}

#[test]
fn empty_content_or_a_nil_mget_member_is_not_a_missing_key_proof() {
    for (command, args, response, response_kind) in [
        (
            "GET",
            vec![b"content:1".as_slice()],
            b"$0\r\n\r\n".as_slice(),
            "bulk_string",
        ),
        (
            "MGET",
            vec![b"content:1".as_slice()],
            b"*1\r\n$-1\r\n".as_slice(),
            "array",
        ),
        (
            "STRLEN",
            vec![b"content:1".as_slice()],
            b":0\r\n".as_slice(),
            "integer",
        ),
        (
            "LRANGE",
            vec![b"content:1".as_slice(), b"5", b"10"],
            b"*0\r\n".as_slice(),
            "array",
        ),
    ] {
        let mut observation = event(2, command, &args, response);
        observation["response_kind"] = json!(response_kind);
        let own = [
            event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
            observation,
        ];
        let (_root, mut state) = fixture(&own, &[]);
        perform(&mut state, "EXPIRE", &[b"content:1", b"60"]);
        perform(&mut state, command, &args);
        assert!(state.snapshot().unused_case.is_empty());
    }
}

#[test]
fn explicit_shared_and_global_key_inventory_still_cannot_join_a_case_proof() {
    let own = [event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n")];
    for shared in [false, true] {
        let other = [event(2, "EXPIRE", &[b"content:1", b"60"], b":1\r\n")];
        let (_root, mut state) = fixture(&own, &other);
        if shared {
            state.exchanges[1].shared_rule_id = Some("explicit-sharing".into());
        } else {
            state.exchanges[1].source = ReplaySource::Startup;
        }
        assert!(state.prepare_observations("case").is_err());
        assert!(state.observations.profiles.is_empty());
    }
}

#[test]
fn initial_finite_access_budget_does_not_count_expiry_prefix_twice() {
    for reads in [MAX_OBSERVATIONS - 1, MAX_OBSERVATIONS] {
        let mut own = vec![event(1, "GET", &[b"content:1"], b"$3\r\nold\r\n"); reads];
        own.push(event(1, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"));
        for (sequence, event) in own.iter_mut().enumerate() {
            event["sequence"] = json!(sequence + 1);
        }
        let (_root, mut state) = fixture(&own, &[]);
        let prepared = state.prepare_observations("case");
        if reads < MAX_OBSERVATIONS {
            prepared.unwrap();
            assert_eq!(state.observations.profiles[0].finite_prefix.len(), reads);
            assert_eq!(state.observations.profiles[0].initial_accesses.len(), reads);
        } else {
            assert!(prepared.is_err());
            assert!(state.observations.profiles.is_empty());
        }
    }
}
