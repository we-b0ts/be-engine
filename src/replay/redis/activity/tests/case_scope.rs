//! Ordinary Cases retain independent metadata state even when physical keys match.
use super::*;

fn local_events(user: u64) -> Vec<Value> {
    let mut first: Value =
        serde_json::from_slice(&object("2020-01-01T00:00:01Z", "2020-01-01T00:00:01Z")).unwrap();
    first["user_id"] = json!(user);
    let first = serde_json::to_vec(&first).unwrap();
    let mut next: Value = serde_json::from_slice(&first).unwrap();
    next["last_activity_at"] = json!("2020-01-01T00:00:03Z");
    let next = serde_json::to_vec(&next).unwrap();
    vec![
        event(
            1,
            "SET",
            &[b"activity:1", &first, b"EX", b"3600"],
            b"+OK\r\n",
        ),
        event(2, "GET", &[b"activity:1"], &value::bulk(&first)),
        event(
            3,
            "SET",
            &[b"activity:1", &next, b"EX", b"3600"],
            b"+OK\r\n",
        ),
        event(4, "DEL", &[b"activity:1"], b":1\r\n"),
    ]
}

fn add_foreign(state: &mut RedisReplayState, values: &[Value]) {
    for value in values {
        state
            .register_exchange(
                serde_json::from_value(value.clone()).unwrap(),
                ReplaySource::Case,
                Some("foreign"),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
    }
}

fn case_fixture(own: &[Value], other: &[Value]) -> (tempfile::TempDir, RedisReplayState) {
    let root = tempfile::tempdir().unwrap();
    let policy = root.path().join("policy.yaml");
    std::fs::write(&policy, document(true).to_string()).unwrap();
    let mut cases = BTreeMap::new();
    for (id, events) in [("case", own), ("foreign", other)] {
        let dir = root.path().join(id);
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
            id.into(),
            crate::replay::ReplayCase {
                id: id.into(),
                dependencies_path: dir.join("dependencies.jsonl"),
                dir,
                status: crate::replay::ReplayCaseStatus::Pending,
            },
        );
    }
    let runtime = crate::replay::ReplayPolicyRuntime::load(&policy, &cases).unwrap();
    let mut state = RedisReplayState {
        request_contracts: runtime.request_contracts.clone(),
        dynamic_values: runtime.dynamic_values.clone(),
        ..Default::default()
    };
    for value in own {
        state
            .register_exchange(
                serde_json::from_value(value.clone()).unwrap(),
                ReplaySource::Case,
                Some("case"),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
    }
    (root, state)
}

#[test]
fn same_key_cases_keep_refresh_state_and_consumption_independent_for_eager_and_lazy_loads() {
    for lazy in [false, true] {
        let current = local_events(3);
        let foreign = local_events(9);
        let (_root, mut state) = case_fixture(&current, &foreign);
        if !lazy {
            add_foreign(&mut state, &foreign);
        }
        state.prepare_activity_case("case").unwrap();
        if lazy {
            add_foreign(&mut state, &foreign);
        }
        assert!(
            state.exchanges[4..]
                .iter()
                .all(|e| !state.activity_refresh.owns(e))
        );
        state.prepare_activity_case("foreign").unwrap();
        assert_eq!(state.activity_refresh.profiles.len(), 2);
        assert!(
            state
                .activity_refresh
                .profiles
                .iter()
                .all(|p| p.current.is_none())
        );

        let value = create(&mut state);
        touch(&mut state, &value);
        perform(&mut state, "DEL", &[b"activity:1"]);
        assert!(request(&mut state, "GET", &[b"activity:1"]).is_err());
        assert!(state.exchanges[..4].iter().all(|e| e.status.is_consumed()));
        assert!(state.exchanges[4..].iter().all(|e| e.status.is_available()));
        assert!(state.activity_refresh.profiles[1].current.is_none());
    }
}

#[test]
fn other_cases_cannot_supply_a_missing_current_value_read_or_bypass_global_ownership() {
    let mut missing_read = local_events(3);
    missing_read.remove(1);
    let (_root, mut state) = case_fixture(&missing_read, &local_events(3));
    add_foreign(&mut state, &local_events(3));
    assert!(state.prepare_activity_case("case").is_err());
    assert!(state.activity_refresh.owned.is_empty());

    let (_root, mut state) = case_fixture(&local_events(3), &[]);
    let record = serde_json::from_value(event(
        10,
        "SET",
        &[b"activity:1", b"global", b"EX", b"3600"],
        b"+OK\r\n",
    ))
    .unwrap();
    state
        .register_exchange(
            record,
            ReplaySource::Startup,
            None,
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap();
    assert!(state.prepare_activity_case("case").is_err());
    assert!(state.activity_refresh.owned.is_empty());
}

#[test]
fn native_source_preflight_counts_each_case_without_foreign_key_conflicts() {
    let first = local_events(3);
    let second = local_events(9);
    let (root, state) = case_fixture(&first, &second);
    let request = json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"});
    let first_dir = root.path().join("case");
    let second_dir = root.path().join("foreign");
    let cases = [
        crate::replay::NativeSourceCase {
            id: "case",
            dir: &first_dir,
            request: &request,
            events: &first,
        },
        crate::replay::NativeSourceCase {
            id: "foreign",
            dir: &second_dir,
            request: &request,
            events: &second,
        },
    ];
    let alone = validate_source(&state.request_contracts, &cases[..1]).unwrap();
    let together = validate_source(&state.request_contracts, &cases).unwrap();
    assert_eq!(alone.len(), 1);
    assert_eq!(
        together.values().sum::<usize>(),
        2 * alone.values().sum::<usize>()
    );
}
