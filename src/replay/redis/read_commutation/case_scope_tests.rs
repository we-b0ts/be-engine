//! Nil-read permissions and finite slots are owned by one ordinary Case.
use super::*;

fn global_rule() -> Value {
    let mut value = rule();
    value["match"].as_object_mut().unwrap().remove("api");
    value
}

fn add(state: &mut RedisReplayState, value: Value, case: &str) {
    state
        .register_exchange(
            serde_json::from_value(value).unwrap(),
            ReplaySource::Case,
            Some(case),
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap();
}

fn case_fixture(own: &[Value], other: &[Value]) -> (tempfile::TempDir, RedisReplayState) {
    let root = tempfile::tempdir().unwrap();
    let policy = root.path().join("policy.yaml");
    std::fs::write(
        &policy,
        json!({"format":"traffic-policy/v3","rules":[global_rule()]}).to_string(),
    )
    .unwrap();
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
        add(&mut state, value.clone(), "case");
    }
    (root, state)
}

#[test]
fn foreign_case_nil_reads_neither_block_nor_extend_current_case_inventory() {
    for lazy in [false, true] {
        let local = event(1, "GET", &[b"cancel:1"], b"$-1\r\n");
        let foreign = event(2, "GET", &[b"cancel:1"], b"$-1\r\n");
        let (_root, mut state) = case_fixture(&[local], std::slice::from_ref(&foreign));
        if !lazy {
            add(&mut state, foreign.clone(), "foreign");
        }
        state.prepare_read_commutation("case").unwrap();
        if lazy {
            add(&mut state, foreign, "foreign");
        }
        assert!(state.exchanges[1].read_commutation_rule.is_none());
        let read = request(&mut state, "GET", &[b"cancel:1"]).unwrap();
        assert_eq!(read.index, 0);
        state.complete_exchange(&read);
        assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
        assert!(state.exchanges[1].status.is_available());
    }
}

#[test]
fn foreign_nil_read_cannot_make_a_non_nil_current_case_eligible() {
    let other = event(2, "GET", &[b"cancel:1"], b"$-1\r\n");
    let (_root, mut state) = case_fixture(
        &[event(1, "GET", &[b"cancel:1"], b"$1\r\nx\r\n")],
        std::slice::from_ref(&other),
    );
    add(&mut state, other, "foreign");
    assert!(state.prepare_read_commutation("case").is_err());
    assert!(state.read_commutation.profiles.is_empty());
}

#[test]
fn native_source_nil_read_proofs_are_independent_of_other_cases_using_the_same_key() {
    let first = [event(1, "GET", &[b"cancel:1"], b"$-1\r\n")];
    let second = [event(2, "GET", &[b"cancel:1"], b"$-1\r\n")];
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
    assert_eq!(
        validate_source(&state.request_contracts, &cases[..1]).unwrap()["poll"],
        1
    );
    assert_eq!(
        validate_source(&state.request_contracts, &cases).unwrap()["poll"],
        2
    );
}
