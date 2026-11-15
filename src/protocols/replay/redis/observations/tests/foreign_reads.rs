//! A Case's observed state never consumes another Case's finite read inventory.
use super::*;

fn setup(lazy_reader: bool) -> (tempfile::TempDir, RedisReplayState) {
    let root = tempfile::tempdir().unwrap();
    let policy = root.path().join("policy.yaml");
    let mut native = read_rule(true);
    native["match"].as_object_mut().unwrap().remove("resource");
    native["match"].as_object_mut().unwrap().remove("api");
    native["effect"]["references"] = json!([]);
    std::fs::write(
        &policy,
        json!({"format":"traffic-policy/v3","redis":{"keys":{"current:*":{
        "kind":"identity","formats":["string"]
    }}},"rules":[native]})
        .to_string(),
    )
    .unwrap();
    let mut cases = BTreeMap::new();
    for id in ["case", "reader"] {
        let dir = root.path().join(id);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("request.json"),
            json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"}).to_string(),
        )
        .unwrap();
        std::fs::write(dir.join("expected-response.json"), "{}").unwrap();
        std::fs::write(dir.join("dependencies.jsonl"), "").unwrap();
        cases.insert(
            id.into(),
            crate::replay::ReplayCase {
                id: id.into(),
                dir: dir.clone(),
                dependencies_path: dir.join("dependencies.jsonl"),
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
    for value in [
        event(1, "SET", &[b"current:1", b"source"], b"+OK\r\n"),
        event(2, "GET", &[b"current:1"], b"$6\r\nsource\r\n"),
    ] {
        add(&mut state, "case", value).unwrap();
    }
    if !lazy_reader {
        add(&mut state, "reader", reader_event()).unwrap();
    }
    (root, state)
}

fn reader_event() -> Value {
    let mut value = event(3, "GET", &[b"current:1"], b"$6\r\nsource\r\n");
    value["connection_id"] = json!(Uuid::from_u128(2));
    value
}

fn add(state: &mut RedisReplayState, case: &str, value: Value) -> Result<()> {
    state.register_exchange(
        serde_json::from_value(value)?,
        ReplaySource::Case,
        Some(case),
        &mut BTreeMap::new(),
        &[],
    )
}

#[test]
fn shared_key_readback_owns_only_its_writer_case_for_eager_and_lazy_inventory() {
    for lazy in [false, true] {
        let (_root, mut state) = setup(lazy);
        state.prepare_observations("case").unwrap();
        perform(&mut state, "SET", &[b"current:1", b"target"]);
        for _ in 0..3 {
            assert_eq!(
                perform(&mut state, "GET", &[b"current:1"]),
                b"$6\r\ntarget\r\n"
            );
        }
        if lazy {
            add(&mut state, "reader", reader_event()).unwrap();
        }
        assert!(state.exchanges[2].observation_rule.is_none());
        assert_eq!(state.exchanges[2].status, ReplayExchangeStatus::Available);
        state.request_contracts.begin_case("reader");
        let read = state
            .match_redis(
                Some("reader"),
                &TargetKey {
                    host: "redis.test".into(),
                    port: 6379,
                },
                TargetConnection::default(),
                2,
                0,
                None,
                "GET",
                &[b"current:1".to_vec()],
            )
            .unwrap();
        assert!(read.observation.is_none());
        assert_eq!(read.response, b"$6\r\nsource\r\n");
        state.complete_exchange(&read);
        assert!(
            state
                .match_redis(
                    Some("reader"),
                    &TargetKey {
                        host: "redis.test".into(),
                        port: 6379
                    },
                    TargetConnection::default(),
                    2,
                    0,
                    None,
                    "GET",
                    &[b"current:1".to_vec()]
                )
                .is_err()
        );
        assert!(
            state
                .observations
                .profiles
                .iter()
                .all(|profile| profile.case == "case")
        );
    }
}

#[test]
fn foreign_writes_or_expiry_observers_leave_an_owned_state_profile_unchanged() {
    for (command, args, response) in [
        (
            "SET",
            vec![b"current:1".as_slice(), b"other".as_slice()],
            b"+OK\r\n".as_slice(),
        ),
        ("DEL", vec![b"current:1".as_slice()], b":1\r\n".as_slice()),
        (
            "EXPIRE",
            vec![b"current:1".as_slice(), b"60".as_slice()],
            b":1\r\n".as_slice(),
        ),
        ("TTL", vec![b"current:1".as_slice()], b":30\r\n".as_slice()),
    ] {
        for lazy in [false, true] {
            let (_root, mut state) = setup(true);
            let mut foreign = event(3, command, &args, response);
            foreign["connection_id"] = json!(Uuid::from_u128(2));
            if !lazy {
                add(&mut state, "reader", foreign.clone()).unwrap();
            }
            state.prepare_observations("case").unwrap();
            if lazy {
                add(&mut state, "reader", foreign).unwrap();
            }
            perform(&mut state, "SET", &[b"current:1", b"target"]);
            assert_eq!(
                perform(&mut state, "GET", &[b"current:1"]),
                b"$6\r\ntarget\r\n",
                "foreign {command}, lazy={lazy}"
            );
            assert!(state.exchanges[2].observation_rule.is_none());
            assert_eq!(state.exchanges[2].status, ReplayExchangeStatus::Available);
        }
    }
}
