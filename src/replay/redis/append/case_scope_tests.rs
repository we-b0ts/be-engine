//! APPEND proofs describe this request's increment, not the key's prior history.
use super::tests::{event, request, rule, state};
use super::*;
use serde_json::{Value, json};

type CaseSource = (String, std::path::PathBuf, Value, Vec<Value>);

fn cases() -> Vec<CaseSource> {
    [
        (
            "case",
            vec![
                event(1, "APPEND", &[b"content:1", b"b"], b":2\r\n"),
                event(2, "APPEND", &[b"content:1", b"cd"], b":4\r\n"),
            ],
        ),
        (
            "other",
            vec![
                event(3, "APPEND", &[b"content:1", b"uv"], b":42\r\n"),
                event(4, "APPEND", &[b"content:1", b"w"], b":43\r\n"),
            ],
        ),
    ]
    .into_iter()
    .map(|(id, mut events)| {
        if id == "other" {
            for event in &mut events {
                event["connection_id"] = json!(Uuid::from_u128(2));
            }
        }
        (
            id.into(),
            std::path::PathBuf::new(),
            json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"}),
            events,
        )
    })
    .collect()
}

fn register(state: &mut RedisReplayState, case: &CaseSource) {
    for event in &case.3 {
        state
            .register_exchange(
                serde_json::from_value(event.clone()).unwrap(),
                ReplaySource::Case,
                Some(&case.0),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
    }
}

fn fixture() -> (tempfile::TempDir, RedisReplayState, Vec<CaseSource>) {
    let root = tempfile::tempdir().unwrap();
    let mut cases = cases();
    let mut inventory = BTreeMap::new();
    for (id, dir, request, events) in &mut cases {
        *dir = root.path().join(&*id);
        std::fs::create_dir(dir.as_path()).unwrap();
        std::fs::write(dir.join("request.json"), request.to_string()).unwrap();
        std::fs::write(dir.join("expected-response.json"), "{}").unwrap();
        std::fs::write(
            dir.join("dependencies.jsonl"),
            events.iter().map(|e| format!("{e}\n")).collect::<String>(),
        )
        .unwrap();
        inventory.insert(
            id.clone(),
            crate::replay::ReplayCase {
                id: id.clone(),
                dir: dir.clone(),
                dependencies_path: dir.join("dependencies.jsonl"),
                status: crate::replay::ReplayCaseStatus::Pending,
            },
        );
    }
    let policy = root.path().join("policy.yaml");
    std::fs::write(
        &policy,
        json!({"format":"traffic-policy/v2","redis":{"keys":{
            "content:*":{"append_stream":true}
        }}})
        .to_string(),
    )
    .unwrap();
    let runtime = crate::replay::ReplayPolicyRuntime::load(&policy, &inventory).unwrap();
    let state = RedisReplayState {
        request_contracts: runtime.request_contracts.clone(),
        dynamic_values: runtime.dynamic_values.clone(),
        ..Default::default()
    };
    (root, state, cases)
}

fn request_case(
    state: &mut RedisReplayState,
    case: &str,
    bytes: &[u8],
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
        "APPEND",
        &[b"content:1".to_vec(), bytes.to_vec()],
    )
}

fn source_view(case: &CaseSource) -> crate::replay::NativeSourceCase<'_> {
    crate::replay::NativeSourceCase {
        id: &case.0,
        dir: &case.1,
        request: &case.2,
        events: &case.3,
    }
}

#[test]
fn same_key_case_proofs_remain_independent_for_eager_and_late_inventory() {
    for late in [false, true] {
        for reverse in [false, true] {
            let (_root, mut state, cases) = fixture();
            if !late && reverse {
                register(&mut state, &cases[1]);
            }
            register(&mut state, &cases[0]);
            if !late && !reverse {
                register(&mut state, &cases[1]);
            }
            state.prepare_append_case("case").unwrap();
            if late {
                register(&mut state, &cases[1]);
            }
            state.request_contracts.begin_case("case");
            for wrong in [b"bcX".as_slice(), b"bcduvw", b"uvw"] {
                assert!(request_case(&mut state, "case", wrong).is_err());
            }
            for (bytes, expected) in [
                (b"bc".as_slice(), b":3\r\n".as_slice()),
                (b"d".as_slice(), b":4\r\n".as_slice()),
            ] {
                let matched = request_case(&mut state, "case", bytes).unwrap();
                assert_eq!(matched.response, expected);
                state.complete_exchange(&matched);
            }
            assert!(request_case(&mut state, "case", b"uvw").is_err());
            assert!(
                state
                    .exchanges
                    .iter()
                    .filter(|e| e.case_id.as_deref() == Some("other"))
                    .all(|e| e.status == ReplayExchangeStatus::Available)
            );
            state.request_contracts.begin_case("other");
            let matched = request_case(&mut state, "other", b"uvw").unwrap();
            assert_eq!(matched.response, b":43\r\n");
            state.complete_exchange(&matched);
            assert!(state.snapshot().unused_case.is_empty());
            let bases = state
                .append_streams
                .profiles
                .iter()
                .map(|p| (p.case.as_str(), p.pieces[0].base))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(bases, BTreeMap::from([("case", 1), ("other", 40)]));
        }
    }
}

#[test]
fn native_source_preflight_uses_each_cases_own_length_and_bytes() {
    let (_root, state, cases) = fixture();
    for reverse in [false, true] {
        let mut views = cases.iter().map(source_view).collect::<Vec<_>>();
        if reverse {
            views.reverse();
        }
        let counts = source::validate_source(&state.request_contracts, &views).unwrap();
        assert_eq!(counts.values().sum::<usize>(), 4);
        let alone =
            source::validate_source(&state.request_contracts, &[source_view(&cases[0])]).unwrap();
        assert_eq!(alone.values().sum::<usize>(), 2);
    }
}

#[test]
fn global_shared_reads_keep_their_owner_even_with_the_current_case_as_origin() {
    let events = [event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n")];
    let (_root, mut state) = state(&events, vec![rule()]);
    state
        .register_exchange(
            serde_json::from_value(event(2, "GET", &[b"content:1"], b"$2\r\nab\r\n")).unwrap(),
            ReplaySource::Global,
            Some("case"),
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap();
    state.exchanges[1].shared_rule_id = Some("shared-read".into());
    assert!(request(&mut state, "APPEND", &[b"content:1", b"ab"]).is_err());
    assert!(
        state
            .exchanges
            .iter()
            .all(|e| e.status == ReplayExchangeStatus::Available)
    );
}

#[test]
fn prior_content_reads_and_resets_still_fence_nonempty_initial_appends() {
    let events = [
        event(1, "GET", &[b"content:1"], b"$1\r\nA\r\n"),
        event(2, "APPEND", &[b"content:1", b"b"], b":2\r\n"),
        event(3, "GET", &[b"content:1"], b"$2\r\nAb\r\n"),
        event(4, "APPEND", &[b"content:1", b"cd"], b":4\r\n"),
        event(5, "DEL", &[b"content:1"], b":1\r\n"),
        event(6, "APPEND", &[b"content:1", b"ef"], b":2\r\n"),
    ];
    let (_root, mut state) = state(&events, vec![rule()]);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"b"]).is_err());
    let read = request(&mut state, "GET", &[b"content:1"]).unwrap();
    state.complete_exchange(&read);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"bcd"]).is_err());
    let append = request(&mut state, "APPEND", &[b"content:1", b"b"]).unwrap();
    assert_eq!(append.response, b":2\r\n");
    state.complete_exchange(&append);
    let read = request(&mut state, "GET", &[b"content:1"]).unwrap();
    state.complete_exchange(&read);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"cdef"]).is_err());
    let append = request(&mut state, "APPEND", &[b"content:1", b"cd"]).unwrap();
    assert_eq!(append.response, b":4\r\n");
    state.complete_exchange(&append);
    assert!(request(&mut state, "APPEND", &[b"content:1", b"ef"]).is_err());
    let delete = request(&mut state, "DEL", &[b"content:1"]).unwrap();
    state.complete_exchange(&delete);
    let append = request(&mut state, "APPEND", &[b"content:1", b"e"]).unwrap();
    assert_eq!(append.response, b":1\r\n");
    state.complete_exchange(&append);
    let append = request(&mut state, "APPEND", &[b"content:1", b"f"]).unwrap();
    assert_eq!(append.response, b":2\r\n");
    state.complete_exchange(&append);
    assert!(state.snapshot().unused_case.is_empty());
}
