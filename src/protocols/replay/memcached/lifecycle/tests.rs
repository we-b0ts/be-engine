use super::*;
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::{io::AsyncReadExt, net::TcpListener};

fn target() -> TargetKey {
    TargetKey {
        host: "cache.test".into(),
        port: 11211,
    }
}

fn event(connection: u128, sequence: u64, key: &str, response: &[u8]) -> Value {
    json!({
        "event_type":"memcached_exchange", "connection_id":Uuid::from_u128(connection),
        "sequence":sequence,"target_host":"cache.test","target_port":11211,
        "wire_protocol":"text","command":"get","opcode":null,
        "key":{"encoding":"utf8","data":key},"args":[],"value":null,"extras":null,
        "cas":null,"quiet":false,"noreply":false,"no_response":false,
        "response_frames":[{"encoding":"base64","data":STANDARD.encode(response)}],"replay_safe":true
    })
}

fn request(key: &str) -> MemcachedRequest {
    MemcachedRequest {
        raw: bytes::Bytes::new(),
        command: "get".into(),
        opcode: None,
        opaque: None,
        key: Some(key.as_bytes().to_vec()),
        args: vec![],
        value: None,
        extras: None,
        cas: None,
        quiet: false,
        noreply: false,
    }
}

fn source(events: &[Value]) -> MemcachedReplayState {
    let mut state = MemcachedReplayState::default();
    for event in events {
        state
            .register_exchange(
                serde_json::from_value(event.clone()).unwrap(),
                ReplaySource::Case,
                Some("case"),
                &mut BTreeMap::new(),
            )
            .unwrap();
    }
    state
}

fn select(state: &mut MemcachedReplayState, key: &str) -> MatchedMemcachedExchange {
    state
        .match_memcached(MemcachedMatchContext {
            active_case_id: Some("case"),
            target: &target(),
            wire_protocol: MemcachedWireProtocol::Text,
            request: &request(key),
            policy: None,
            observed_at: Utc::now(),
        })
        .unwrap()
}

#[test]
fn independent_lanes_finish_out_of_order_without_rewriting_arrival_or_reusing_a_slot() {
    let mut state = source(&[event(1, 1, "a", b"END\r\n"), event(2, 1, "b", b"END\r\n")]);
    let first = select(&mut state, "b");
    let second = select(&mut state, "a");
    assert_eq!((first.index, second.index), (1, 0));
    first.claim.publish_wire();
    second.claim.publish_wire();
    state.finish_exchange(&second, || Ok(())).unwrap();
    state.finish_exchange(&first, || Ok(())).unwrap();
    assert_eq!(state.events.matched_count, 2);
    assert_eq!(
        state
            .events
            .matched
            .iter()
            .map(|report| report.target_event_index)
            .collect::<Vec<_>>(),
        [Some(1), Some(0)]
    );
    assert!(
        state
            .finish_exchange::<()>(&first, || panic!("a consumed slot must not commit twice"))
            .unwrap()
            .is_none()
    );
    assert_eq!(state.events.matched_count, 2);
    assert!(
        state
            .match_memcached(MemcachedMatchContext {
                active_case_id: Some("case"),
                target: &target(),
                wire_protocol: MemcachedWireProtocol::Text,
                request: &request("b"),
                policy: None,
                observed_at: Utc::now(),
            })
            .is_err()
    );
}

#[test]
fn quiet_delivery_requires_commit_and_cancelled_delivery_cannot_release_its_lane() {
    for cancelled in [false, true] {
        let mut quiet = event(1, 1, "first", b"");
        quiet["wire_protocol"] = "binary".into();
        quiet["opcode"] = 9.into();
        quiet["quiet"] = true.into();
        quiet["no_response"] = true.into();
        quiet["response_frames"] = json!([]);
        let mut next = event(1, 2, "second", b"");
        next["wire_protocol"] = "binary".into();
        next["opcode"] = 0.into();
        let mut state = source(&[quiet, next]);
        let mut first = request("first");
        first.opcode = Some(9);
        first.quiet = true;
        first.opaque = Some(41);
        let matched = state
            .match_memcached(MemcachedMatchContext {
                active_case_id: Some("case"),
                target: &target(),
                wire_protocol: MemcachedWireProtocol::Binary,
                request: &first,
                policy: None,
                observed_at: Utc::now(),
            })
            .unwrap();
        let guard = matched.claim.guard();
        let mut next = request("second");
        next.opcode = Some(0);
        next.opaque = Some(42);
        let try_next = |state: &mut MemcachedReplayState| {
            state.match_memcached(MemcachedMatchContext {
                active_case_id: Some("case"),
                target: &target(),
                wire_protocol: MemcachedWireProtocol::Binary,
                request: &next,
                policy: None,
                observed_at: Utc::now(),
            })
        };
        assert!(matches!(
            try_next(&mut state),
            Err(CommandMatchDiagnostic::LaneBlocked { .. })
        ));
        matched.claim.publish_wire();
        assert!(matches!(
            try_next(&mut state),
            Err(CommandMatchDiagnostic::LaneBlocked { .. })
        ));
        if cancelled {
            drop(guard);
            assert_eq!(
                state.finite_exchange_status(matched.index),
                Some(ReplayExchangeStatus::Failed)
            );
            assert!(!state.has_case_in_flight());
            assert!(matches!(
                try_next(&mut state),
                Err(CommandMatchDiagnostic::LaneBlocked { .. })
            ));
            assert!(state.case_is_dirty("case"));
            assert_eq!(state.events.matched_count, 0);
        } else {
            state.finish_exchange(&matched, || Ok(())).unwrap();
            drop(guard);
            assert!(try_next(&mut state).is_ok());
        }
    }
}

#[tokio::test]
async fn failed_native_policy_commit_after_real_wire_delivery_is_terminal_and_dirty() {
    use crate::value_contract::identities::{IdentityDecision, IdentityPair};
    let (root, runtime) = runtime(&[event(1, 1, "first", b"END\r\n")]).await;
    let matched = match_memcached_request(
        &runtime.state,
        &target(),
        MemcachedWireProtocol::Text,
        &request("first"),
    )
    .await
    .unwrap();
    let (mut server, mut client) = socket_pair().await;
    for frame in &matched.response_frames {
        server.write_all(frame).await.unwrap();
    }
    let mut output = [0; 5];
    client.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"END\r\n");
    matched.claim.publish_wire();
    let mut state = runtime.state.lock().await;
    let case = state.active_case_id.clone().unwrap();
    let path = root.path().join("policy.yaml");
    std::fs::write(&path, "format: traffic-policy/v3\nrules: []\n").unwrap();
    let mut policy = ReplayPolicyRuntime::load(&path, &state.cases).unwrap();
    let proposal = |target: &str| {
        IdentityDecision::prepare(
            &case,
            vec![IdentityPair {
                source: serde_json::to_string("source-entity").unwrap(),
                target: serde_json::to_string(target).unwrap(),
            }],
        )
        .unwrap()
    };
    policy
        .request_contracts
        .commit_identity(proposal("committed-target"))
        .unwrap();
    let mut contract = crate::policy::runtime::request_contract::Decision::default();
    contract.identity = Some(proposal("conflicting-target"));
    let mut decision = DependencyRuleDecision::default();
    decision.value_contracts.push(contract);
    // Exercise the exact native transaction passed to shared finish by delivery.rs.
    let error = state
        .protocols
        .memcached
        .finish_exchange(&matched, || policy.commit(Some(&case), decision))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("identity equality relationship changed")
    );
    assert_eq!(
        state
            .protocols
            .memcached
            .finite_exchange_status(matched.index),
        Some(ReplayExchangeStatus::Failed)
    );
    assert!(!state.protocols.memcached.has_in_flight());
    assert!(state.protocols.memcached.case_is_dirty(&case));
    assert_eq!(state.protocols.memcached.events.matched_count, 0);
    assert_eq!(state.protocols.memcached.events.unsafe_events.len(), 1);
    assert!(
        state
            .protocols
            .memcached
            .finish_exchange::<()>(&matched, || panic!("failed delivery cannot become success"))
            .unwrap()
            .is_none()
    );
}

async fn runtime(
    events: &[Value],
) -> (
    crate::policy::runtime::test_fixture::ManagedFixtureDirectory,
    ReplayRuntime,
) {
    let root = crate::policy::runtime::test_fixture::managed_tempdir().unwrap();
    let raw = root.path().join("source");
    std::fs::create_dir_all(&raw).unwrap();
    std::fs::write(
        raw.join("dependencies.jsonl"),
        events
            .iter()
            .map(|event| format!("{event}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let case = crate::replay::test_support::recording::centralize_partitioned(&raw, &[]).await;
    let addr = "127.0.0.1:0".parse().unwrap();
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: case,
            selected_case_ids: vec![],
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(root.path().join("ca.pem")),
            ca_key_path: Some(root.path().join("key.pem")),
            policy_path: None,
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        },
        addr,
        addr,
    )
    .await
    .unwrap();
    (root, runtime)
}

async fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (server, client)
}

#[cfg(unix)]
#[tokio::test]
async fn pooled_successor_after_actual_wire_delivery_precedes_first_delivery_bookkeeping() {
    use std::os::fd::AsRawFd;
    let payload = vec![b'x'; 512 * 1024];
    let frame = [
        format!("VALUE first 0 {}\r\n", payload.len()).into_bytes(),
        payload,
        b"\r\nEND\r\n".to_vec(),
    ]
    .concat();
    let (_root, runtime) = runtime(&[
        event(1, 1, "first", &frame),
        event(1, 2, "second", b"END\r\n"),
    ])
    .await;
    let first = match_memcached_request(
        &runtime.state,
        &target(),
        MemcachedWireProtocol::Text,
        &request("first"),
    )
    .await
    .unwrap();
    let (mut server, mut client) = socket_pair().await;
    let buffer: libc::c_int = 4096;
    // SAFETY: server owns the live fd; the buffer pointer and size match SO_SNDBUF.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&buffer as *const libc::c_int).cast(),
                std::mem::size_of_val(&buffer) as libc::socklen_t,
            )
        },
        0
    );
    let shared = runtime.state.clone();
    let delivery = tokio::spawn(async move {
        let mut reader = MemcachedBufferedReader::new(&mut server, 64 * 1024 * 1024);
        deliver_memcached_exchange(&mut reader, &shared, &first, tokio::time::Instant::now())
            .await
            .unwrap();
    });
    let mut output = vec![0; frame.len()];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut output[..1]))
        .await
        .unwrap()
        .unwrap();
    // A tiny send buffer keeps the large response blocked until this client
    // drains it. Hold the actual ReplayState lock across that drain to force
    // wire publication before the first delivery can update native accounting.
    let mut state = runtime.state.lock().await;
    let wire = state.protocols.memcached.lifecycle.subscribe();
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut output[1..]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        wire.wait(tokio::time::Instant::now() + Duration::from_secs(3))
            .await,
        crate::replay::admission::WaitOutcome::Changed
    );
    assert_eq!(output, frame);
    assert_eq!(
        state.protocols.memcached.exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
    assert_eq!(state.protocols.memcached.events.matched_count, 0);
    let case = state.active_case_id.clone();
    let second = state
        .protocols
        .memcached
        .match_memcached(MemcachedMatchContext {
            active_case_id: case.as_deref(),
            target: &target(),
            wire_protocol: MemcachedWireProtocol::Text,
            request: &request("second"),
            policy: None,
            observed_at: Utc::now(),
        })
        .unwrap();
    assert_eq!(second.index, 1);
    drop(state);
    delivery.await.unwrap();
    let (mut server, mut client) = socket_pair().await;
    let mut reader = MemcachedBufferedReader::new(&mut server, 64 * 1024 * 1024);
    deliver_memcached_exchange(
        &mut reader,
        &runtime.state,
        &second,
        tokio::time::Instant::now(),
    )
    .await
    .unwrap();
    let mut output = [0; 5];
    client.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"END\r\n");
    let state = runtime.state.lock().await;
    assert_eq!(state.protocols.memcached.events.matched_count, 2);
    assert!(state.protocols.memcached.events.unmatched.is_empty());
    assert!(!state.protocols.memcached.has_in_flight());
}
