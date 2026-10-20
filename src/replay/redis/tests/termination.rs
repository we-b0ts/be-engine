use super::*;
use crate::dependency::{
    DependencyTermination, TerminationKind, TerminationScope, TerminationSide,
};
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

const GET: &[u8] = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";

fn termination(side: TerminationSide, kind: TerminationKind) -> DependencyExchangeOutcome {
    DependencyExchangeOutcome::Terminated(DependencyTermination {
        side,
        kind,
        scope: if kind == TerminationKind::Eof {
            TerminationScope::WriteHalf
        } else {
            TerminationScope::Connection
        },
    })
}

fn dependency(
    command: &str,
    outcome: DependencyExchangeOutcome,
    response: &str,
    duration_ms: u64,
) -> Value {
    json!({"event_type":"redis_exchange", "connection_id":Uuid::new_v4(), "sequence":1,
        "target_host":"redis.test", "target_port":6379,"resp_version":2,"database":0,"username":null,
        "command":command,"args":[capture("key")],"response_kind":"other","response":capture(response),
        "outcome":outcome,"duration_ms":duration_ms,"replay_safe":true})
}

async fn fixture(
    record: Value,
) -> (
    tempfile::TempDir,
    TcpStream,
    Arc<Mutex<ReplayState>>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    tokio::fs::create_dir_all(&case).await.unwrap();
    tokio::fs::write(
        case.join("dependencies.jsonl"),
        match record {
            Value::Array(records) => records
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            record => record.to_string(),
        },
    )
    .await
    .unwrap();
    crate::replay::write_test_recording_network_manifest(&case);
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: case.clone(),
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(case.join("ca.pem")),
            ca_key_path: Some(case.join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let (client, server) = tokio::join!(connect, listener.accept());
    let state = runtime.state.clone();
    let task = tokio::spawn(handle_connection(
        server.unwrap().0,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        state.clone(),
    ));
    (temp, client.unwrap(), state, task)
}

#[tokio::test]
async fn server_eof_replays_partial_prefix_and_preserves_request_half() {
    let (_temp, mut client, state, task) = fixture(dependency(
        "GET",
        termination(TerminationSide::Server, TerminationKind::Eof),
        "$5\r\npar",
        30,
    ))
    .await;
    let started = tokio::time::Instant::now();
    client.write_all(GET).await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, b"$5\r\npar");
    assert!(started.elapsed() >= Duration::from_millis(25));
    assert_eq!(state.lock().await.redis.snapshot().matched_count, 1);
    assert!(
        !task.is_finished(),
        "server FIN must preserve its request read direction"
    );
    client.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn server_reset_is_a_real_reset_and_consumes_failure_exchange() {
    let (_temp, mut client, state, task) = fixture(dependency(
        "GET",
        termination(TerminationSide::Server, TerminationKind::Reset),
        "",
        20,
    ))
    .await;
    client.write_all(GET).await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    task.await.unwrap().unwrap();
    assert_eq!(state.lock().await.redis.snapshot().matched_count, 1);
}

#[tokio::test]
async fn client_eof_is_observed_without_server_initiating_close() {
    let (_temp, mut client, state, task) = fixture(dependency(
        "GET",
        termination(TerminationSide::Client, TerminationKind::Eof),
        "",
        80,
    ))
    .await;
    client.write_all(GET).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(80), client.read(&mut [0]))
            .await
            .is_err()
    );
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(state.lock().await.redis.snapshot().matched_count, 1);
}

#[tokio::test]
async fn missed_client_close_deadline_marks_dirty_and_keeps_connection_open() {
    let (_temp, mut client, state, task) = fixture(dependency(
        "GET",
        termination(TerminationSide::Client, TerminationKind::Eof),
        "",
        10,
    ))
    .await;
    client.write_all(GET).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1150)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), client.read(&mut [0]))
            .await
            .is_err()
    );
    let snapshot = state.lock().await.redis.snapshot();
    assert_eq!(snapshot.matched_count, 0);
    assert!(!snapshot.unsafe_events.is_empty());
    assert!(!task.is_finished());
    client.shutdown().await.unwrap();
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("timing window")
    );
}

#[tokio::test]
async fn builtin_setup_failure_does_not_turn_into_a_success_reply() {
    let (_temp, mut client, state, task) = fixture(dependency(
        "AUTH",
        termination(TerminationSide::Server, TerminationKind::Eof),
        "",
        0,
    ))
    .await;
    client
        .write_all(b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n")
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(state.lock().await.redis.snapshot().matched_count, 1);
}

#[test]
fn redis_rejects_engine_cleanup_and_stream_scopes_even_when_marked_safe() {
    for outcome in [
        DependencyExchangeOutcome::Terminated(DependencyTermination {
            side: TerminationSide::Engine,
            kind: TerminationKind::Cancelled,
            scope: TerminationScope::Connection,
        }),
        DependencyExchangeOutcome::Terminated(DependencyTermination {
            side: TerminationSide::Client,
            kind: TerminationKind::Cancelled,
            scope: TerminationScope::Stream,
        }),
    ] {
        let mut state = RedisReplayState::default();
        let record = serde_json::from_value(dependency("GET", outcome, "", 0)).unwrap();
        assert!(
            state
                .register_exchange(
                    record,
                    ReplaySource::Case,
                    Some("case"),
                    &mut BTreeMap::new(),
                    &[]
                )
                .is_err()
        );
    }
}

#[tokio::test]
async fn server_close_consumes_each_pending_pipelined_request() {
    let first = dependency(
        "GET",
        termination(TerminationSide::Server, TerminationKind::Eof),
        "$5\r\npar",
        30,
    );
    let mut second = first.clone();
    second["sequence"] = 2.into();
    second["response"] = serde_json::to_value(capture("")).unwrap();
    let (_temp, mut client, state, task) = fixture(json!([first, second])).await;
    client.write_all(&[GET, GET].concat()).await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, b"$5\r\npar");
    assert_eq!(state.lock().await.redis.snapshot().matched_count, 2);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn target_close_before_server_failure_is_dirty() {
    let (_temp, mut client, state, task) = fixture(dependency(
        "GET",
        termination(TerminationSide::Server, TerminationKind::Eof),
        "",
        200,
    ))
    .await;
    client.write_all(GET).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    client.shutdown().await.unwrap();
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("before recorded server termination")
    );
    let report = state.lock().await.redis.snapshot();
    assert_eq!(report.matched_count, 0);
    assert!(!report.unsafe_events.is_empty());
}

#[tokio::test]
async fn client_fin_does_not_satisfy_recorded_client_reset() {
    let (_temp, mut client, state, task) = fixture(dependency(
        "GET",
        termination(TerminationSide::Client, TerminationKind::Reset),
        "",
        20,
    ))
    .await;
    client.write_all(GET).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    client.shutdown().await.unwrap();
    assert!(task.await.unwrap().is_err());
    let report = state.lock().await.redis.snapshot();
    assert_eq!(report.matched_count, 0);
    assert!(!report.unsafe_events.is_empty());
}

#[tokio::test]
async fn extra_request_after_server_fin_is_dirty_without_forcing_client_close() {
    let (_temp, mut client, state, task) = fixture(dependency(
        "GET",
        termination(TerminationSide::Server, TerminationKind::Eof),
        "",
        0,
    ))
    .await;
    client.write_all(GET).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    client.write_all(GET).await.unwrap();
    for _ in 0..50 {
        if !state.lock().await.redis.snapshot().unsafe_events.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!state.lock().await.redis.snapshot().unsafe_events.is_empty());
    assert!(!task.is_finished());
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn client_prefix_without_delivery_timing_cannot_be_marked_replayable() {
    let record = serde_json::from_value(dependency(
        "GET",
        termination(TerminationSide::Client, TerminationKind::Eof),
        "$5\r\npar",
        20,
    ))
    .unwrap();
    let error = RedisReplayState::default()
        .register_exchange(
            record,
            ReplaySource::Case,
            Some("case"),
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap_err();
    assert!(error.to_string().contains("delivery timing"));
}

async fn distinct_global_failures_keep_their_connection_identity(kind: TerminationKind) {
    let (_temp, mut client, state, task) = fixture(json!([])).await;
    {
        let mut state = state.lock().await;
        for _ in 0..2 {
            let mut record = dependency("GET", termination(TerminationSide::Server, kind), "", 20);
            record["global_dependency_reason"] = "background_rule".into();
            state
                .redis
                .register_exchange(
                    serde_json::from_value(record).unwrap(),
                    ReplaySource::Global,
                    None,
                    &mut BTreeMap::new(),
                    &[],
                )
                .unwrap();
        }
        assert!(
            state
                .redis
                .exchanges
                .iter()
                .all(|exchange| exchange.connection_independent)
        );
    }
    client.write_all(&[GET, GET].concat()).await.unwrap();
    // One Target close cannot stand in for failures on two Source connections.
    // The mismatch must remain visible while the Target still owns its socket.
    assert!(
        tokio::time::timeout(Duration::from_millis(150), client.read(&mut [0]))
            .await
            .is_err()
    );
    let report = state.lock().await.redis.snapshot();
    assert_eq!(report.matched_count, 0);
    assert!(!report.unsafe_events.is_empty());
    assert!(!task.is_finished());
    client.shutdown().await.unwrap();
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("recorded connection termination")
    );
}

#[tokio::test]
async fn distinct_global_eof_failures_cannot_share_one_target_close() {
    distinct_global_failures_keep_their_connection_identity(TerminationKind::Eof).await;
}

#[tokio::test]
async fn distinct_global_reset_failures_cannot_share_one_target_close() {
    distinct_global_failures_keep_their_connection_identity(TerminationKind::Reset).await;
}
