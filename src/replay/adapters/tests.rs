//! Adapters observe genuine native wire delivery from a current sealed Source.
use super::*;
use crate::recorder::{
    CaseContext, MemcachedExchangeEvent, MotanExchangeEvent, Recorder, RecorderEvent, capture_body,
};
use crate::replay::{ReplayConfig, ReplayProtocol, ReplayRuntime, ReplayTarget};
use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

const CASE: Uuid = Uuid::from_u128(123);

fn motan_request() -> Vec<u8> {
    let mut metadata = motan_protocol::Metadata::new();
    metadata.insert(motan_protocol::META_GROUP, "contract-group");
    metadata.insert(motan_protocol::META_PATH, "example.EchoService");
    metadata.insert(motan_protocol::META_METHOD, "echo");
    metadata.insert(motan_protocol::META_METHOD_DESC, "java.lang.String");
    motan_protocol::FrameBuilder::request(91)
        .metadata(metadata)
        .serialization(0)
        .encode()
        .unwrap()
        .to_vec()
}

async fn source(
    root: &std::path::Path,
    connection: Uuid,
    raw: &[u8],
    response: &[u8],
) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(root.join(crate::repository::LOCAL_ROOT))?;
    crate::platform::encryption_key::load_or_create(root)?;
    let recorder =
        Recorder::new(root.join(crate::repository::LOCAL_ROOT).join("recordings")).await?;
    let case = CaseContext {
        id: CASE,
        rule_name: "native-contract".into(),
        uri_group: None,
    };
    for (host, port) in [("cache.test", 11211), ("motan.test", 8002)] {
        recorder.observe_accessed_endpoint(host, port).await?;
    }
    recorder
        .append_case_dependency(
            &case,
            &RecorderEvent::MemcachedExchange(MemcachedExchangeEvent {
                id: Uuid::new_v4(),
                connection_id: connection,
                sequence: 1,
                request_started_at: Utc::now(),
                timestamp: Utc::now(),
                client_addr: None,
                target_host: "cache.test".into(),
                target_port: 11211,
                target_addr: "cache.test:11211".into(),
                upstream_addr: "cache.test:11211".into(),
                wire_protocol: "text".into(),
                command: "get".into(),
                opcode: None,
                opaque: None,
                key: Some(capture_body(b"key", 1024)),
                args: vec![],
                value: None,
                extras: None,
                cas: None,
                noreply: false,
                quiet: false,
                response_status: "0".into(),
                response_frames: vec![capture_body(b"VALUE key 0 5\r\nvalue\r\nEND\r\n", 1024)],
                response_frame_offsets_ms: vec![],
                no_response: false,
                outcome: crate::DependencyExchangeOutcome::Response,
                duration_ms: 0,
                replay_safe: true,
                parse_warnings: vec![],
            }),
            "fixture_request_admission",
        )
        .await?;
    recorder
        .append_case_dependency(
            &case,
            &RecorderEvent::MotanExchange(MotanExchangeEvent {
                id: Uuid::new_v4(),
                connection_id: connection,
                sequence: 2,
                timestamp: Utc::now(),
                client_addr: None,
                target_host: "motan.test".into(),
                target_port: 8002,
                target_addr: "motan.test:8002".into(),
                advertised_ip: "198.18.0.2".parse()?,
                upstream_addr: "motan.test:8002".into(),
                codec_version: 0,
                group: Some("contract-group".into()),
                interface_name: Some("example.EchoService".into()),
                method_name: Some("echo".into()),
                parameter_desc: Some("java.lang.String".into()),
                method_sign: None,
                command: "example.EchoService#echo".into(),
                request: capture_body(raw, 1024 * 1024),
                response_status: "normal".into(),
                response: capture_body(response, 1024 * 1024),
                heartbeat: false,
                outcome: crate::DependencyExchangeOutcome::Response,
                duration_ms: 0,
                replay_safe: true,
                parse_warnings: vec![],
            }),
            "fixture_request_admission",
        )
        .await?;
    recorder
        .write_case_json(&case, "admission.json", &json!({"fixture":true}))
        .await?;
    recorder
        .write_case_json(
            &case,
            "request.json",
            &json!({"method":"GET","uri":"/api","timestamp":"2020-01-01T00:00:00Z"}),
        )
        .await?;
    recorder
        .write_case_json(&case, "expected-response.json", &json!({"status":200}))
        .await?;
    recorder.publish_case(&case).await?;
    recorder.finish_run().await?;
    Ok(recorder.case_dir(&case))
}

async fn runtime(case: std::path::PathBuf, root: &std::path::Path) -> ReplayRuntime {
    let addr = "127.0.0.1:0".parse().unwrap();
    ReplayRuntime::load(
        ReplayConfig {
            case_dir: case,
            selected_case_ids: vec![],
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(root.join("ca.pem")),
            ca_key_path: Some(root.join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        },
        addr,
        addr,
    )
    .await
    .unwrap()
}

async fn native_connection(
    state: Arc<Mutex<crate::replay::ReplayState>>,
    protocol: ReplayProtocol,
) -> (TcpStream, tokio::task::JoinHandle<Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let (host, port) = match protocol {
            ReplayProtocol::Memcached => ("cache.test", 11211),
            ReplayProtocol::Motan => ("motan.test", 8002),
            _ => unreachable!(),
        };
        let target = ReplayTarget {
            host: host.into(),
            port,
            fake_ip: "198.18.0.2".parse()?,
            protocol,
        };
        match protocol {
            ReplayProtocol::Memcached => {
                crate::replay::memcached::handle_connection(stream, target, state).await
            }
            ReplayProtocol::Motan => {
                crate::replay::motan::handle_connection(stream, target, state).await
            }
            _ => unreachable!(),
        }
    });
    (TcpStream::connect(address).await.unwrap(), task)
}

#[tokio::test]
async fn memcached_and_motan_registry_handles_wait_for_real_native_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let connection = Uuid::new_v4();
    let raw = motan_request();
    let mut response = Vec::new();
    motan_protocol::encode_empty_response(
        motan_protocol::parse_frame_ref(&raw, motan_protocol::Limits::default()).unwrap(),
        &mut response,
        motan_protocol::Limits::default(),
    )
    .unwrap();
    let runtime = runtime(
        source(temp.path(), connection, &raw, &response)
            .await
            .unwrap(),
        temp.path(),
    )
    .await;
    let references = [
        RecordedReference::Memcached {
            connection_id: connection,
            sequence: 1,
        },
        RecordedReference::Motan {
            connection_id: connection,
            sequence: 2,
        },
    ];
    let handles = {
        let state = runtime.state.lock().await;
        assert!(
            resolve_case(&state, "another-case", &references, |reference, handle| (
                reference, handle
            ))
            .is_err()
        );
        let handles = resolve_case(
            &state,
            &CASE.to_string(),
            &references,
            |reference, handle| (reference, handle),
        )
        .unwrap();
        assert!(
            handles
                .iter()
                .all(|(_, handle)| handle.delivery_state(&state)
                    == Some(ReplayExchangeStatus::Available))
        );
        handles
    };
    let (mut memcached, memcached_task) =
        native_connection(runtime.state.clone(), ReplayProtocol::Memcached).await;
    memcached.write_all(b"get key\r\n").await.unwrap();
    let expected = b"VALUE key 0 5\r\nvalue\r\nEND\r\n";
    let mut got = vec![0; expected.len()];
    memcached.read_exact(&mut got).await.unwrap();
    assert_eq!(got, expected);
    let (mut motan, motan_task) =
        native_connection(runtime.state.clone(), ReplayProtocol::Motan).await;
    motan.write_all(&raw).await.unwrap();
    let mut got = vec![0; response.len()];
    motan.read_exact(&mut got).await.unwrap();
    assert_eq!(got, response);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state = runtime.state.lock().await;
            if handles.iter().all(|(_, handle)| {
                handle.delivery_state(&state) == Some(ReplayExchangeStatus::Consumed)
            }) {
                break;
            }
            drop(state);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = runtime.state.lock().await;
    assert!(
        handles
            .iter()
            .all(|(_, handle)| !handle.permits_unstarted_omission(&state, true, false))
    );
    drop(state);
    memcached_task.abort();
    motan_task.abort();
}
