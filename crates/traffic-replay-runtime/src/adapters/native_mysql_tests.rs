//! Application entrypoints install MySQL behind the shared finite inventory.
use super::*;
use crate::replay::{ReplayConfig, ReplayLifecycleConfig, ReplayRuntime};
use serde_json::json;
use std::{path::Path, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use traffic_protocol_mysql::{MysqlPacket, read_packet, write_packet};

async fn load(case: &Path, policies: bool, delay_ms: u64) -> (Arc<ReplayRuntime>, TcpListener) {
    std::fs::write(case.join("dependencies.jsonl"), json!({
        "event_type":"mysql_exchange", "connection_id":uuid::Uuid::nil(), "query_sequence":1,
        "target_host":"db.test", "target_port":3306, "database":"app", "username":"user",
        "command":"COM_QUERY", "sql":"SELECT id FROM items WHERE id=7", "duration_ms":delay_ms,
        "response":{"status":"resultset","columns":[{"name":"id","table":"items","column":"id","family":"integer","sql_type":"INT"}],
        "rows":[[{"kind":"integer","value":7}]]}
    }).to_string()).unwrap();
    crate::replay::write_test_recording_network_manifest(case);
    let mut providers = crate::protocols::default_providers().as_ref().clone();
    if policies {
        use traffic_contract::{
            codec::Codec,
            rule::{FieldContract, IdentityFormat},
        };
        use traffic_policy_value::{MessageSide, RuleBinding, ValueRule};
        for (side, selector) in [
            (MessageSide::Request, json!({"kind":"literal","index":0})),
            (
                MessageSide::Response,
                json!({"kind":"field","table":"items","column":"id"}),
            ),
        ] {
            providers
                .bindings_mut()
                .register(
                    "mysql",
                    side,
                    RuleBinding {
                        rule: Arc::new(ValueRule {
                            id: "entity".into(),
                            contract: FieldContract::Identity {
                                prefix: String::new(),
                                format: IdentityFormat::Decimal,
                            },
                        }),
                        selector,
                        codec: Codec::Json,
                        pointer: String::new(),
                    },
                    false,
                )
                .unwrap();
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let runtime = ReplayRuntime::load_with_providers(
        ReplayConfig {
            case_dir: case.into(),
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: address,
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
        address,
        ReplayLifecycleConfig::default(),
        Arc::new(providers),
    )
    .await
    .unwrap();
    (Arc::new(runtime), listener)
}

fn login(tls: bool) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    let flags = 0x0000_8208_u32
        | if tls {
            traffic_protocol_mysql::CLIENT_SSL
        } else {
            0
        };
    bytes[..4].copy_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(b"user\0\0app\0");
    bytes
}

async fn serve(
    runtime: &Arc<ReplayRuntime>,
    listener: TcpListener,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let state = runtime.state.clone();
    let ca = runtime.ca.clone();
    tokio::spawn(async move {
        let (socket, peer) = listener.accept().await?;
        let target = state.lock().await.targets[0].clone();
        RuntimeState::<ReplayProtocols>::serve_connection(socket, peer, Some(target), state, ca)
            .await
    })
}

async fn acknowledge(io: &mut (impl AsyncRead + AsyncWrite + Unpin), tls: bool) {
    write_packet(
        io,
        &MysqlPacket {
            sequence_id: if tls { 2 } else { 1 },
            payload: login(tls),
        },
    )
    .await
    .unwrap();
    assert_eq!(read_packet(io).await.unwrap().unwrap().payload[0], 0);
}

async fn query(io: &mut (impl AsyncRead + AsyncWrite + Unpin), id: u64) {
    write_packet(
        io,
        &MysqlPacket {
            sequence_id: 0,
            payload: [
                vec![3],
                format!("select id from items where id={id}").into_bytes(),
            ]
            .concat(),
        },
    )
    .await
    .unwrap();
    let column_count = read_packet(io).await.unwrap().unwrap();
    assert_eq!(column_count.sequence_id, 1);
    assert_eq!(column_count.payload, [1]);
    for sequence in 2..=3 {
        assert_eq!(
            read_packet(io).await.unwrap().unwrap().sequence_id,
            sequence
        );
    }
    let row = read_packet(io).await.unwrap().unwrap();
    assert_eq!(
        row.payload,
        traffic_protocol_mysql::values::lenenc_bytes(id.to_string().as_bytes())
    );
    assert_eq!(read_packet(io).await.unwrap().unwrap().sequence_id, 5);
    write_packet(
        io,
        &MysqlPacket {
            sequence_id: 0,
            payload: vec![1],
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn registered_value_policy_matches_sql_and_materializes_result_cells() {
    let root = tempfile::tempdir().unwrap();
    let (runtime, listener) = load(root.path(), true, 0).await;
    let address = listener.local_addr().unwrap();
    let task = serve(&runtime, listener).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    assert_eq!(
        read_packet(&mut socket).await.unwrap().unwrap().sequence_id,
        0
    );
    acknowledge(&mut socket, false).await;
    query(&mut socket, 99).await;
    task.await.unwrap().unwrap();
    let report = serde_json::to_value(runtime.state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["dependency_protocols"]["mysql"]["matched_count"], 1);
    assert!(
        report["dependency_protocols"]["mysql"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn client_ssl_uses_the_shared_replay_certificate_port() {
    let root = tempfile::tempdir().unwrap();
    let (runtime, listener) = load(root.path(), false, 0).await;
    let address = listener.local_addr().unwrap();
    let task = serve(&runtime, listener).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    read_packet(&mut socket).await.unwrap().unwrap();
    write_packet(
        &mut socket,
        &MysqlPacket {
            sequence_id: 1,
            payload: login(true)[..32].to_vec(),
        },
    )
    .await
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(runtime.ca.ca_cert_der()).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut socket = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("db.test").unwrap(),
            socket,
        )
        .await
        .unwrap();
    acknowledge(&mut socket, true).await;
    query(&mut socket, 7).await;
    task.await.unwrap().unwrap();
    let report = serde_json::to_value(runtime.state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["dependency_protocols"]["mysql"]["matched_count"], 1);
}

#[tokio::test]
async fn incomplete_command_input_retains_case_io_until_the_session_ends() {
    let root = tempfile::tempdir().unwrap();
    let (runtime, listener) = load(root.path(), false, 0).await;
    let address = listener.local_addr().unwrap();
    let task = serve(&runtime, listener).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    read_packet(&mut socket).await.unwrap().unwrap();
    acknowledge(&mut socket, false).await;
    socket.write_all(&[100, 0, 0, 0, 3]).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !runtime
            .state
            .lock()
            .await
            .native
            .inputs
            .has_case_in_flight()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!runtime.state.lock().await.native.inputs.has_in_flight());
}

#[tokio::test]
async fn cancelled_native_delivery_leaves_a_failed_claim_and_unused_source() {
    let root = tempfile::tempdir().unwrap();
    let (runtime, listener) = load(root.path(), false, 60_000).await;
    let address = listener.local_addr().unwrap();
    let task = serve(&runtime, listener).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    read_packet(&mut socket).await.unwrap().unwrap();
    acknowledge(&mut socket, false).await;
    write_packet(
        &mut socket,
        &MysqlPacket {
            sequence_id: 0,
            payload: [vec![3], b"SELECT id FROM items WHERE id=7".to_vec()].concat(),
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let state = runtime.state.lock().await;
            if state.native.core.exchanges.iter().any(|exchange| {
                matches!(
                    state
                        .native
                        .core
                        .lifecycle
                        .live_status(exchange.index, exchange.status),
                    replay::ReplayExchangeStatus::Responding
                )
            }) {
                break;
            }
            drop(state);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let state = runtime.state.lock().await;
    let exchange = &state.native.core.exchanges[0];
    assert_eq!(
        state.native.core.lifecycle.live_status(0, exchange.status),
        replay::ReplayExchangeStatus::Failed
    );
    let report = serde_json::to_value(state.snapshot_report()).unwrap();
    assert_eq!(
        report["dependency_protocols"]["mysql"]["unused_case"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
