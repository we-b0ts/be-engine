//! Finite HTTP uses the application entrypoint and shared registered value execution.
use crate::replay::{ReplayConfig, ReplayLifecycleConfig, ReplayRuntime};
use std::{path::Path, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn load(
    case: &Path,
    tls: bool,
    values: bool,
) -> (
    std::net::SocketAddr,
    Arc<ReplayRuntime>,
    tokio::task::JoinHandle<()>,
) {
    let authority = if tls { "api.test:443" } else { "api.test" };
    super::http_test_support::write_http_case(
        case,
        if tls { "https" } else { "http" },
        authority,
        "/items",
        r#"{"id":42,"fixed":"original"}"#,
        r#"{"id":42}"#,
    )
    .await;
    crate::replay::write_test_recording_network_manifest(case);
    let mut providers = crate::protocols::default_providers().as_ref().clone();
    if values {
        use traffic_contract::{
            codec::Codec,
            rule::{FieldContract, IdentityFormat},
        };
        use traffic_policy_value::{MessageSide, RuleBinding, ValueRule};
        for side in [MessageSide::Request, MessageSide::Response] {
            providers
                .bindings_mut()
                .register(
                    "http",
                    side,
                    RuleBinding {
                        rule: Arc::new(ValueRule {
                            id: "entity".into(),
                            contract: FieldContract::Identity {
                                prefix: String::new(),
                                format: IdentityFormat::Decimal,
                            },
                        }),
                        selector: serde_json::json!({"kind":"body"}),
                        codec: Codec::Json,
                        pointer: "/id".into(),
                    },
                    false,
                )
                .unwrap();
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let runtime = Arc::new(
        ReplayRuntime::load_with_providers(
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
                // Managed replay supplies config metadata with an empty host set.
                allowed_unused_http: Some(crate::ReplayAllowedUnusedHttpConfig {
                    config_path: case.join("project.yaml"),
                    hosts: Default::default(),
                }),
            },
            "127.0.0.1:0".parse().unwrap(),
            address,
            ReplayLifecycleConfig::default(),
            Arc::new(providers),
        )
        .await
        .unwrap(),
    );
    let service = runtime.clone();
    let task = tokio::spawn(async move {
        service.run_tcp(listener).await.unwrap();
    });
    (address, runtime, task)
}

async fn request(
    io: &mut (impl AsyncRead + AsyncWrite + Unpin),
    authority: &str,
    body: &str,
) -> Vec<u8> {
    let bytes = format!(
        "POST /items HTTP/1.1\r\nHost: {authority}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    io.write_all(bytes.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        io.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    response
}

#[tokio::test]
async fn registered_value_policy_matches_http_and_materializes_its_response() {
    let directory = tempfile::tempdir().unwrap();
    let (address, runtime, task) = load(directory.path(), false, true).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    let response = request(&mut socket, "api.test", r#"{"id":99,"fixed":"original"}"#).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(br#"{"id":99}"#));
    let state = runtime.state.lock().await;
    let report = serde_json::to_value(state.snapshot_report()).unwrap();
    assert_eq!(report["dependency_protocols"]["http"]["matched_count"], 1);
    assert!(
        report["dependency_protocols"]["http"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn https_alias_uses_the_native_http_provider_and_the_replay_ca() {
    let directory = tempfile::tempdir().unwrap();
    let (address, runtime, task) = load(directory.path(), true, false).await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(runtime.ca.ca_cert_der()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let stream = TcpStream::connect(address).await.unwrap();
    let mut socket = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("api.test").unwrap(),
            stream,
        )
        .await
        .unwrap();
    let response = request(
        &mut socket,
        "api.test:443",
        r#"{"id":42,"fixed":"original"}"#,
    )
    .await;
    assert!(response.ends_with(br#"{"id":42}"#));
    let report = serde_json::to_value(runtime.state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["dependency_protocols"]["http"]["matched_count"], 1);
    task.abort();
}
