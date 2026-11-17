use super::*;
use crate::config::{TcpApplicationProtocol, TcpProtocolOverrideConfig};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[test]
fn exact_override_wins_over_port_hints() {
    let mut config = crate::TcpProtocolDetectionConfig::default();
    config.overrides.push(TcpProtocolOverrideConfig {
        host: "cache.internal".to_string(),
        port: 6379,
        protocol: TcpApplicationProtocol::Raw,
    });
    assert_eq!(
        protocol_override(&config, "CACHE.INTERNAL.", 6379),
        Some(DetectedProtocol::Raw)
    );
}

#[tokio::test]
async fn configured_listener_accepts_connections() {
    let listener = bind_listener("127.0.0.1:0".parse().unwrap(), 4096).unwrap();
    let addr = listener.local_addr().unwrap();
    let client_task = tokio::spawn(TcpStream::connect(addr));

    let (_, peer_addr) = listener.accept().await.unwrap();

    assert!(peer_addr.ip().is_loopback());
    client_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn fragmented_sniff_waits_for_a_complete_command_without_consuming_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let command = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n".to_vec();
    let writer = command.clone();
    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        for byte in writer {
            client.write_all(&[byte]).await.unwrap();
            sleep(Duration::from_millis(2)).await;
        }
    });
    let (mut server, _) = listener.accept().await.unwrap();

    assert_eq!(
        peek_client_protocol(&server, &crate::protocols::default_providers())
            .await
            .unwrap(),
        Detection::Match(DetectedProtocol::Redis)
    );
    let mut actual = vec![0_u8; command.len()];
    server.read_exact(&mut actual).await.unwrap();
    assert_eq!(actual, command);
    client_task.await.unwrap();
}

#[tokio::test]
async fn delayed_http_client_is_still_routed_to_http_recorder() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config: crate::AppConfig =
        serde_yaml::from_str("capture: {dependencies: [http]}").unwrap();
    config.artifacts = None;
    config.recording.output_dir = temp.path().join("recordings");
    config.dns_mock.registry_path = temp.path().join("fake_dns_registry.json");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = crate::AppState::new(config).await.unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut preconnected, _) = upstream_listener.accept().await.unwrap();
        let mut eof = [0_u8; 1];
        assert_eq!(preconnected.read(&mut eof).await.unwrap(), 0);

        let (stream, _) = upstream_listener.accept().await.unwrap();
        let service = service_fn(|_req| async {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(hyper::header::CONNECTION, "close")
                    .body(Full::new(Bytes::from_static(b"missing")))
                    .unwrap(),
            )
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });

    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    let client = TcpStream::connect(gateway_addr).await.unwrap();
    let (proxy_client, peer_addr) = gateway_listener.accept().await.unwrap();
    let entry = FakeDnsEntry {
        domain: "example.test".to_string(),
        fake_ip: Ipv4Addr::new(198, 19, 0, 22),
        real_ips: vec![Ipv4Addr::LOCALHOST],
        response_alias: false,
        upstream_authority: None,
        upstream_protocol: None,
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
    };
    let fake_addr = SocketAddr::new(IpAddr::V4(entry.fake_ip), upstream_addr.port());
    let state_for_proxy = state.clone();
    let proxy = tokio::spawn(proxy_raw_tcp(
        proxy_client,
        fake_addr,
        entry,
        Some(peer_addr.to_string()),
        state_for_proxy,
        RawTcpOptions {
            record_connection: true,
            sniff_server_first_protocols: true,
            detected_protocol: None,
        },
    ));

    sleep(INITIAL_PEEK_TIMEOUT + Duration::from_millis(50)).await;
    let (mut sender, connection) = http1::handshake(TokioIo::new(client)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .method(Method::GET)
                .uri("/delayed")
                .header(HOST, "example.test")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"missing")
    );
    drop(sender);

    tokio::time::timeout(Duration::from_secs(1), proxy)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    upstream.await.unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let traffic =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    assert!(traffic.contains(r#""event_type":"http_exchange""#));
    assert!(traffic.contains(r#""uri":"/delayed""#));
    assert!(!traffic.contains(r#""event_type":"tcp_gateway_connection""#));
}

#[tokio::test]
async fn delayed_tls_client_is_still_routed_to_https_mitm() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config: crate::AppConfig =
        serde_yaml::from_str("capture: {dependencies: [http]}").unwrap();
    config.artifacts = None;
    config.recording.output_dir = temp.path().join("recordings");
    config.dns_mock.registry_path = temp.path().join("fake_dns_registry.json");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = crate::AppState::new(config).await.unwrap();

    let upstream_config = state.ca().server_config_for_host("example.test").unwrap();
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(upstream_config);
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let Ok(tls) = acceptor.accept(stream).await else {
                continue;
            };
            let service = service_fn(|_req| async {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(hyper::header::CONNECTION, "close")
                        .body(Full::new(Bytes::from_static(b"secure")))
                        .unwrap(),
                )
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .unwrap();
            break;
        }
    });

    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    let client = TcpStream::connect(gateway_addr).await.unwrap();
    let (proxy_client, peer_addr) = gateway_listener.accept().await.unwrap();
    let entry = FakeDnsEntry {
        domain: "example.test".to_string(),
        fake_ip: Ipv4Addr::new(198, 19, 0, 21),
        real_ips: vec![Ipv4Addr::LOCALHOST],
        response_alias: false,
        upstream_authority: None,
        upstream_protocol: None,
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
    };
    let fake_addr = SocketAddr::new(IpAddr::V4(entry.fake_ip), upstream_addr.port());
    let state_for_proxy = state.clone();
    let proxy = tokio::spawn(proxy_raw_tcp(
        proxy_client,
        fake_addr,
        entry,
        Some(peer_addr.to_string()),
        state_for_proxy,
        RawTcpOptions {
            record_connection: true,
            sniff_server_first_protocols: true,
            detected_protocol: None,
        },
    ));

    sleep(INITIAL_PEEK_TIMEOUT + Duration::from_millis(50)).await;
    let mut roots = RootCertStore::empty();
    roots.add(state.ca().ca_cert_der()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let tls = connector
        .connect(ServerName::try_from("example.test").unwrap(), client)
        .await
        .unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .method(Method::GET)
                .uri("/secure")
                .header(HOST, "example.test")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"secure")
    );
    drop(sender);

    tokio::time::timeout(Duration::from_secs(1), proxy)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    upstream.await.unwrap();
}

#[tokio::test]
async fn idle_detection_accepts_a_delayed_mysql_greeting() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_task = tokio::spawn(TcpStream::connect(client_listener.local_addr().unwrap()));
    let (proxy_client, _) = client_listener.accept().await.unwrap();
    let _client = client_task.await.unwrap().unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_task = tokio::spawn(TcpStream::connect(upstream_listener.local_addr().unwrap()));
    let (mut upstream_server, _) = upstream_listener.accept().await.unwrap();
    let proxy_upstream = upstream_task.await.unwrap().unwrap();
    let detection = tokio::spawn(async move {
        detect_protocol_when_data_arrives(
            &proxy_client,
            &proxy_upstream,
            &crate::protocols::default_providers(),
        )
        .await
    });

    sleep(INITIAL_PEEK_TIMEOUT + PARTIAL_PEEK_TIMEOUT + Duration::from_millis(200)).await;
    upstream_server
        .write_all(&[1, 0, 0, 0, 0x0a])
        .await
        .unwrap();

    assert_eq!(
        detection.await.unwrap().unwrap(),
        DetectedProtocol::Registered(crate::protocols::DependencyProtocol::Mysql)
    );
}

#[test]
fn direct_cache_snapshot_entry_forwards_to_the_original_ip() {
    let ip = Ipv4Addr::new(10, 20, 30, 40);
    let entry = direct_cache_snapshot_entry(ip);

    assert_eq!(entry.domain, "10.20.30.40");
    assert_eq!(entry.real_ips, [ip]);
    assert_eq!(
        upstream_addr(&entry, 6379).unwrap(),
        "10.20.30.40:6379".parse().unwrap()
    );
}
