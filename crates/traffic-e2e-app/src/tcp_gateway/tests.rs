use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::dns_mock::FakeDnsEntry;

use super::*;
mod stream_cancellation;
mod upstream_routes;

#[tokio::test]
async fn mitms_fake_ip_https_and_records_exchange() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = crate::AppState::new(config).await.unwrap();

    let upstream_config = state.ca().server_config_for_host("example.test").unwrap();
    let upstream_addr = spawn_https_upstream(upstream_config).await;
    let entry = FakeDnsEntry {
        domain: "example.test".to_string(),
        fake_ip: Ipv4Addr::new(198, 18, 0, 1),
        real_ips: vec![Ipv4Addr::new(127, 0, 0, 1)],
        response_alias: false,
        upstream_authority: None,
        upstream_protocol: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let fake_addr = SocketAddr::new(IpAddr::V4(entry.fake_ip), upstream_addr.port());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let state_for_gateway = state.clone();
    let gateway = tokio::spawn(async move {
        let (client, peer) = listener.accept().await.unwrap();
        serve_https_mitm_connection(
            client,
            fake_addr,
            entry,
            Some(peer.to_string()),
            state_for_gateway,
        )
        .await
        .unwrap();
    });

    let stream = TcpStream::connect(gateway_addr).await.unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(state.ca().ca_cert_der()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("example.test".to_string()).unwrap();
    let tls = connector.connect(server_name, stream).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::builder()
        .method(Method::GET)
        .uri("/secure")
        .header(HOST, "example.test")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"secure");
    drop(sender);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    gateway.abort();
    state.recorder().flush_traffic().await.unwrap();

    let run_dir = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .unwrap();
    let jsonl = tokio::fs::read_to_string(run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""event_type":"http_exchange""#));
    assert!(jsonl.contains(r#""scheme":"fake_ip_https""#));
    assert!(jsonl.contains("/secure"));
}

#[tokio::test]
async fn terminates_alias_https_and_forwards_plain_http_to_managed_proxy() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = crate::AppState::new(config).await.unwrap();

    let upstream_addr = spawn_http_upstream().await;
    let alias = "k8s-cluster.pluto-eci.trp.test";
    let entry = FakeDnsEntry {
        domain: alias.to_string(),
        fake_ip: Ipv4Addr::new(198, 18, 0, 2),
        real_ips: vec![Ipv4Addr::LOCALHOST],
        response_alias: true,
        upstream_authority: Some(upstream_addr.to_string()),
        upstream_protocol: Some(FakeDnsUpstreamProtocol::Http),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let fake_addr = SocketAddr::new(IpAddr::V4(entry.fake_ip), upstream_addr.port());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let state_for_gateway = state.clone();
    let gateway = tokio::spawn(async move {
        let (client, peer) = listener.accept().await.unwrap();
        serve_https_mitm_connection(
            client,
            fake_addr,
            entry,
            Some(peer.to_string()),
            state_for_gateway,
        )
        .await
        .unwrap();
    });

    let stream = TcpStream::connect(gateway_addr).await.unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(state.ca().ca_cert_der()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from(alias.to_string()).unwrap();
    let tls = connector.connect(server_name, stream).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let response = sender
        .send_request(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/pods")
                .header(HOST, format!("{alias}:{}", upstream_addr.port()))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"plain kubectl proxy");
    drop(sender);
    gateway.await.unwrap();
}

async fn spawn_https_upstream(config: Arc<rustls::ServerConfig>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let acceptor = TlsAcceptor::from(config);
        let tls = acceptor.accept(stream).await.unwrap();
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
    });
    addr
}

async fn spawn_http_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|_req| async {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONNECTION, "close")
                    .body(Full::new(Bytes::from_static(b"plain kubectl proxy")))
                    .unwrap(),
            )
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });
    addr
}
