use super::*;
use crate::recording_upstream::RecordingUpstreams;

mod pooling;

const HOSTNAME: &str = "api.team.svc.cluster.local";

#[tokio::test]
async fn kubernetes_http_dials_forwarded_port_but_records_original_endpoint() {
    routed_exchange(false).await;
}

#[tokio::test]
async fn kubernetes_https_keeps_original_sni_and_host_with_a_different_dial_port() {
    routed_exchange(true).await;
}

async fn routed_exchange(secure: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.dns_mock.enabled = true;
    config.tcp_gateway.enabled = true;
    config.dns_mock.registry_path = temp.path().join("dns.json");
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.upstream_routes.push(crate::UpstreamRouteConfig {
        host: HOSTNAME.into(),
        via: crate::UpstreamTransportConfig::KubernetesPortForward {
            namespace: "team".into(),
            service: "api".into(),
        },
    });
    let state = crate::AppState::new(config).await.unwrap();
    assert!(state.recording_upstream(HOSTNAME, 8100).is_err());
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let mut routes = RecordingUpstreams::default();
    routes.insert(HOSTNAME, 8100, address).unwrap();
    state.install_recording_upstreams(routes).unwrap();
    assert_eq!(
        state
            .recording_upstream("API.TEAM.SVC.CLUSTER.LOCAL.", 8100)
            .unwrap(),
        Some(address)
    );
    assert!(state.recording_upstream(HOSTNAME, 9000).is_err());
    assert_eq!(
        state.recording_upstream("other.example", 8100).unwrap(),
        None
    );
    let tls_config = state.ca().server_config_for_host(HOSTNAME).unwrap();
    let upstream_server = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let service = service_fn(|request: Request<Incoming>| async move {
            assert_eq!(request.headers()[HOST], format!("{HOSTNAME}:8100"));
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/items?x=1"
            );
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"recorded"))))
        });
        if secure {
            let tls = TlsAcceptor::from(tls_config).accept(stream).await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .unwrap();
        } else {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        }
    });
    let fake_addr = "198.19.0.1:8100".parse().unwrap();
    let entry = FakeDnsEntry {
        domain: HOSTNAME.into(),
        fake_ip: Ipv4Addr::new(198, 19, 0, 1),
        real_ips: vec![Ipv4Addr::new(203, 0, 113, 99)],
        response_alias: false,
        upstream_authority: None,
        upstream_protocol: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let serving = state.clone();
    let gateway = tokio::spawn(async move {
        let (client, peer) = listener.accept().await.unwrap();
        if secure {
            serve_https_mitm_connection(client, fake_addr, entry, Some(peer.to_string()), serving)
                .await
                .unwrap();
        } else {
            serve_http_connection(client, fake_addr, entry, Some(peer.to_string()), serving)
                .await
                .unwrap();
        }
    });
    let exercise = async {
        let stream = TcpStream::connect(gateway_addr).await.unwrap();
        if secure {
            let mut roots = RootCertStore::empty();
            roots.add(state.ca().ca_cert_der()).unwrap();
            let client = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let tls = TlsConnector::from(Arc::new(client))
                .connect(ServerName::try_from(HOSTNAME.to_owned()).unwrap(), stream)
                .await
                .unwrap();
            request(TokioIo::new(tls)).await;
        } else {
            request(TokioIo::new(stream)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), exercise)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    gateway.abort();
    upstream_server.abort();
    state.recorder().flush_traffic().await.unwrap();
    let traffic =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    let events: Vec<serde_json::Value> = traffic
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "http_exchange"
                && event["authority"] == format!("{HOSTNAME}:8100")
                && event["response_status"] == 200)
    );
}

async fn request<T>(io: T)
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(io).await.unwrap();
    let connection = tokio::spawn(async move { connection.await.unwrap() });
    let response = sender
        .send_request(
            Request::builder()
                .uri("/items?x=1")
                .header(HOST, format!("{HOSTNAME}:8100"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "recorded"
    );
    drop(sender);
    connection.await.unwrap();
}
