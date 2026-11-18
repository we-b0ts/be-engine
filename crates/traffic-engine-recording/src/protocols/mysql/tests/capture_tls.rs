//! Native capture terminates CLIENT_SSL on both sides through the shared host.
use super::*;

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap());
    let (client, server) = tokio::join!(client, listener.accept());
    (client.unwrap(), server.unwrap().0)
}

#[tokio::test]
async fn client_ssl_records_semantic_queries_with_an_independent_upstream_ca() {
    tokio::time::timeout(Duration::from_secs(8), capture())
        .await
        .unwrap();
}

async fn capture() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temporary = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temporary.path().join("recordings");
    config.tls.ca_cert_path = temporary.path().join("recorder-ca.pem");
    config.tls.ca_key_path = temporary.path().join("recorder-key.pem");
    let state = AppState::new(config).await.unwrap();
    let (mut client, proxy_client) = pair().await;
    let (mut upstream, proxy_upstream) = pair().await;
    let handler = tokio::spawn(crate::recorder::native::handle_connected(
        crate::protocols::DependencyProtocol::Mysql,
        proxy_client,
        proxy_upstream,
        state.clone(),
        traffic_protocol::connection::ConnectionInfo {
            endpoint: traffic_protocol::connection::Endpoint {
                host: "mysql.test".into(),
                port: 3306,
            },
            client_addr: None,
            upstream_addr: None,
            max_frame_bytes: 1024 * 1024,
        },
    ));
    let flags = traffic_protocol_mysql::CLIENT_SSL | 0x8200 | CLIENT_CONNECT_WITH_DB;
    write_packet(
        &mut upstream,
        &MysqlPacket {
            sequence_id: 0,
            payload: server_handshake_payload(flags),
        },
    )
    .await
    .unwrap();
    read_packet(&mut client).await.unwrap().unwrap();
    let mut login = login_payload("app");
    login[..4].copy_from_slice(&flags.to_le_bytes());
    write_packet(
        &mut client,
        &MysqlPacket {
            sequence_id: 1,
            payload: login[..32].to_vec(),
        },
    )
    .await
    .unwrap();
    let ssl = read_packet(&mut upstream).await.unwrap().unwrap();
    assert!(parse_handshake_response(&ssl).tls_requested);

    let upstream_ca = crate::MitmCa::load_or_generate(
        temporary.path().join("upstream-ca.pem"),
        temporary.path().join("upstream-key.pem"),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(
        upstream_ca
            .mysql_server_config_for_host("mysql.test")
            .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(state.ca().ca_cert_der()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let (client_tls, upstream_tls) = tokio::join!(
        connector.connect(
            rustls::pki_types::ServerName::try_from("mysql.test").unwrap(),
            client
        ),
        acceptor.accept(upstream),
    );
    let mut client = client_tls.unwrap();
    let mut upstream = upstream_tls.unwrap();
    write_packet(
        &mut client,
        &MysqlPacket {
            sequence_id: 2,
            payload: login,
        },
    )
    .await
    .unwrap();
    let login = read_packet(&mut upstream).await.unwrap().unwrap();
    assert_eq!(
        parse_handshake_response(&login).database.as_deref(),
        Some("app")
    );
    let ok = |sequence_id| MysqlPacket {
        sequence_id,
        payload: vec![0, 0, 0, 2, 0, 0, 0],
    };
    write_packet(&mut upstream, &ok(3)).await.unwrap();
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload[0],
        0
    );
    write_packet(
        &mut client,
        &MysqlPacket {
            sequence_id: 0,
            payload: b"\x03SELECT 1".to_vec(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        read_packet(&mut upstream).await.unwrap().unwrap().payload,
        b"\x03SELECT 1"
    );
    write_packet(&mut upstream, &ok(1)).await.unwrap();
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload[0],
        0
    );
    loop {
        state.recorder().flush_traffic().await.unwrap();
        let traffic = crate::recorder::test_io::read_to_string(
            state.recorder().run_dir.join("traffic.jsonl"),
        )
        .await
        .unwrap();
        if let Some(event) = traffic
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|event| event["event_type"] == "mysql_exchange")
        {
            assert_eq!(event["sql"], "SELECT 1");
            assert_eq!(event["response"]["status"], "ok");
            assert_eq!(event["outcome"], "response");
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    handler.abort();
}
