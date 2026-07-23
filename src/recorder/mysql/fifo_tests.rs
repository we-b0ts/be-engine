use std::time::Duration;

use tempfile::tempdir;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::AppConfig;

#[tokio::test]
async fn records_pipelined_query_and_ping_responses_in_fifo_order() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client = tokio::spawn(TcpStream::connect(client_addr));
    let (proxy_client, _) = client_listener.accept().await.unwrap();
    let mut client = client.await.unwrap().unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let proxy_upstream = tokio::spawn(TcpStream::connect(upstream_addr));
    let (mut upstream, _) = upstream_listener.accept().await.unwrap();
    let proxy_upstream = proxy_upstream.await.unwrap().unwrap();

    let handler = tokio::spawn(handle_connected_mysql(
        proxy_client,
        proxy_upstream,
        state.clone(),
        MysqlConnectionContext {
            route_name: Some("test".to_string()),
            listen_addr: client_addr.to_string(),
            client_addr: None,
            target_host: Some("mysql.test".to_string()),
            target_port: Some(3306),
            target_addr: Some("mysql.test:3306".to_string()),
            upstream_addr: upstream_addr.to_string(),
        },
    ));

    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 0,
                payload: vec![0x0a],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert!(read_packet(&mut client).await.unwrap().is_some());

    client
        .write_all(
            &MysqlPacket {
                sequence_id: 1,
                payload: login_payload("pluto"),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert!(read_packet(&mut upstream).await.unwrap().is_some());
    upstream
        .write_all(&ok_packet(2).to_wire_bytes())
        .await
        .unwrap();
    assert!(read_packet(&mut client).await.unwrap().is_some());

    let sql = "SELECT 2";
    let query = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x03], sql.as_bytes().to_vec()].concat(),
    };
    let ping = MysqlPacket {
        sequence_id: 0,
        payload: vec![0x0e],
    };
    let mut pipelined = query.to_wire_bytes();
    pipelined.extend_from_slice(&ping.to_wire_bytes());
    client.write_all(&pipelined).await.unwrap();

    assert_eq!(
        read_packet(&mut upstream).await.unwrap().unwrap().payload,
        query.payload
    );
    assert_eq!(
        read_packet(&mut upstream).await.unwrap().unwrap().payload,
        ping.payload
    );

    for packet in select_two_resultset()
        .into_iter()
        .chain(std::iter::once(ok_packet(1)))
    {
        upstream.write_all(&packet.to_wire_bytes()).await.unwrap();
    }
    for _ in 0..6 {
        assert!(read_packet(&mut client).await.unwrap().is_some());
    }

    client.shutdown().await.unwrap();
    drop(client);
    assert!(read_packet(&mut upstream).await.unwrap().is_none());
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    let exchanges = traffic
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["event_type"] == "mysql_exchange")
        .collect::<Vec<_>>();

    let query_exchange = exchanges
        .iter()
        .find(|event| event["command"] == "COM_QUERY" && event["sql"] == sql)
        .expect("query exchange");
    assert_eq!(query_exchange["query_sequence"], 1);
    assert_eq!(query_exchange["response"]["status"], "resultset");
    assert_eq!(query_exchange["response"]["row_count"], 1);
    assert!(
        query_exchange["parse_warnings"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let ping_exchange = exchanges
        .iter()
        .find(|event| event["command"] == "COM_PING")
        .expect("ping exchange");
    assert_eq!(ping_exchange["query_sequence"], 2);
    assert_eq!(ping_exchange["response"]["status"], "ok");
    assert!(!exchanges.iter().any(|event| {
        event["response"]["status"] == "incomplete"
            && (event["query_sequence"] == 1 || event["query_sequence"] == 2)
    }));
}

fn login_payload(database: &str) -> Vec<u8> {
    let mut payload = vec![0_u8; 32];
    payload[0..4].copy_from_slice(&crate::mysql::wire::CLIENT_CONNECT_WITH_DB.to_le_bytes());
    payload.extend_from_slice(b"recorder-test\0");
    payload.push(0);
    payload.extend_from_slice(database.as_bytes());
    payload.push(0);
    payload
}

fn ok_packet(sequence_id: u8) -> MysqlPacket {
    MysqlPacket {
        sequence_id,
        payload: vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
    }
}

fn select_two_resultset() -> Vec<MysqlPacket> {
    vec![
        packet(1, vec![1]),
        packet(2, column_definition()),
        packet(3, vec![0xfe, 0, 0, 0, 0]),
        packet(4, vec![1, b'2']),
        packet(5, vec![0xfe, 0, 0, 0, 0]),
    ]
}

fn column_definition() -> Vec<u8> {
    let mut payload = Vec::new();
    for field in [b"def".as_slice(), b"pluto", b"", b"", b"2", b"2"] {
        payload.push(field.len() as u8);
        payload.extend_from_slice(field);
    }
    payload.push(0x0c);
    payload.extend_from_slice(&33_u16.to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.push(3);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&[0, 0]);
    payload
}

fn packet(sequence_id: u8, payload: Vec<u8>) -> MysqlPacket {
    MysqlPacket {
        sequence_id,
        payload,
    }
}
