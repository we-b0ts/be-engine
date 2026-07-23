use super::*;

use std::time::Duration;

use tempfile::tempdir;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::mysql::wire::{CLIENT_COMPRESS, CLIENT_CONNECT_WITH_DB};
use crate::{
    AppConfig, MysqlWriteOperation, RecordingAccessPolicy, RecordingAccessRuleConfig,
    RecordingAccessRuleEffect,
};

#[test]
fn aggregates_resultset_packets_into_one_response() {
    let mut tracker = MysqlResponseTracker::new(1024, true);
    tracker.start_query(Uuid::nil(), 7, "COM_STMT_EXECUTE".to_string(), None, None);

    assert!(
        observe_payload(&mut tracker, 1, &[1]).is_none(),
        "column-count packet should not finish the response"
    );
    assert!(
        observe_payload(&mut tracker, 2, b"column").is_none(),
        "column definition packet should not finish the response"
    );
    assert!(
        observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none(),
        "first EOF ends column definitions only"
    );
    assert!(
        observe_payload(&mut tracker, 4, &[0x00, b'r', b'o', b'w']).is_none(),
        "binary row payloads may start with 0x00 and must not finish as OK"
    );

    let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0])
        .expect("second EOF should finish the response");
    assert_eq!(response.query_sequence, 7);
    assert_eq!(response.status, "resultset");
    assert_eq!(response.packet_count, 5);
    assert_eq!(response.payload_bytes, 21);
    assert_eq!(response.payload.original_len, 21);
    assert_eq!(response.payload.stored_len, 21);
    assert!(!response.payload.truncated);
    let packets = response.packets.expect("raw packets should be recorded");
    assert_eq!(packets[3].packet_kind, "result_or_data");
    assert_eq!(packets[3].payload.original_len, 4);
}

#[test]
fn response_payload_is_concatenated_and_truncated() {
    let mut tracker = MysqlResponseTracker::new(4, false);
    tracker.start_query(Uuid::nil(), 8, "COM_STMT_EXECUTE".to_string(), None, None);

    assert!(observe_payload(&mut tracker, 1, &[1]).is_none());
    assert!(observe_payload(&mut tracker, 2, b"abc").is_none());
    assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
    assert!(observe_payload(&mut tracker, 4, b"row").is_none());
    let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0]).unwrap();

    assert_eq!(response.payload_bytes, 17);
    assert_eq!(response.payload.original_len, 17);
    assert_eq!(response.payload.stored_len, 4);
    assert!(response.payload.truncated);
    assert!(response.packets.is_none());
}

#[test]
fn raw_packets_can_be_recorded_when_enabled() {
    let mut tracker = MysqlResponseTracker::new(4, true);
    tracker.start_query(Uuid::nil(), 9, "COM_STMT_EXECUTE".to_string(), None, None);

    assert!(observe_payload(&mut tracker, 1, &[1]).is_none());
    assert!(observe_payload(&mut tracker, 2, b"abcdef").is_none());
    assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
    assert!(observe_payload(&mut tracker, 4, b"row").is_none());
    let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0]).unwrap();

    let packets = response.packets.expect("raw packets should be recorded");
    assert_eq!(packets[1].payload_len, 6);
    assert_eq!(packets[1].payload.original_len, 6);
    assert_eq!(packets[1].payload.stored_len, 4);
    assert!(packets[1].payload.truncated);
}

#[test]
fn aggregates_stmt_prepare_until_expected_eofs() {
    let mut tracker = MysqlResponseTracker::new(1024, false);
    tracker.start_query(Uuid::nil(), 3, "COM_STMT_PREPARE".to_string(), None, None);

    let mut prepare_ok = vec![0x00];
    prepare_ok.extend_from_slice(&1_u32.to_le_bytes());
    prepare_ok.extend_from_slice(&1_u16.to_le_bytes());
    prepare_ok.extend_from_slice(&1_u16.to_le_bytes());
    prepare_ok.push(0);
    prepare_ok.extend_from_slice(&0_u16.to_le_bytes());

    assert!(observe_payload(&mut tracker, 1, &prepare_ok).is_none());
    assert!(observe_payload(&mut tracker, 2, b"param").is_none());
    assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
    assert!(observe_payload(&mut tracker, 4, b"column").is_none());
    let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0])
        .expect("stmt prepare should finish after param and column EOF packets");
    assert_eq!(response.status, "stmt_prepare");
    assert_eq!(response.packet_count, 5);
    assert!(response.packets.is_none());
}

#[tokio::test]
async fn blocked_query_returns_mysql_error_without_reaching_upstream() {
    assert_blocked_query("UPDATE users SET active = 1").await;
}

#[tokio::test]
async fn blocked_select_for_update_returns_mysql_error_without_reaching_upstream() {
    assert_blocked_query("SELECT * FROM users WHERE id = 1 FOR UPDATE").await;
}

#[tokio::test]
async fn pending_query_uses_uncompressed_framing_and_records_client_termination() {
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
            client_process: None,
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
                payload: server_handshake_payload(CLIENT_COMPRESS),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    let forwarded_handshake = read_packet(&mut client).await.unwrap().unwrap();
    assert_eq!(
        server_lower_capability_flags(&forwarded_handshake.payload) & CLIENT_COMPRESS as u16,
        0
    );
    let mut compressed_login_payload = login_payload("pluto");
    compressed_login_payload[0..4]
        .copy_from_slice(&(CLIENT_CONNECT_WITH_DB | CLIENT_COMPRESS).to_le_bytes());
    client
        .write_all(
            &MysqlPacket {
                sequence_id: 1,
                payload: compressed_login_payload,
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    let forwarded_login = read_packet(&mut upstream).await.unwrap().unwrap();
    assert_eq!(
        parse_handshake_response(&forwarded_login).capability_flags & CLIENT_COMPRESS,
        0
    );
    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 2,
                payload: vec![0x00],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert!(read_packet(&mut client).await.unwrap().is_some());

    let sql = "SELECT timeout_value";
    client
        .write_all(
            &MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], sql.as_bytes().to_vec()].concat(),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    let forwarded = read_packet(&mut upstream).await.unwrap().unwrap();
    assert_eq!(&forwarded.payload[1..], sql.as_bytes());
    tokio::time::sleep(Duration::from_millis(60)).await;
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
    let raw = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    let exchange = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["event_type"] == "mysql_exchange" && value["sql"] == sql)
        .unwrap();
    assert_eq!(exchange["outcome"], "client_terminated");
    assert_eq!(exchange["response"]["status"], "client_terminated");
    assert!(exchange["parse_warnings"].as_array().unwrap().is_empty());
    assert!(exchange["duration_ms"].as_u64().unwrap() >= 50);
}

async fn assert_blocked_query(sql: &str) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = RecordingAccessPolicy::BlockKnownWrites;
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
            client_process: None,
            target_host: Some("mysql.test".to_string()),
            target_port: Some(3306),
            target_addr: Some("mysql.test:3306".to_string()),
            upstream_addr: upstream_addr.to_string(),
        },
    ));

    let handshake = MysqlPacket {
        sequence_id: 0,
        payload: vec![0x0a],
    };
    upstream
        .write_all(&handshake.to_wire_bytes())
        .await
        .unwrap();
    assert!(read_packet(&mut client).await.unwrap().is_some());

    let login = MysqlPacket {
        sequence_id: 1,
        payload: vec![0_u8; 32],
    };
    client.write_all(&login.to_wire_bytes()).await.unwrap();
    assert!(read_packet(&mut upstream).await.unwrap().is_some());
    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 2,
                payload: vec![0x00],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert!(read_packet(&mut client).await.unwrap().is_some());

    let query = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x03], sql.as_bytes().to_vec()].concat(),
    };
    client.write_all(&query.to_wire_bytes()).await.unwrap();
    let rejection = tokio::time::timeout(Duration::from_secs(1), read_packet(&mut client))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(rejection.payload[0], 0xff);
    assert_eq!(
        u16::from_le_bytes([rejection.payload[1], rejection.payload[2]]),
        1290
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), read_packet(&mut upstream))
            .await
            .is_err()
    );

    state.recorder().flush_traffic().await.unwrap();
    let traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(traffic.contains(r#""event_type":"readonly_rejection""#));
    assert!(traffic.contains(r#""protocol":"mysql""#));
    assert!(traffic.contains(r#""operation_class":"write""#));
    assert!(traffic.contains(r#""operation":"COM_QUERY""#));
    assert!(!traffic.contains(sql));
    handler.abort();
}

#[tokio::test]
async fn allowed_insert_reaches_upstream_and_records_exchange_and_audit() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = RecordingAccessPolicy::BlockKnownWrites;
    config.recording.access_rules = vec![RecordingAccessRuleConfig::Mysql {
        name: "allow-request-log".to_string(),
        effect: RecordingAccessRuleEffect::Allow,
        operations: vec![MysqlWriteOperation::Insert],
        routes: vec!["test".to_string()],
        targets: Vec::new(),
        databases: vec!["pluto".to_string()],
        tables: vec!["request_log".to_string()],
    }];
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
            client_process: None,
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
        .write_all(
            &MysqlPacket {
                sequence_id: 2,
                payload: vec![0x00],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert!(read_packet(&mut client).await.unwrap().is_some());

    let sql = "INSERT INTO request_log(message) VALUES ('recorded')";
    client
        .write_all(
            &MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], sql.as_bytes().to_vec()].concat(),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    let forwarded = tokio::time::timeout(Duration::from_secs(1), read_packet(&mut upstream))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&forwarded.payload[1..], sql.as_bytes());
    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 1,
                payload: vec![0x00],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    let response = read_packet(&mut client).await.unwrap().unwrap();
    assert_eq!(response.payload[0], 0x00);

    let mut traffic = String::new();
    for _ in 0..100 {
        state.recorder().flush_traffic().await.unwrap();
        traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
        if traffic.contains(r#""event_type":"mysql_exchange""#) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(traffic.contains(r#""event_type":"access_policy_allow""#));
    assert!(traffic.contains(r#""rule":"allow-request-log""#));
    assert!(traffic.contains(r#""resources":["pluto.request_log"]"#));
    assert!(traffic.contains(r#""event_type":"mysql_exchange""#));
    assert!(traffic.contains(sql));
    assert!(!traffic.contains(r#""event_type":"readonly_rejection""#));
    handler.abort();
}

#[tokio::test]
async fn stmt_close_is_forwarded_without_recording_an_incomplete_exchange() {
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
            client_process: None,
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
        .write_all(
            &MysqlPacket {
                sequence_id: 2,
                payload: vec![0x00],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert!(read_packet(&mut client).await.unwrap().is_some());

    client
        .write_all(
            &MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x16], b"SELECT 1".to_vec()].concat(),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    let prepare = read_packet(&mut upstream).await.unwrap().unwrap();
    assert_eq!(prepare.payload[0], 0x16);
    let mut prepare_ok = vec![0x00];
    prepare_ok.extend_from_slice(&7_u32.to_le_bytes());
    prepare_ok.extend_from_slice(&0_u16.to_le_bytes());
    prepare_ok.extend_from_slice(&0_u16.to_le_bytes());
    prepare_ok.push(0);
    prepare_ok.extend_from_slice(&0_u16.to_le_bytes());
    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 1,
                payload: prepare_ok,
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload[0],
        0x00
    );

    client
        .write_all(
            &MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x19], 7_u32.to_le_bytes().to_vec()].concat(),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    let close = read_packet(&mut upstream).await.unwrap().unwrap();
    assert_eq!(
        close.payload,
        [vec![0x19], 7_u32.to_le_bytes().to_vec()].concat()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), read_packet(&mut client))
            .await
            .is_err()
    );

    client
        .write_all(
            &MysqlPacket {
                sequence_id: 0,
                payload: vec![0x0e],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut upstream).await.unwrap().unwrap().payload,
        vec![0x0e]
    );
    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 1,
                payload: vec![0x00],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload[0],
        0x00
    );

    state.recorder().flush_traffic().await.unwrap();
    let traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    let events = traffic
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(events.iter().any(|event| {
        event["event_type"] == "mysql_query" && event["command"] == "COM_STMT_CLOSE"
    }));
    assert!(!events.iter().any(|event| {
        event["event_type"] == "mysql_exchange" && event["command"] == "COM_STMT_CLOSE"
    }));
    assert!(
        !events
            .iter()
            .any(|event| event["command"] == "COM_UNKNOWN_0x19")
    );
    handler.abort();
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

fn server_handshake_payload(capability_flags: u32) -> Vec<u8> {
    let mut payload = vec![0x0a];
    payload.extend_from_slice(b"8.0.0-test\0");
    payload.extend_from_slice(&42_u32.to_le_bytes());
    payload.extend_from_slice(b"12345678");
    payload.push(0);
    payload.extend_from_slice(&(capability_flags as u16).to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.extend_from_slice(&((capability_flags >> 16) as u16).to_le_bytes());
    payload
}

fn server_lower_capability_flags(payload: &[u8]) -> u16 {
    let server_version_len = payload[1..].iter().position(|byte| *byte == 0).unwrap() + 1;
    let offset = 1 + server_version_len + 4 + 8 + 1;
    u16::from_le_bytes([payload[offset], payload[offset + 1]])
}

fn observe_payload(
    tracker: &mut MysqlResponseTracker,
    sequence_id: u8,
    payload: &[u8],
) -> Option<MysqlResponseEvent> {
    let packet = MysqlPacket {
        sequence_id,
        payload: payload.to_vec(),
    };
    let info = parse_server_packet(&packet);
    tracker.observe_packet(&packet, info)
}
