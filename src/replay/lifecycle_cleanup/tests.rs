use super::*;
use crate::replay::control::{ReplayControlRequest, handle_control_request};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn capture(data: &str) -> Value {
    json!({"encoding":"utf8","data":data,"truncated":false,"original_len":data.len(),"stored_len":data.len()})
}

fn redis(connection: Uuid, sequence: u64) -> Value {
    json!({"event_type":"redis_exchange","id":Uuid::new_v4(),"timestamp":"2026-01-01T00:00:00Z",
        "connection_id":connection,"sequence":sequence,"target_host":"redis.test","target_port":6379,"resp_version":2,
        "database":0,"command":"GET","args":[capture(&format!("key{sequence}"))],"response_kind":"other","response":capture(""),
        "duration_ms":15000,"replay_safe":false,"outcome":"response","parse_warnings":["engine cleanup interrupted Redis capture"]})
}

fn mysql(connection: Uuid) -> Value {
    json!({"event_type":"mysql_exchange","timestamp":"2026-01-01T00:00:00Z","connection_id":connection,"query_sequence":1,
        "target_host":"mysql.test","target_port":3306,"database":"appdb","username":"root","command":"COM_QUERY","sql":"SELECT 1",
        "params":null,"response":{"status":"incomplete","columns":[],"rows":[],"rows_truncated":false},"outcome":"response",
        "duration_ms":15000,"parse_warnings":["engine cleanup interrupted MySQL capture"]})
}

fn peer_cleanup(event: &mut Value) {
    event["outcome"] = json!({"terminated":{"side":"client","kind":"eof","scope":"write_half"}});
    event["parse_warnings"] = json!([]);
}

fn cancelled_connection() -> Value {
    json!({"event_type":"dependency_connect_failure","id":Uuid::new_v4(),
        "timestamp":"2026-01-01T00:00:00Z","protocol":"tcp","target_host":"redis.test","target_port":6379,
        "duration_ms":15000,"failure_kind":"engine_cancelled","client_outcome":"reset"})
}

fn reference(event: &Value) -> Value {
    match event["event_type"].as_str().unwrap() {
        "mysql_exchange" => {
            json!({"protocol":"mysql","connection_id":event["connection_id"],"sequence":event["query_sequence"]})
        }
        "redis_exchange" => {
            json!({"protocol":"redis","connection_id":event["connection_id"],"sequence":event["sequence"]})
        }
        "dependency_connect_failure" => json!({"protocol":"connect","event_id":event["id"]}),
        _ => unreachable!(),
    }
}

async fn fixture(events: &[Value], authorize: bool) -> Result<(tempfile::TempDir, ReplayRuntime)> {
    fixture_with_reason(events, authorize, "timeout").await
}

async fn fixture_with_reason(
    events: &[Value],
    authorize: bool,
    reason: &str,
) -> Result<(tempfile::TempDir, ReplayRuntime)> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("apis");
    for case in ["case-a", "case-b"] {
        tokio::fs::create_dir_all(root.join(case)).await?;
        tokio::fs::write(
            root.join(case).join("dependencies.jsonl"),
            if case == "case-a" {
                events
                    .iter()
                    .map(|event| format!("{event}\n"))
                    .collect::<String>()
            } else {
                String::new()
            },
        )
        .await?;
    }
    let references = events.iter().map(reference).collect::<Vec<_>>();
    let cleanup = if authorize {
        events
            .iter()
            .filter(|event| {
                event["outcome"].is_object()
                    || event["failure_kind"] == "engine_cancelled"
                    || event["parse_warnings"].as_array().is_some_and(|warnings| {
                        warnings.iter().any(|warning| {
                            warning
                                .as_str()
                                .is_some_and(|text| text.starts_with("engine cleanup interrupted"))
                        })
                    })
            })
            .map(reference)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    tokio::fs::write(root.join("case-a/async-api-observation.json"),json!({
        "version":1,"complete":true,"inventory_complete":true,"end_reason":reason,"request_timeout_ms":3000,
        "source_stop_required":true,"source_stop_after_ms":0,"completed_refs":references,
        "cleanup_refs":cleanup
    }).to_string()).await?;
    crate::replay::write_test_recording_network_manifest(&root);
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: root,
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse()?,
            tcp_listen: "127.0.0.1:0".parse()?,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(temp.path().join("ca.pem")),
            ca_key_path: Some(temp.path().join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
    )
    .await?;
    Ok((temp, runtime))
}

async fn command(state: &Arc<Mutex<ReplayState>>, command: &str) -> Value {
    handle_control_request(
        ReplayControlRequest {
            command: command.into(),
            case_id: Some("case-a".into()),
            fail_on_dirty: false,
            fail_on_incomplete: false,
            identity_pairs: Vec::new(),
            derived_input: None,
            native_event: None,
            input_timing: None,
            socketio_timing: None,
        },
        state.clone(),
        None,
        None,
    )
    .await
    .0
}

async fn pair() -> (TcpStream, TcpStream, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let (server, peer) = server.unwrap();
    (client.unwrap(), server, peer)
}

#[tokio::test]
async fn lifecycle_redis_pipeline_requires_every_real_request_and_target_termination() {
    for source_peer_end in [false, true] {
        let connection = Uuid::new_v4();
        let mut events = [redis(connection, 1), redis(connection, 2)];
        if source_peer_end {
            for event in &mut events {
                peer_cleanup(event);
            }
        }
        let (_temp, runtime) = fixture(&events, true).await.unwrap();
        let state = runtime.state.clone();
        assert_eq!(command(&state, "begin").await["ok"], true);
        let (mut client, server, _) = pair().await;
        let task = tokio::spawn(crate::replay::redis::handle_connection(
            server,
            ReplayTarget {
                host: "redis.test".into(),
                port: 6379,
                fake_ip: "198.18.0.1".parse().unwrap(),
                protocol: ReplayProtocol::Redis,
            },
            state.clone(),
        ));
        client
            .write_all(b"*2\r\n$3\r\nGET\r\n$4\r\nkey1\r\n*2\r\n$3\r\nGET\r\n$4\r\nkey2\r\n")
            .await
            .unwrap();
        let mut probe = [0; 1];
        let observed = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            client.read(&mut probe),
        )
        .await;
        assert!(
            observed.is_err(),
            "Source received no response before lifecycle stop (peer cleanup={source_peer_end}, Target observation={observed:?}, byte={probe:?})"
        );
        let ready = command(&state, "prepare_end").await;
        assert_eq!(ready["ok"], true, "{ready}");
        assert!(
            !task.is_finished(),
            "arming a lifecycle gate cannot manufacture consumption"
        );
        assert_eq!(command(&state, "end").await["ok"], false);
        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(command(&state, "end_stopped").await["ok"], true);
        assert_eq!(state.lock().await.redis.snapshot().unused_case.len(), 0);
    }
}

#[tokio::test]
async fn lifecycle_mysql_waits_without_fabricating_an_error_or_result() {
    for source_peer_end in [false, true] {
        let mut event = mysql(Uuid::new_v4());
        if source_peer_end {
            peer_cleanup(&mut event);
        }
        let (_temp, runtime) = fixture(&[event], true).await.unwrap();
        let state = runtime.state.clone();
        assert_eq!(command(&state, "begin").await["ok"], true);
        let (mut client, server, peer) = pair().await;
        let task = tokio::spawn(crate::replay::mysql::handle_connection(
            server,
            peer,
            Some(TargetKey {
                host: "mysql.test".into(),
                port: 3306,
            }),
            state.clone(),
            runtime.ca.clone(),
        ));
        let _ = crate::mysql::wire::read_packet(&mut client)
            .await
            .unwrap()
            .unwrap();
        let flags = 0x200_u32 | 0x8000 | 8 | 0x80000;
        let mut login = flags.to_le_bytes().to_vec();
        login.extend_from_slice(&[0; 4]);
        login.push(45);
        login.extend_from_slice(&[0; 23]);
        login.extend_from_slice(b"root\0\0appdb\0mysql_native_password\0");
        client
            .write_all(
                &crate::mysql::wire::MysqlPacket {
                    sequence_id: 1,
                    payload: login,
                }
                .to_wire_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(
            crate::mysql::wire::read_packet(&mut client)
                .await
                .unwrap()
                .unwrap()
                .payload[0],
            0
        );
        client
            .write_all(
                &crate::mysql::wire::MysqlPacket {
                    sequence_id: 0,
                    payload: b"\x03SELECT 1".to_vec(),
                }
                .to_wire_bytes(),
            )
            .await
            .unwrap();
        let mut probe = [0; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                client.read(&mut probe)
            )
            .await
            .is_err()
        );
        assert_eq!(command(&state, "prepare_end").await["ok"], true);
        assert!(!task.is_finished());
        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(command(&state, "end_stopped").await["ok"], true);
        assert_eq!(
            state.lock().await.mysql.exchanges[0].status,
            ReplayExchangeStatus::Consumed
        );
    }
}

#[tokio::test]
async fn lifecycle_cancelled_connect_holds_real_socket_until_target_stops() {
    let (_temp, runtime) = fixture(&[cancelled_connection()], true).await.unwrap();
    let state = runtime.state.clone();
    assert_eq!(command(&state, "begin").await["ok"], true);
    let (mut client, mut server, _) = pair().await;
    let delivering = state.clone();
    let task = tokio::spawn(async move {
        crate::replay::connect_failure::deliver(
            &mut server,
            &ReplayTarget {
                host: "redis.test".into(),
                port: 6379,
                fake_ip: "198.18.0.1".parse().unwrap(),
                protocol: ReplayProtocol::Redis,
            },
            &delivering,
        )
        .await
    });
    // Source never established the upstream connection, so these initial
    // caller bytes are transport evidence rather than a captured RESP command.
    client.write_all(b"*1\r\n$5\r\nHELLO\r\n").await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(30),
            client.read(&mut [0; 1]),
        )
        .await
        .is_err()
    );
    assert_eq!(command(&state, "prepare_end").await["ok"], true);
    assert!(
        !task.is_finished(),
        "Source cancellation cannot reset Target"
    );
    client.shutdown().await.unwrap();
    assert!(task.await.unwrap().unwrap());
    assert_eq!(command(&state, "end_stopped").await["ok"], true);
    assert!(!state.lock().await.connect_failures.snapshot().is_dirty());
}

#[tokio::test]
async fn dependency_failure_closes_pending_redis_only_after_real_error_delivery() {
    for deliver_failure in [false, true] {
        let cleanup = redis(Uuid::new_v4(), 1);
        let mut failure = redis(Uuid::new_v4(), 2);
        failure["outcome"] = json!("response");
        failure["response_kind"] = json!("error");
        failure["response"] = capture("-ERR recorded dependency failure\r\n");
        failure["duration_ms"] = json!(0);
        failure["replay_safe"] = json!(true);
        failure["parse_warnings"] = json!([]);
        let (_temp, runtime) = fixture_with_reason(&[cleanup, failure], true, "dependency_failure")
            .await
            .unwrap();
        let state = runtime.state.clone();
        assert_eq!(command(&state, "begin").await["ok"], true);
        let target = ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        };
        let (mut pending, server, _) = pair().await;
        let waiting = tokio::spawn(crate::replay::redis::handle_connection(
            server,
            target.clone(),
            state.clone(),
        ));
        pending
            .write_all(b"*2\r\n$3\r\nGET\r\n$4\r\nkey1\r\n")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while state.lock().await.redis.exchange_status(0)
                != Some(ReplayExchangeStatus::AwaitingClientTermination)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut ordinary = None;
        if deliver_failure {
            let (mut client, server, _) = pair().await;
            let task = tokio::spawn(crate::replay::redis::handle_connection(
                server,
                target,
                state.clone(),
            ));
            client
                .write_all(b"*2\r\n$3\r\nGET\r\n$4\r\nkey2\r\n")
                .await
                .unwrap();
            let mut response = [0; 34];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"-ERR recorded dependency failure\r\n");
            ordinary = Some((client, task));
        }
        pending.shutdown().await.unwrap();
        let ended = waiting.await.unwrap();
        assert_eq!(ended.is_ok(), deliver_failure, "{ended:?}");
        if let Some((mut client, task)) = ordinary {
            client.shutdown().await.unwrap();
            task.await.unwrap().unwrap();
            assert_eq!(command(&state, "prepare_end").await["ok"], true);
            assert_eq!(command(&state, "end_stopped").await["ok"], true);
            assert_eq!(state.lock().await.redis.snapshot().unused_case.len(), 0);
        }
    }
}

#[tokio::test]
async fn cleanup_context_never_launders_missing_scope_truncated_requests_or_parser_corruption() {
    async fn rejected(events: &[Value], authorize: bool) -> bool {
        match fixture(events, authorize).await {
            Err(_) => true,
            Ok((_temp, runtime)) => command(&runtime.state, "begin").await["ok"] == false,
        }
    }
    for mut event in [redis(Uuid::new_v4(), 1), mysql(Uuid::new_v4())] {
        assert!(rejected(&[event.clone()], false).await);
        event["parse_warnings"]
            .as_array_mut()
            .unwrap()
            .push(json!("independent parser corruption"));
        assert!(rejected(&[event], true).await);
    }
    let mut event = redis(Uuid::new_v4(), 1);
    event["args"][0]["truncated"] = true.into();
    assert!(rejected(&[event], true).await);
    let mut event = mysql(Uuid::new_v4());
    event["params"] =
        json!([{"kind":"bytes","raw":{"encoding":"base64","data":"AA==","truncated":true}}]);
    assert!(rejected(&[event], true).await);
    assert!(rejected(&[cancelled_connection()], false).await);
}

#[tokio::test]
async fn cleanup_gate_cannot_accept_early_target_cancellation() {
    let (_temp, runtime) = fixture(&[redis(Uuid::new_v4(), 1)], true).await.unwrap();
    assert_eq!(command(&runtime.state, "begin").await["ok"], true);
    let (mut client, mut server, _) = pair().await;
    let gate = AtomicBool::new(false);
    client.shutdown().await.unwrap();
    assert!(
        await_target_end(&mut server, &gate, &runtime.state, "case-a")
            .await
            .is_err()
    );
}
