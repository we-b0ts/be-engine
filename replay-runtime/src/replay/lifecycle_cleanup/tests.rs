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

#[allow(dead_code)]
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
        "version":2,"capture_complete":true,"business_complete":reason=="resource","business_completion":if reason=="resource" {"observed"}else{"unobserved"},"inventory_complete":true,"end_reason":reason,"request_timeout_ms":3000,
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
            parameters: Default::default(),
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
async fn incomplete_mysql_cleanup_is_rejected_without_a_native_lifecycle_capability() {
    assert!(fixture(&[mysql(Uuid::new_v4())], true).await.is_err());
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
