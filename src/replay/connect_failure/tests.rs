use super::*;
use crate::replay::control::{begin_case, end_case};
use serde_json::json;
use tokio::io::AsyncWriteExt;

fn command(command: &str) -> super::super::control::ReplayControlRequest {
    super::super::control::ReplayControlRequest {
        command: command.into(),
        case_id: Some("case-a".into()),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        identity_pairs: Vec::new(),
        derived_input: None,
        native_event: None,
    }
}

fn event(id: Uuid, duration_ms: u64) -> Value {
    json!({"event_type":"dependency_connect_failure", "id":id,
        "timestamp":"2026-01-01T00:00:00Z", "protocol":"redis",
        "target_host":"redis.test", "target_port":6379,
        "duration_ms":duration_ms, "failure_kind":"connection_refused",
        "client_outcome":"reset"})
}

struct Fixture {
    _temp: tempfile::TempDir,
    runtime: ReplayRuntime,
}

async fn fixture(duration_ms: u64) -> Fixture {
    fixture_with_predecessor(duration_ms, None).await
}

async fn fixture_with_predecessor(duration_ms: u64, predecessor: Option<Value>) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("apis");
    let id = Uuid::new_v4();
    let mut failed = event(id, duration_ms);
    if predecessor.is_some() {
        failed["timestamp"] = "2026-01-01T00:00:01Z".into();
    }
    for case in ["case-a", "case-b"] {
        tokio::fs::create_dir_all(root.join(case)).await.unwrap();
        tokio::fs::write(
            root.join(case).join("dependencies.jsonl"),
            if case == "case-a" {
                predecessor.as_ref().map_or_else(
                    || format!("{failed}\n"),
                    |normal| format!("{normal}\n{failed}\n"),
                )
            } else {
                String::new()
            },
        )
        .await
        .unwrap();
    }
    let mut references = vec![json!({"protocol":"connect","event_id":id})];
    if let Some(normal) = predecessor {
        references.push(json!({"protocol":"redis","connection_id":normal["connection_id"],"sequence":normal["sequence"]}));
    }
    tokio::fs::write(
        root.join("case-a/async-api-observation.json"),
        json!({"version":1,"complete":true,"inventory_complete":true,
            "end_reason":"dependency_failure","request_timeout_ms":1000,
            "completed_refs":references})
        .to_string(),
    )
    .await
    .unwrap();
    crate::replay::write_test_recording_network_manifest(&root);
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: root,
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
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
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    Fixture {
        _temp: temp,
        runtime,
    }
}

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (client.unwrap(), server.unwrap().0)
}

async fn prepare_stop(state: Arc<Mutex<ReplayState>>) -> Value {
    crate::replay::control::handle_control_request(command("prepare_end"), state, None, None)
        .await
        .0
}

fn target() -> ReplayTarget {
    ReplayTarget {
        host: "redis.test".into(),
        port: 6379,
        fake_ip: "198.18.0.1".parse().unwrap(),
        protocol: ReplayProtocol::Redis,
    }
}

fn normal_event() -> Value {
    let capture = |data: &str| json!({"encoding":"utf8","data":data,"truncated":false,"original_len":data.len(),"stored_len":data.len()});
    json!({"event_type":"redis_exchange","id":Uuid::new_v4(),"timestamp":"2026-01-01T00:00:00Z",
        "connection_id":Uuid::new_v4(),"sequence":1,"target_host":"redis.test","target_port":6379,
        "resp_version":2,"database":0,"command":"GET","args":[capture("key")],"response_kind":"simple_string",
        "response":capture("+OK\r\n"),"duration_ms":1,"replay_safe":true,"outcome":"response"})
}

#[tokio::test]
async fn a_recorded_failed_connect_waits_for_the_real_normal_predecessor() {
    let fixture = fixture_with_predecessor(10, Some(normal_event())).await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let (mut client, mut server) = pair().await;
    assert!(
        !deliver(&mut server, &target(), &state).await.unwrap(),
        "the normal connection must retain protocol ownership"
    );
    let normal_state = state.clone();
    let normal = tokio::spawn(super::super::redis::handle_connection(
        server,
        target(),
        normal_state,
    ));
    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
        .await
        .unwrap();
    let mut response = [0; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"+OK\r\n");
    client.shutdown().await.unwrap();
    normal.await.unwrap().unwrap();
    let (mut client, mut server) = pair().await;
    let failure_state = state.clone();
    let failure =
        tokio::spawn(async move { deliver(&mut server, &target(), &failure_state).await });
    assert_eq!(
        client.read(&mut [0; 1]).await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionReset
    );
    assert!(failure.await.unwrap().unwrap());
    assert_eq!(
        state.lock().await.connect_failures.snapshot().matched_count,
        1
    );
    assert_eq!(end_case(&command("end"), state.clone()).await["ok"], false);
    let prepared = prepare_stop(state.clone()).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert_eq!(prepared["target_stop_required"], true);
    assert_eq!(
        end_case(&command("end_stopped"), state.clone()).await["ok"],
        true
    );
}

#[tokio::test]
async fn overlapping_normal_and_failed_source_connections_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("dependencies.jsonl");
    let mut normal = normal_event();
    normal["timestamp"] = "2026-01-01T00:00:00.995Z".into();
    let mut failure = event(Uuid::new_v4(), 10);
    failure["timestamp"] = "2026-01-01T00:00:01Z".into();
    tokio::fs::write(&path, format!("{normal}\n{failure}\n"))
        .await
        .unwrap();
    let error = Inventory::default()
        .load("case", &path, &mut BTreeMap::new())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ambiguous normal and failed connections")
    );
}

#[tokio::test]
async fn http_predecessors_use_their_physical_authority_and_cannot_be_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("dependencies.jsonl");
    let http_id = Uuid::new_v4();
    let mut normal = json!({"event_type":"http_exchange", "id":http_id,
        "timestamp":"2026-01-01T00:00:00Z", "scheme":"fake_ip_https",
        "authority":"redis.test:6379", "uri":"/business"});
    let mut failure = event(Uuid::new_v4(), 10);
    failure["timestamp"] = "2026-01-01T00:00:01Z".into();
    for overlapping in [false, true] {
        if overlapping {
            normal["timestamp"] = "2026-01-01T00:00:00.995Z".into();
        }
        tokio::fs::write(&path, format!("{normal}\n{failure}\n"))
            .await
            .unwrap();
        let mut inventory = Inventory::default();
        let result = inventory.load("case", &path, &mut BTreeMap::new()).await;
        if overlapping {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("ambiguous normal and failed connections")
            );
        } else {
            result.unwrap();
            assert_eq!(
                inventory.entries[0].predecessors,
                [
                    crate::replay::control::dependency_tail::RecordedReference::Http {
                        exchange_id: http_id
                    }
                ]
            );
        }
    }
}

#[tokio::test]
async fn real_target_connection_consumes_the_recorded_reset_once_and_releases_async_tail() {
    let fixture = fixture(200).await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let ending_state = state.clone();
    let ending = tokio::spawn(async move { prepare_stop(ending_state).await });
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(
        !ending.is_finished(),
        "Target stop must wait for the real failed connection"
    );
    let (mut client, mut server) = pair().await;
    let delivering = state.clone();
    let started = tokio::time::Instant::now();
    let delivery = tokio::spawn(async move { deliver(&mut server, &target(), &delivering).await });
    client.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state.lock().await.connect_failures.has_in_flight() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(crate::replay::control::case_cleanup::has_started(
        &*state.lock().await
    ));
    let (reply, stop) = crate::replay::control::handle_control_request(
        command("finalize"),
        state.clone(),
        None,
        None,
    )
    .await;
    assert!(!stop);
    assert!(reply["error"].as_str().unwrap().contains("in flight"));
    let error = client.read(&mut [0; 1]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(started.elapsed() >= std::time::Duration::from_millis(180));
    assert!(delivery.await.unwrap().unwrap());
    assert!(!state.lock().await.connect_failures.has_in_flight());
    let prepared = ending.await.unwrap();
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert_eq!(prepared["target_stop_required"], true);
    assert_eq!(end_case(&command("end"), state.clone()).await["ok"], false);
    assert_eq!(
        end_case(&command("end_stopped"), state.clone()).await["ok"],
        true
    );
    let report = state.lock().await.connect_failures.snapshot();
    assert_eq!(report.matched_count, 1);
    assert!(!report.is_dirty());
    let (_client, mut server) = pair().await;
    assert!(!deliver(&mut server, &target(), &state).await.unwrap());
}

#[tokio::test]
async fn wrong_case_and_endpoint_do_not_borrow_a_failure_and_early_target_close_is_dirty() {
    let fixture = fixture(100).await;
    let state = fixture.runtime.state.clone();
    let mut begin = command("begin");
    begin.case_id = Some("case-b".into());
    assert_eq!(begin_case(&begin, state.clone()).await["ok"], true);
    let (_client, mut server) = pair().await;
    assert!(!deliver(&mut server, &target(), &state).await.unwrap());
    let mut end = command("end");
    end.case_id = Some("case-b".into());
    assert_eq!(end_case(&end, state.clone()).await["ok"], true);
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let mut wrong = target();
    wrong.port = 6380;
    assert!(!deliver(&mut server, &wrong, &state).await.unwrap());
    let (mut client, mut server) = pair().await;
    client.shutdown().await.unwrap();
    assert!(deliver(&mut server, &target(), &state).await.is_err());
    assert_eq!(end_case(&command("end"), state.clone()).await["ok"], false);
    assert!(state.lock().await.connect_failures.snapshot().is_dirty());
}

#[tokio::test]
async fn failure_inventory_rejects_duplicate_ids_and_unbounded_transport_values() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("dependencies.jsonl");
    let original = event(Uuid::new_v4(), 1);
    for change in ["duplicate", "duration", "protocol", "outcome"] {
        let mut changed = original.clone();
        match change {
            "duration" => changed["duration_ms"] = (MAX_DURATION_MS + 1).into(),
            "protocol" => changed["protocol"] = "unknown".into(),
            "outcome" => changed["client_outcome"] = "ignore".into(),
            _ => {}
        }
        tokio::fs::write(
            &path,
            if change == "duplicate" {
                format!("{original}\n{changed}\n")
            } else {
                format!("{changed}\n")
            },
        )
        .await
        .unwrap();
        assert!(
            Inventory::default()
                .load("case", &path, &mut BTreeMap::new())
                .await
                .is_err(),
            "accepted {change}"
        );
    }
}

#[tokio::test]
async fn common_case_deadline_stops_a_long_recorded_connection_failure() {
    let fixture = fixture(60_000).await;
    let path = fixture
        ._temp
        .path()
        .join("apis/case-a/async-api-observation.json");
    let mut metadata: Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    metadata["request_timeout_ms"] = 80.into();
    tokio::fs::write(path, metadata.to_string()).await.unwrap();
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let (mut client, mut server) = pair().await;
    let delivering = state.clone();
    let started = tokio::time::Instant::now();
    let delivery = tokio::spawn(async move { deliver(&mut server, &target(), &delivering).await });
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert!(
        delivery
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("common Case deadline")
    );
    assert!(state.lock().await.connect_failures.snapshot().is_dirty());
}
