use super::*;
use crate::replay::control::{ReplayControlRequest, begin_case, end_case};
use crate::replay::{
    MysqlReplayConfig, ReplayCaseStatus, ReplayProtocol, ReplayRuntime, ReplayTarget,
};
use serde_json::{Value, json};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub(super) const GET: &[u8] = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
const PING: &[u8] = b"*1\r\n$4\r\nPING\r\n";

pub(super) struct Fixture {
    _temp: tempfile::TempDir,
    pub(super) runtime: ReplayRuntime,
    pub(super) root: std::path::PathBuf,
}

pub(super) fn command(command: &str) -> ReplayControlRequest {
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
    }
}

fn dependency(connection: Uuid, duration_ms: u64) -> Value {
    let capture = |data: &str| {
        json!({"encoding":"utf8", "data":data, "truncated":false,
        "original_len":data.len(),"stored_len":data.len()})
    };
    json!({
        "event_type":"redis_exchange", "id":Uuid::new_v4(), "connection_id":connection,
        "sequence":1, "target_host":"redis.test", "target_port":6379,
        "resp_version":2, "database":0, "command":"GET", "args":[capture("key")],
        "response_kind":"simple_string", "response":capture("+OK\r\n"),
        "duration_ms":duration_ms, "replay_safe":true, "outcome":"response", "parse_warnings":[]
    })
}

async fn metadata(root: &Path, connection: Uuid, timeout_ms: u64) {
    tokio::fs::write(
        root.join("case-a/api-origin-observation.json"),
        json!({
            "version":1, "idle_ms":60000, "request_timeout_ms":timeout_ms,
            "elapsed_ms":100, "outcome":"quiet", "rules":[],
            "selected_completed_refs":[{"protocol":"redis", "connection_id":connection, "sequence":1}]
        }).to_string(),
    ).await.unwrap();
}

pub(super) async fn fixture(timeout_ms: Option<u64>, duration_ms: u64) -> Fixture {
    fixture_with_response(timeout_ms, duration_ms, None).await
}

pub(super) async fn fixture_with_response(
    timeout_ms: Option<u64>,
    duration_ms: u64,
    response: Option<(&str, &str)>,
) -> Fixture {
    fixture_with_records(timeout_ms, duration_ms, response, true).await
}

pub(super) async fn fixture_empty() -> Fixture {
    fixture_with_records(None, 0, None, false).await
}

async fn fixture_with_records(
    timeout_ms: Option<u64>,
    duration_ms: u64,
    response: Option<(&str, &str)>,
    include_dependency: bool,
) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("apis");
    let connection = Uuid::new_v4();
    for case in ["case-a", "case-b"] {
        tokio::fs::create_dir_all(root.join(case)).await.unwrap();
        tokio::fs::write(
            root.join(case).join("dependencies.jsonl"),
            if case == "case-a" && include_dependency {
                let mut event = dependency(connection, duration_ms);
                if let Some((kind, raw)) = response {
                    event["response_kind"] = kind.into();
                    event["response"]["data"] = raw.into();
                    event["response"]["original_len"] = raw.len().into();
                    event["response"]["stored_len"] = raw.len().into();
                }
                format!("{event}\n")
            } else {
                String::new()
            },
        )
        .await
        .unwrap();
    }
    if let Some(timeout) = timeout_ms {
        metadata(&root, connection, timeout).await;
    }
    crate::replay::write_test_recording_network_manifest(&root);
    let runtime = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: root.clone(),
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
        root,
    }
}

pub(super) async fn client(
    state: Arc<Mutex<ReplayState>>,
) -> (TcpStream, tokio::task::JoinHandle<Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let (client, server) = tokio::join!(connect, listener.accept());
    let task = tokio::spawn(crate::protocols::replay::redis::handle_connection(
        server.unwrap().0,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        state,
    ));
    (client.unwrap(), task)
}

#[tokio::test]
async fn delayed_real_target_call_is_consumed_before_end_without_repeating_source_idle() {
    let fixture = fixture(Some(1000), 30).await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let (mut client, task) = client(state.clone()).await;
    let end_state = state.clone();
    let started = Instant::now();
    let ending = tokio::spawn(async move { end_case(&command("end"), end_state).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!ending.is_finished());
    assert_eq!(state.lock().await.active_case_id.as_deref(), Some("case-a"));
    client.write_all(GET).await.unwrap();
    let mut response = [0; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"+OK\r\n");
    let ended = tokio::time::timeout(Duration::from_millis(500), ending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended["ok"], true, "{ended}");
    assert!(started.elapsed() < Duration::from_millis(800));
    assert_eq!(state.lock().await.active_case_id, None);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn missing_call_uses_the_begin_deadline_and_repeated_begin_cannot_extend_it() {
    let fixture = fixture(Some(100), 1).await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let original = state.lock().await.dependency_tails.cases["case-a"]
        .as_ref()
        .unwrap()
        .deadline
        .unwrap();
    tokio::time::advance(Duration::from_millis(80)).await;
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    assert_eq!(
        state.lock().await.dependency_tails.cases["case-a"]
            .as_ref()
            .unwrap()
            .deadline
            .unwrap(),
        original
    );
    let ended = end_case(&command("end"), state.clone()).await;
    assert_eq!(ended["ok"], false);
    assert_eq!(ended["dirty"], true);
    assert!(
        ended["error"]
            .as_str()
            .unwrap()
            .contains("absolute request budget")
    );
    assert!(state.lock().await.active_case_id.is_none());
    assert!(
        state
            .lock()
            .await
            .dependency_tails
            .failure("case-a")
            .is_some()
    );
}

#[tokio::test(start_paused = true)]
async fn preparing_a_case_that_is_not_yet_admitted_does_not_start_its_budget() {
    let fixture = fixture(Some(100), 1).await;
    let state = fixture.runtime.state.clone();
    prepare(&state, "case-a").await.unwrap();
    assert!(
        state.lock().await.dependency_tails.cases["case-a"]
            .as_ref()
            .unwrap()
            .deadline
            .is_none()
    );
    tokio::time::advance(Duration::from_millis(200)).await;
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let deadline = state.lock().await.dependency_tails.cases["case-a"]
        .as_ref()
        .unwrap()
        .deadline
        .unwrap();
    assert_eq!(deadline - Instant::now(), Duration::from_millis(100));
}

#[tokio::test(start_paused = true)]
async fn fast_case_tail_respects_the_earlier_of_two_minutes_and_the_source_budget() {
    use crate::replay::ReplayStreamTiming;

    for (mode, source_ms, expected_seconds) in [
        (ReplayStreamTiming::Fast, 900_000, 120),
        (ReplayStreamTiming::Fast, 90_000, 90),
        (ReplayStreamTiming::Recorded, 900_000, 900),
    ] {
        let fixture = fixture(Some(source_ms), 1).await;
        let state = fixture.runtime.state.clone();
        state.lock().await.stream_timing = Some(mode);
        assert_eq!(
            begin_case(&command("begin"), state.clone()).await["ok"],
            true
        );
        let deadline = deadline(&state, "case-a").await.unwrap();
        assert_eq!(
            deadline - Instant::now(),
            Duration::from_secs(expected_seconds)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn the_absolute_budget_also_bounds_the_preceding_fixed_cleanup_window() {
    let fixture = fixture(Some(100), 1).await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    state.lock().await.case_dependency_post_response_window = Duration::from_secs(60);
    let started = Instant::now();
    let ended = end_case(&command("end"), state.clone()).await;
    assert_eq!(ended["ok"], false);
    assert_eq!(ended["dirty"], true);
    assert_eq!(started.elapsed(), Duration::from_millis(100));
    assert!(state.lock().await.active_case_id.is_none());
    assert!(
        state
            .lock()
            .await
            .dependency_tails
            .failure("case-a")
            .is_some()
    );
}

#[tokio::test]
async fn unrelated_redis_heartbeats_do_not_extend_the_absolute_tail_budget() {
    let fixture = fixture(Some(150), 1).await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let (mut client, task) = client(state.clone()).await;
    let noise = tokio::spawn(async move {
        loop {
            client.write_all(PING).await.unwrap();
            let mut pong = [0; 7];
            client.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"+PONG\r\n");
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    });
    let started = Instant::now();
    let ended = tokio::time::timeout(
        Duration::from_millis(500),
        end_case(&command("end"), state.clone()),
    )
    .await
    .unwrap();
    assert_eq!(ended["ok"], false);
    assert!(started.elapsed() < Duration::from_millis(400));
    assert!(state.lock().await.active_case_id.is_none());
    assert!(
        state
            .lock()
            .await
            .dependency_tails
            .failure("case-a")
            .is_some()
    );
    noise.abort();
    let _ = noise.await;
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn ordinary_cases_without_tail_metadata_finish_without_a_fixed_sleep() {
    let fixture = fixture(None, 1).await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let started = Instant::now();
    let ended = end_case(&command("end"), state.clone()).await;
    assert_eq!(ended["ok"], true);
    assert_eq!(ended["dirty"], true);
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(state.lock().await.active_case_id, None);
}

#[tokio::test(start_paused = true)]
async fn reopening_an_ended_eager_case_uses_a_fresh_budget_without_waiving_unused_calls() {
    let fixture = fixture(Some(100), 1).await;
    let path = fixture.root.join("case-a/api-origin-observation.json");
    let mut value: Value = serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    value["selected_completed_refs"] = json!([]);
    tokio::fs::write(path, value.to_string()).await.unwrap();
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let first_deadline = state.lock().await.dependency_tails.cases["case-a"]
        .as_ref()
        .unwrap()
        .deadline
        .unwrap();
    let ended = end_case(&command("end"), state.clone()).await;
    assert_eq!(ended["ok"], true);
    assert_eq!(
        ended["dirty"], true,
        "a metadata inventory never exempts unused calls"
    );
    assert!(
        !state
            .lock()
            .await
            .dependency_tails
            .cases
            .contains_key("case-a")
    );
    tokio::time::advance(Duration::from_millis(200)).await;
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let second_deadline = state.lock().await.dependency_tails.cases["case-a"]
        .as_ref()
        .unwrap()
        .deadline
        .unwrap();
    assert!(second_deadline > first_deadline);
    assert_eq!(end_case(&command("end"), state.clone()).await["ok"], true);
}

#[tokio::test]
async fn absent_duplicate_and_foreign_case_references_reject_begin_explicitly() {
    for problem in ["absent", "duplicate", "foreign", "incomplete"] {
        let fixture = fixture(Some(1000), 1).await;
        let path = fixture.root.join("case-a/api-origin-observation.json");
        let mut value: Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        match problem {
            "absent" => value["selected_completed_refs"][0]["sequence"] = 2.into(),
            "duplicate" => {
                let reference = value["selected_completed_refs"][0].clone();
                value["selected_completed_refs"]
                    .as_array_mut()
                    .unwrap()
                    .push(reference);
            }
            "incomplete" => value["inventory_complete"] = false.into(),
            "foreign" => {
                let destination = fixture.root.join("case-b/api-origin-observation.json");
                tokio::fs::write(destination, value.to_string())
                    .await
                    .unwrap();
                let mut request = command("begin");
                request.case_id = Some("case-b".into());
                let result = begin_case(&request, fixture.runtime.state.clone()).await;
                assert_eq!(result["ok"], false);
                continue;
            }
            _ => unreachable!(),
        }
        tokio::fs::write(path, value.to_string()).await.unwrap();
        let result = begin_case(&command("begin"), fixture.runtime.state.clone()).await;
        assert_eq!(result["ok"], false);
    }
}

#[tokio::test(start_paused = true)]
async fn explicit_dependency_failure_finishes_dirty_after_actual_cleanup() {
    let fixture = fixture(Some(60_000), 1).await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    state
        .lock()
        .await
        .protocols
        .mysql
        .events
        .dirty_case_ids
        .insert("case-a".into());
    let started = Instant::now();
    let mut end = command("end");
    end.fail_on_dirty = true;
    let ended = end_case(&end, state.clone()).await;
    assert_eq!(ended["ok"], false);
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(state.lock().await.active_case_id, None);
    assert_eq!(
        state.lock().await.cases["case-a"].status,
        ReplayCaseStatus::Ended
    );
}

#[tokio::test]
async fn primary_failure_with_no_dependencies_needs_no_success_tail() {
    let fixture = fixture_empty().await;
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let mut invalid = command("case_failed");
    invalid.case_id = Some("case-b".into());
    let (reply, _) =
        crate::replay::control::handle_control_request(invalid, state.clone(), None, None).await;
    assert_eq!(reply["ok"], false);
    let (reply, _) = crate::replay::control::handle_control_request(
        command("case_failed"),
        state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(reply["ok"], true);
    assert_eq!(end_case(&command("end"), state.clone()).await["ok"], true);
    assert!(state.lock().await.active_case_id.is_none());
}
