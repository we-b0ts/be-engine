//! Real Target streams and delayed dependencies share one reusable Replay session.

use super::*;
use crate::interaction::{
    model::{EndReason, InputTranscript, Protocol},
    policy::{InteractionPolicy, StreamTerminal},
};
use crate::recorded_request::RecordedHttpClient;
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};

mod failure;
mod tail;

async fn runtime(root: &Path, cleanup_ms: u64) -> Arc<ReplayRuntime> {
    runtime_with_background(root, cleanup_ms, false).await
}

async fn runtime_with_background(
    root: &Path,
    cleanup_ms: u64,
    background: bool,
) -> Arc<ReplayRuntime> {
    for case_id in ["case-a", "case-b"] {
        let case = root.join(case_id);
        crate::replay::http::tests::write_http_case(
            &case,
            "fake_ip_http",
            "dependency.test",
            &format!("/tail/{case_id}"),
            "",
            "ok",
        )
        .await;
        let dependency = case.join("dependencies.jsonl");
        let mut record: Value =
            serde_json::from_slice(&tokio::fs::read(&dependency).await.unwrap()).unwrap();
        record["response_stream"] = serde_json::json!({
            "version":1, "headers_ms":0,
            "chunks":[{"at_ms":0,"start":0,"end":2}],
            "end_ms":200, "complete":true
        });
        if background {
            if case_id == "case-a" {
                record["uri"] = "/background".into();
                record["response_headers"]["content-type"] =
                    serde_json::json!(["application/octet-stream"]);
                record["response_stream"]["end_ms"] = 2000.into();
                record["global_dependency_reason"] = "background_rule".into();
                record["global_dependency_phase"] = "runtime".into();
                record["global_dependency_matched_by"] = "background-http".into();
                tokio::fs::write(
                    root.join("global-dependencies.jsonl"),
                    format!("{record}\n"),
                )
                .await
                .unwrap();
            }
            tokio::fs::write(&dependency, "").await.unwrap();
        } else {
            tokio::fs::write(&dependency, format!("{record}\n"))
                .await
                .unwrap();
        }
        let transcript = InputTranscript::new(
            Protocol::Sse,
            InteractionPolicy {
                business_idle_ms: 20,
                input_gap_ms: 1,
                cleanup_timeout_ms: cleanup_ms,
                stream_terminal: Some(StreamTerminal::Text {
                    value: "[DONE]".into(),
                }),
                ..Default::default()
            },
        );
        tokio::fs::write(
            case.join("request.json"),
            serde_json::json!({
                "method":"GET", "uri":"/events", "headers":{},
                "body":{"encoding":"utf8","data":"","truncated":false},
                "interaction":transcript
            })
            .to_string(),
        )
        .await
        .unwrap();
    }
    write_test_recording_network_manifest(root);
    let load_root = if background {
        let mut config = crate::AppConfig::default();
        config
            .process_dependency_tasks
            .insert("fixture_process".into(), "background_http_task".into());
        std::fs::create_dir_all(root.join(crate::repository::LOCAL_ROOT)).unwrap();
        crate::platform::encryption_key::load_or_create(root).unwrap();
        let recorder = crate::recorder::Recorder::new(
            root.join(crate::repository::LOCAL_ROOT)
                .join("central-background"),
        )
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
        let event: Value =
            serde_json::from_slice(&std::fs::read(root.join("global-dependencies.jsonl")).unwrap())
                .unwrap();
        crate::replay::test_support::recording::append(&recorder, &event, true).await;
        for index in 0..2 {
            let context = crate::recorder::CaseContext {
                id: Uuid::from_u128(index as u128 + 1),
                rule_name: "fixture".into(),
                uri_group: None,
            };
            let request = serde_json::json!({"method":"GET","uri":"/events"});
            recorder
                .write_case_json(
                    &context,
                    "admission.json",
                    &serde_json::json!({"fixture":true}),
                )
                .await
                .unwrap();
            recorder
                .write_case_json(&context, "request.json", &request)
                .await
                .unwrap();
            recorder
                .write_case_json(&context, "expected-response.json", &serde_json::json!({}))
                .await
                .unwrap();
            recorder.publish_case(&context).await.unwrap();
        }
        recorder.finish_run().await.unwrap();
        recorder.run_dir.as_ref().clone()
    } else {
        root.to_owned()
    };
    Arc::new(
        ReplayRuntime::load_with_lifecycle(
            MysqlReplayConfig {
                case_dir: load_root,
                selected_case_ids: Vec::new(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: "127.0.0.1:0".parse().unwrap(),
                fake_cidr: "198.18.0.0/15".into(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(root.join("ca.pem")),
                ca_key_path: Some(root.join("ca-key.pem")),
                policy_path: None,
                http_ignore_query_params: Vec::new(),
                process_owned_dependencies: if background {
                    vec![crate::BackgroundDependencyRuleConfig::Http {
                        name: "background-http".into(),
                        authorities: vec!["dependency.test".into()],
                        methods: vec!["POST".into()],
                        path_prefixes: vec!["/background".into()],
                        source_revision: String::new(),
                        source_evidence:
                            "the process runs this HTTP stream independently of primary requests"
                                .into(),
                    }]
                } else {
                    Vec::new()
                },
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            ReplayLifecycleConfig {
                case_dependency_post_response_window: Duration::from_millis(if background {
                    10
                } else {
                    100
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    )
}

fn command(command: &str, case_id: &str) -> ReplayControlRequest {
    ReplayControlRequest {
        command: command.into(),
        case_id: Some(case_id.into()),
        fail_on_dirty: true,
        fail_on_incomplete: false,
        identity_pairs: Vec::new(),
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    }
}

#[tokio::test]
async fn consecutive_stream_cases_keep_delayed_dependencies_and_wait_only_for_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 1_000).await;
    let session_id = runtime.state.lock().await.session_id;
    let dependency_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dependency_address = dependency_listener.local_addr().unwrap();
    let replay = runtime.clone();
    let replay_task = tokio::spawn(async move { replay.run_tcp(dependency_listener).await });
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target = tokio::spawn(async move {
        for case_id in ["case-a", "case-b"] {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            read_head(&mut stream).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nE\r\ndata: [DONE]\n\n\r\n").await.unwrap();
            let mut buffer = [0; 1];
            assert_eq!(stream.read(&mut buffer).await.unwrap(), 0);
            // This call begins after the primary stream was cancelled, inside
            // the normal attribution window; its timed EOF arrives after it.
            tokio::time::sleep(Duration::from_millis(15)).await;
            let mut dependency = TcpStream::connect(dependency_address).await.unwrap();
            dependency.write_all(format!("POST /tail/{case_id} HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(1),
                dependency.read_to_end(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 200"));
            assert!(response.ends_with("0\r\n\r\n"));
        }
    });
    let client = RecordedHttpClient::new(
        format!("http://{target_address}"),
        Duration::from_secs(1),
        1_000_000,
    );
    for case_id in ["case-a", "case-b"] {
        assert_eq!(
            begin_case(&command("begin", case_id), runtime.state.clone()).await["ok"],
            true
        );
        let actual = client
            .send(&temp.path().join(case_id).join("request.json"))
            .await
            .unwrap();
        let output = actual.interaction.unwrap();
        assert!(output.end.clean);
        assert_eq!(output.end.reason, EndReason::BusinessIdle);
        let started = tokio::time::Instant::now();
        let ended = tokio::time::timeout(
            Duration::from_secs(1),
            end_case(&command("end", case_id), runtime.state.clone()),
        )
        .await
        .expect("case end must not add a business/dependency quiet period");
        assert_eq!(ended["ok"], true, "{ended}");
        assert!(started.elapsed() >= Duration::from_millis(200));
        let state = runtime.state.lock().await;
        assert_eq!(state.session_id, session_id);
        assert!(state.active_case_id.is_none());
        assert_eq!(state.cases[case_id].status, ReplayCaseStatus::Ended);
    }
    target.await.unwrap();
    let report = runtime.state.lock().await.snapshot_report();
    assert_eq!(report.matched_http_exchanges.len(), 2);
    assert_eq!(
        report.matched_http_exchanges[0].case_id.as_deref(),
        Some("case-a")
    );
    assert_eq!(
        report.matched_http_exchanges[1].case_id.as_deref(),
        Some("case-b")
    );
    assert!(report.unused_case_http_exchanges.is_empty());
    assert!(report.unmatched_http_requests.is_empty());
    replay_task.abort();
}

#[tokio::test]
async fn an_unfinished_delivery_times_out_without_releasing_its_case() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 150).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let replay = runtime.clone();
    let task = tokio::spawn(async move { replay.run_tcp(listener).await });
    let mut dependency = TcpStream::connect(address).await.unwrap();
    dependency.write_all(b"POST /tail/case-a HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    read_head(&mut dependency).await;
    assert!(runtime.state.lock().await.http_has_in_flight());
    let started = tokio::time::Instant::now();
    let ended = end_case(&command("end", "case-a"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], false);
    let error = ended["error"].as_str().unwrap();
    assert!(
        error.contains("cleanup")
            && error.contains("timed out")
            && error.contains("ownership was retained"),
        "{ended}"
    );
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert_eq!(
        runtime.state.lock().await.active_case_id.as_deref(),
        Some("case-a")
    );
    assert_eq!(
        begin_case(&command("begin", "case-b"), runtime.state.clone()).await["ok"],
        false
    );
    task.abort();
}

#[tokio::test]
async fn global_background_delivery_spans_cases_but_still_blocks_session_finalization() {
    tokio::time::timeout(Duration::from_secs(5), background_spans_cases())
        .await
        .unwrap();
}

async fn background_spans_cases() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_background(temp.path(), 500, true).await;
    let first = Uuid::from_u128(1).to_string();
    let second = Uuid::from_u128(2).to_string();
    assert_eq!(
        begin_case(&command("begin", &first), runtime.state.clone()).await["ok"],
        true
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let replay = runtime.clone();
    let task = tokio::spawn(async move { replay.run_tcp(listener).await });
    let mut background = TcpStream::connect(address).await.unwrap();
    background.write_all(b"POST /background HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    read_head(&mut background).await;
    {
        let state = runtime.state.lock().await;
        assert!(state.http_has_in_flight());
        assert!(!state.http_has_case_in_flight());
    }
    let ended = end_case(&command("end", &first), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    assert_eq!(
        begin_case(&command("begin", &second), runtime.state.clone()).await["ok"],
        true
    );
    assert!(runtime.state.lock().await.http_has_in_flight());
    let ended = end_case(&command("end", &second), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    let finalize = ReplayControlRequest {
        command: "finalize".into(),
        case_id: None,
        fail_on_dirty: true,
        fail_on_incomplete: true,
        identity_pairs: Vec::new(),
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    };
    let (pending, report) = finalize_replay(&finalize, runtime.state.clone()).await;
    assert_eq!(pending["ok"], false);
    assert_eq!(pending["complete"], false);
    assert!(pending["error"].as_str().unwrap().contains("in flight"));
    assert!(report.is_none());

    let mut tail = Vec::new();
    background.read_to_end(&mut tail).await.unwrap();
    assert!(tail.ends_with(b"0\r\n\r\n"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.state.lock().await.http_has_in_flight() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = runtime.state.lock().await;
    let report = state.snapshot_report();
    assert_eq!(report.matched_http_exchanges.len(), 1);
    let delivered = serde_json::to_value(&report.matched_http_exchanges[0]).unwrap();
    assert_eq!(delivered["source"], "process");
    assert_eq!(delivered["case_id"], first);
    assert!(report.unused_global_http_exchanges.is_empty());
    drop(state);
    let (finished, report) = finalize_replay(&finalize, runtime.state.clone()).await;
    assert_eq!(finished["ok"], true, "{finished}");
    assert_eq!(finished["complete"], true);
    assert!(report.is_some());
    task.abort();
}

async fn read_head(stream: &mut TcpStream) {
    let mut header = Vec::new();
    while !header.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let mut buffer = [0; 1024];
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0 && header.len() + count <= 8192);
        header.extend_from_slice(&buffer[..count]);
    }
}
