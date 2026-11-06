//! Failed cases retain their diagnostics and yield to later cases after cleanup.
use super::*;
use crate::e2e_run::model::CaseStatus;
use crate::interaction::{
    model::{InputAction, InputActionKind, InputTranscript, Protocol, WireMessage},
    policy::{InteractionPolicy, StreamTerminal},
};
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, UnixListener},
};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn rejected_socketio_session_does_not_stop_the_next_case() {
    rejected_session(Protocol::SocketIo, 2, 10).await;
}

#[tokio::test]
async fn rejected_websocket_session_does_not_stop_the_next_case() {
    rejected_session(Protocol::WebSocket, 2, 10).await;
}

#[tokio::test]
async fn rejected_sessions_stop_only_after_the_configured_failure_count() {
    rejected_session(Protocol::SocketIo, 12, 10).await;
}

async fn rejected_session(protocol: Protocol, case_count: usize, failure_limit: usize) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    std::fs::create_dir_all(root.join(".traffic-e2e/local")).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    let (mut layout, _, mut state) = super::super::test_session::session(root);
    layout.active_dir = root.join(".traffic-e2e/local/runtime/active");
    std::fs::create_dir_all(layout.active_dir.join("reports")).unwrap();
    let template = state.cases[0].clone();
    state.cases = (0..case_count)
        .map(|index| {
            let mut case = template.clone();
            case.case_id = format!("case-{index}");
            case.case_dir = root.join("recording").join(&case.case_id);
            std::fs::create_dir_all(&case.case_dir).unwrap();
            case.status = CaseStatus::Pending;
            case.assertion_passed = None;
            case.replay_clean = None;
            case
        })
        .collect();
    let mut config = super::super::test_session::config(root);
    config.runner_owned_response_assertions = false;
    config.replay_loading.lazy_cases = false;
    config.max_failed_cases_per_api = failure_limit;
    std::fs::write(
        &config.replay_policy,
        "format: traffic-policy/v3\nrules: []\n",
    )
    .unwrap();
    let runtime = CaseExecutionRuntime {
        request_rules: Arc::new(
            crate::request_rules::RequestRuleRuntime::load(root, &config.replay_policy).unwrap(),
        ),
        response_assertions: None,
    };
    state.target_started = true;
    let failed_id = state.cases[0].case_id.clone();
    let rejected = Arc::new(AtomicBool::new(false));
    let control_rejected = rejected.clone();
    let control_socket = root.join("control.sock");
    let listener = UnixListener::bind(&control_socket).unwrap();
    state.replay_session = layout.active_dir.join("session.json");
    std::fs::write(
        &state.replay_session,
        json!({"control_socket":control_socket}).to_string(),
    )
    .unwrap();
    let control = tokio::spawn(async move {
        let mut active = None;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.is_empty() {
                continue;
            }
            let request: Value = serde_json::from_str(&line).unwrap();
            let case = request["case_id"].as_str();
            let reply = match request["command"].as_str().unwrap() {
                "begin" => {
                    assert!(active.is_none());
                    active = case.map(str::to_owned);
                    json!({"ok":true})
                }
                "request_begin" | "case_failed" => {
                    assert_eq!(active.as_deref(), case);
                    json!({"ok":true})
                }
                "native_event_begin" => {
                    assert_eq!(active.as_deref(), case);
                    json!({"ok":true,"enabled":false})
                }
                "input_timing_begin" => {
                    assert_eq!(active.as_deref(), case);
                    json!({"ok":true,"epoch":"2020-01-01T00:00:00Z"})
                }
                "case_execution_status" => {
                    let failed = case == Some(failed_id.as_str())
                        && control_rejected.load(Ordering::Acquire);
                    json!({"ok":true,"failed":failed,"kind":"dependency_unmatched", "failures":if failed {json!([{"protocol":"redis","command":"SET","target_event_index":0}])} else {json!([])}})
                }
                "end" => {
                    assert_eq!(active.take().as_deref(), case);
                    json!({"ok":false,"dirty":true,"error":"unmatched dependency"})
                }
                "status" => json!({"ok":true,"session":{"active_case_id":active}}),
                command => panic!("unexpected control {command}"),
            };
            let _ = reader
                .into_inner()
                .write_all(format!("{reply}\n").as_bytes())
                .await;
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.target_http_origin = format!("http://{}", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let target_accepted = accepted.clone();
    let target = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        target_accepted.fetch_add(1, Ordering::SeqCst);
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        if protocol == Protocol::SocketIo {
            socket.send(Message::Text(r#"0{"sid":"live-target","upgrades":[],"pingInterval":1000,"pingTimeout":1000,"maxPayload":1048576}"#.into())).await.unwrap();
        }
        let input = socket.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(
            input,
            if protocol == Protocol::SocketIo {
                "40/local-executor,{}"
            } else {
                "request"
            }
        );
        rejected.store(true, Ordering::Release);
        // The failed primary transport closes before later cases connect.
        while let Some(Ok(message)) = socket.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            target_accepted.fetch_add(1, Ordering::SeqCst);
            stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        }
    });
    for case in &state.cases {
        let policy = InteractionPolicy {
            business_idle_ms: 5_000,
            max_duration_ms: 10_000,
            cleanup_timeout_ms: 200,
            request_timeout_ms: 1_000,
            stream_terminal: (protocol == Protocol::WebSocket).then(|| StreamTerminal::Text {
                value: "complete".into(),
            }),
            ..InteractionPolicy::default()
        };
        let mut input = InputTranscript::new(protocol, policy);
        input.actions.push(InputAction {
            sequence: 1,
            offset_ms: 0,
            offset_us: None,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text(if protocol == Protocol::SocketIo {
                    "40/local-executor,{}"
                } else {
                    "request"
                }),
            },
        });
        std::fs::write(case.case_dir.join("request.json"),json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=websocket","headers":{},"body":{"encoding":"utf8","data":"","truncated":false},"interaction":input}).to_string()).unwrap();
    }
    tokio::time::timeout(
        Duration::from_secs(3),
        execute(&config, &layout, &mut state, &runtime),
    )
    .await
    .unwrap()
    .unwrap();
    control.abort();
    target.abort();
    assert_eq!(
        state.cases[0].status,
        CaseStatus::Failed,
        "{:?}",
        state.errors
    );
    assert!(
        state.cases[0].execution_failure.is_some(),
        "{:?}",
        state.errors
    );
    assert_eq!(
        state.cases[0].execution_failure.as_ref().unwrap()["observed_primary_status"],
        101,
        "{:?}",
        state.errors
    );
    assert_eq!(
        state.cases[0].execution_failure.as_ref().unwrap()["request_completed"],
        false
    );
    let executed = case_count.min(failure_limit);
    assert!(
        state.cases[..executed]
            .iter()
            .all(|case| case.status == CaseStatus::Failed),
        "{:?}",
        state.errors
    );
    assert!(
        state.cases[executed..]
            .iter()
            .all(|case| case.status == CaseStatus::Pending)
    );
    assert_eq!(accepted.load(Ordering::SeqCst), executed);
    // Target shutdown and aggregate finalization remain with the caller.
    assert!(state.target_started);
}
