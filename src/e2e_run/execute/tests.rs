//! The executor keeps a Target alive across successful interaction cases.

use super::*;
use crate::interaction::{
    model::{InputTranscript, Protocol},
    policy::InteractionPolicy,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, UnixListener},
};

#[tokio::test]
async fn successful_stream_cases_reuse_the_running_target_and_normal_case_controls() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    std::fs::create_dir_all(root.join(".traffic-e2e/local")).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    let (mut layout, _, mut state) = super::super::test_session::session(root);
    layout.active_dir = root.join(".traffic-e2e/local/runtime/active");
    std::fs::create_dir_all(layout.active_dir.join("reports")).unwrap();
    let mut config = super::super::test_session::config(root);
    config.runner_owned_response_assertions = false;
    config.replay_loading.lazy_cases = false;
    std::fs::write(
        &config.replay_policy,
        "format: traffic-policy/v1\nrules: []\n",
    )
    .unwrap();
    let runtime = CaseExecutionRuntime {
        request_rules: Arc::new(
            crate::request_rules::RequestRuleRuntime::load(root, &config.replay_policy).unwrap(),
        ),
        response_assertions: None,
    };
    state.target_started = true;
    state.target_container_name = None;
    state.replay_session = layout.active_dir.join("replay-session.json");
    let socket = root.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::write(
        &state.replay_session,
        json!({"control_socket":socket}).to_string(),
    )
    .unwrap();
    // Control transport is exercised here; real Replay dependency ownership and
    // delivery are covered independently by replay::control::tests::streaming.
    let control = tokio::spawn(async move {
        let mut commands = Vec::new();
        let mut active = None;
        for _ in 0..6 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let command = request["command"].as_str().unwrap();
            let case_id = request["case_id"].as_str().unwrap();
            match command {
                "begin" => {
                    assert!(active.is_none());
                    active = Some(case_id.to_owned());
                }
                "request_begin" => assert_eq!(active.as_deref(), Some(case_id)),
                "end" => assert_eq!(active.take().as_deref(), Some(case_id)),
                _ => panic!("unexpected case control: {command}"),
            }
            commands.push(format!("{command}:{case_id}"));
            reader
                .into_inner()
                .write_all(b"{\"ok\":true}\n")
                .await
                .unwrap();
        }
        commands
    });
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.target_http_origin = format!("http://{}", target_listener.local_addr().unwrap());
    let target = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut buffer = [0; 1024];
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0 && header.len() + count <= 8192);
                header.extend_from_slice(&buffer[..count]);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\nContent-Length: 14\r\n\r\ndata: [DONE]\n\n").await.unwrap();
        }
    });
    for (position, case) in state.cases.clone().into_iter().enumerate() {
        let input = InputTranscript::new(Protocol::Sse, InteractionPolicy::default());
        std::fs::write(
            case.case_dir.join("request.json"),
            json!({"method":"GET","uri":"/events","headers":{},
                "body":{"encoding":"utf8","data":"","truncated":false},
                "interaction":input})
            .to_string(),
        )
        .unwrap();
        execute_case(
            &config,
            &layout,
            &mut state,
            position,
            &case.case_id,
            &case.case_dir,
            &runtime,
        )
        .await
        .unwrap();
        assert_eq!(
            state.cases[position].status,
            CaseStatus::Passed,
            "{:?}",
            state.errors
        );
        assert!(
            state.target_started,
            "normal case end must keep Target running"
        );
    }
    target.await.unwrap();
    let commands = control.await.unwrap();
    let expected = state
        .cases
        .iter()
        .flat_map(|case| {
            ["begin", "request_begin", "end"].map(|command| format!("{command}:{}", case.case_id))
        })
        .collect::<Vec<_>>();
    assert_eq!(commands, expected);
    assert!(state.errors.is_empty(), "{:?}", state.errors);
    assert!(!layout.active_dir.join("reports/target-stop.json").exists());
}
