//! The executor keeps a Target alive across successful interaction cases.

use super::*;
use crate::interaction::{
    model::{InputTranscript, Protocol},
    policy::InteractionPolicy,
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, UnixListener},
};

#[tokio::test]
async fn status_failure_notifies_cleanup_and_remains_primary_while_body_only_failure_keeps_normal_end()
 {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    std::fs::create_dir_all(root.join(".traffic-e2e/local")).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    let (layout, _, mut state) = super::super::test_session::session(root);
    let mut config = super::super::test_session::config(root);
    config.runner_owned_response_assertions = true;
    config.replay_loading.lazy_cases = false;
    std::fs::write(
        &config.replay_policy,
        "format: traffic-policy/v3\nrules: []\n",
    )
    .unwrap();
    let runtime = CaseExecutionRuntime {
        request_rules: Arc::new(
            crate::request_rules::RequestRuleRuntime::load(root, &config.replay_policy).unwrap(),
        ),
        response_assertions: Some(ResponseAssertionRuntime::load(&config.replay_policy).unwrap()),
    };
    state.target_started = true;
    state.replay_finalized = false;
    state.aggregate_complete = false;
    state.replay_session = layout.active_dir.join("replay-session.json");
    let socket = root.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::write(
        &state.replay_session,
        json!({"control_socket":socket}).to_string(),
    )
    .unwrap();
    let failed_case = state.cases[0].case_id.clone();
    let control = tokio::spawn(async move {
        let mut commands = Vec::new();
        let mut active = None;
        let mut failed = false;
        let mut ended = 0;
        while ended < 2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.is_empty() {
                continue;
            }
            let request: Value = serde_json::from_str(&line).unwrap();
            let command = request["command"].as_str().unwrap();
            let case = request["case_id"].as_str().unwrap();
            match command {
                "begin" => {
                    assert!(active.is_none());
                    active = Some(case.to_owned());
                    failed = false;
                }
                "request_begin" => assert_eq!(active.as_deref(), Some(case)),
                "case_execution_status" => {}
                "case_failed" => {
                    assert_eq!(active.as_deref(), Some(case));
                    failed = true;
                }
                "end" => {
                    ended += 1;
                    assert_eq!(active.take().as_deref(), Some(case));
                    assert_eq!(failed, case == failed_case);
                }
                _ => panic!("unexpected control: {command}"),
            }
            if command != "case_execution_status" {
                commands.push(command.to_owned());
            }
            reader
                .into_inner()
                .write_all(b"{\"ok\":true}\n")
                .await
                .unwrap();
        }
        commands
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.target_http_origin = format!("http://{}", listener.local_addr().unwrap());
    let target = tokio::spawn(async move {
        for status in ["500 Internal Server Error", "200 OK"] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut buffer = [0; 1024];
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0 && head.len() + count <= 8192);
                head.extend_from_slice(&buffer[..count]);
            }
            let body = r#"{"detail":"failed"}"#;
            stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
    });
    for (position, case) in state.cases.clone().into_iter().enumerate() {
        std::fs::write(
            case.case_dir.join("request.json"),
            json!({
                "method":case.group_id.split_whitespace().next().unwrap(),"uri":"/api","headers":{},
                "body":{"encoding":"utf8","data":"","truncated":false}
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            case.case_dir.join("expected-response.json"),
            json!({
                "status":200,"headers":{"content-type":["application/json"]},
                "body":{"encoding":"utf8","data":"{\"created_at\":\"source\"}","truncated":false}
            })
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
        assert_eq!(state.cases[position].status, CaseStatus::Failed);
        assert!(state.target_started);
    }
    target.await.unwrap();
    assert_eq!(
        control.await.unwrap(),
        vec![
            "begin",
            "request_begin",
            "case_failed",
            "end",
            "begin",
            "request_begin",
            "end"
        ]
    );
    let report = run_result(&layout, &state);
    let representative = report.diagnosis.representative.unwrap();
    assert_eq!(
        representative.difference_kind,
        crate::replay::ResponseDifferenceKind::StatusMismatch
    );
    assert_eq!(representative.expected.value, Some(json!(200)));
    assert_eq!(representative.actual.value, Some(json!(500)));
    assert!(
        state
            .cases
            .iter()
            .all(|case| case.assertion_passed == Some(false))
    );
}

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
        let mut ended = 0;
        while ended < 2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.is_empty() {
                continue;
            }
            let request: Value = serde_json::from_str(&line).unwrap();
            let command = request["command"].as_str().unwrap();
            let case_id = request["case_id"].as_str().unwrap();
            match command {
                "begin" => {
                    assert!(active.is_none());
                    active = Some(case_id.to_owned());
                }
                "request_begin" | "case_execution_status" => {
                    assert_eq!(active.as_deref(), Some(case_id))
                }
                "end" => {
                    ended += 1;
                    assert_eq!(active.take().as_deref(), Some(case_id));
                }
                _ => panic!("unexpected case control: {command}"),
            }
            if command != "case_execution_status" {
                commands.push(format!("{command}:{case_id}"));
            }
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

#[tokio::test]
async fn unmatched_dependency_interrupts_only_its_case_and_reports_execution_evidence() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    std::fs::create_dir_all(root.join(".traffic-e2e/local")).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    let (layout, _, mut state) = super::super::test_session::session(root);
    let mut config = super::super::test_session::config(root);
    config.runner_owned_response_assertions = true;
    config.replay_loading.lazy_cases = false;
    std::fs::write(
        &config.replay_policy,
        "format: traffic-policy/v3\nrules: []\n",
    )
    .unwrap();
    let runtime = CaseExecutionRuntime {
        request_rules: Arc::new(
            crate::request_rules::RequestRuleRuntime::load(root, &config.replay_policy).unwrap(),
        ),
        response_assertions: Some(ResponseAssertionRuntime::load(&config.replay_policy).unwrap()),
    };
    state.target_started = true;
    let rejected = Arc::new(AtomicBool::new(false));
    let control_rejected = rejected.clone();
    let failed_id = state.cases[0].case_id.clone();
    let control_socket = root.join("failed-control.sock");
    let listener = UnixListener::bind(&control_socket).unwrap();
    state.replay_session = layout.active_dir.join("failed-session.json");
    std::fs::write(
        &state.replay_session,
        json!({"control_socket":control_socket}).to_string(),
    )
    .unwrap();
    let control = tokio::spawn(async move {
        let mut active = None;
        let mut ended = 0;
        while ended < 2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.is_empty() {
                continue;
            }
            let request: Value = serde_json::from_str(&line).unwrap();
            let command = request["command"].as_str().unwrap();
            let case = request["case_id"].as_str();
            let mut reply = json!({"ok":true});
            match command {
                "begin" => {
                    assert!(active.is_none());
                    active = case.map(str::to_owned);
                }
                "request_begin" | "case_failed" => assert_eq!(active.as_deref(), case),
                "case_execution_status" => {
                    let failed = case == Some(failed_id.as_str())
                        && control_rejected.load(Ordering::Acquire);
                    reply = json!({"ok":true,"failed":failed,"failures":if failed {json!([{"protocol":"redis","command":"PUBLISH","target_event_index":1,"reason":"request arguments did not match"}])} else {json!([])}});
                }
                "end" => {
                    assert_eq!(active.take().as_deref(), case);
                    ended += 1;
                    if case == Some(failed_id.as_str()) {
                        reply = json!({"ok":false,"dirty":true,"error":"unmatched dependency"});
                    }
                }
                "status" => reply = json!({"ok":true,"session":{"active_case_id":active}}),
                _ => panic!("unexpected control {command}"),
            }
            let _ = reader
                .into_inner()
                .write_all(format!("{reply}\n").as_bytes())
                .await;
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.target_http_origin = format!("http://{}", listener.local_addr().unwrap());
    let target = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        assert!(first.read(&mut bytes).await.unwrap() > 0);
        rejected.store(true, Ordering::Release);
        let (mut second, _) = listener.accept().await.unwrap();
        assert!(second.read(&mut bytes).await.unwrap() > 0);
        second.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
    });
    for (position, case) in state.cases.clone().into_iter().enumerate() {
        std::fs::write(case.case_dir.join("request.json"),json!({"method":"GET","uri":"/api","headers":{},"body":{"encoding":"utf8","data":"","truncated":false}}).to_string()).unwrap();
        std::fs::write(case.case_dir.join("expected-response.json"),json!({"status":200,"headers":{"content-type":["application/json"]},"body":{"encoding":"utf8","data":"{}","truncated":false}}).to_string()).unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            execute_case(
                &config,
                &layout,
                &mut state,
                position,
                &case.case_id,
                &case.case_dir,
                &runtime,
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }
    target.await.unwrap();
    control.await.unwrap();
    assert_eq!(state.cases[0].status, CaseStatus::Failed);
    assert_eq!(state.cases[1].status, CaseStatus::Passed);
    assert!(state.target_started);
    assert!(state.cases[1].execution_failure.is_none());
    let report = run_result(&layout, &state);
    assert_eq!(report.diagnosis.execution_failures.len(), 1);
    assert_eq!(
        report.diagnosis.execution_failures[0]["kind"],
        "dependency_unmatched"
    );
    assert_eq!(
        report.diagnosis.execution_failures[0]["request_completed"],
        false
    );
    assert_eq!(
        report.diagnosis.execution_failures[0]["failures"][0]["command"],
        "PUBLISH"
    );
    assert!(
        report.diagnosis.execution_failures[0]
            .get("observed_primary_status")
            .is_none()
    );
}
