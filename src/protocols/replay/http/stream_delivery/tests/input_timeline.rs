//! Real flushed dependency prefixes gate a separately delivered primary close.
use super::*;
use crate::replay::control::{ReplayControlRequest, handle_control_request};

async fn control(runtime: &Arc<crate::replay::ReplayRuntime>, value: Value) -> Value {
    let request: ReplayControlRequest = serde_json::from_value(value).unwrap();
    handle_control_request(request, runtime.state.clone(), None, None)
        .await
        .0
}

trait TestStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestStream for T {}

async fn exercise_shared_close(cap: u64, abandon: bool, cancel: Option<bool>, tls: bool) {
    let temp = crate::policy::runtime::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("shared-close");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let epoch = "2026-11-03T13:28:26Z";
    let mut dep = dependency();
    if tls {
        dep["scheme"] = json!("https");
    }
    dep["id"] = json!(uuid::Uuid::new_v4().to_string());
    dep["request_started_at"] = json!(epoch);
    dep["response_body"]["data"] = json!("onetwolate");
    dep["response_stream"] = json!({"version":2,"headers_ms":10,"chunks":[
        {"at_ms":90000,"start":0,"end":3},{"at_ms":99000,"start":3,"end":6},
        {"at_ms":101000,"start":6,"end":10}],"end_ms":142000,"complete":true});
    tokio::fs::write(case.join("dependencies.jsonl"), dep.to_string())
        .await
        .unwrap();
    let policy = None;
    let input = crate::interaction::model::InputTranscript::new(
        crate::interaction::model::Protocol::Sse,
        crate::interaction::policy::InteractionPolicy {
            request_timeout_ms: 900000,
            max_duration_ms: 900000,
            ..Default::default()
        },
    );
    let mut input = serde_json::to_value(input).unwrap();
    input["actions"] = json!([{"sequence":1,"offset_ms":100000,"after":[],"compressible_gap":false,
        "action":{"kind":"close","code":null,"reason":""}}]);
    tokio::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/tasks","timestamp":epoch,"interaction":input}).to_string(),
    )
    .await
    .unwrap();
    let (address, runtime, task) =
        crate::protocols::replay::http::tests::spawn_http_replay_with_policy(
            &case,
            vec![],
            policy,
            None,
        )
        .await;
    let id = {
        let mut state = runtime.state.lock().await;
        state.stream_timing = Some(crate::replay::ReplayStreamTiming::Fast);
        state.stream_interval_cap_ms = cap;
        state.cases.keys().next().unwrap().clone()
    };
    if runtime.state.lock().await.active_case_id.is_none() {
        let b = control(&runtime, json!({"command":"begin","case_id":id})).await;
        assert_eq!(b["ok"], true, "{b}");
    }
    let begin = control(
        &runtime,
        json!({"command":"http_input_timing_begin","case_id":id}),
    )
    .await;
    assert_eq!(begin["enabled"], true, "{begin}");
    let query = json!({"epoch":begin["epoch"],"sequence":1,"completed":[]});
    let close = |command: &str| {
        let mut query = query.clone();
        if command == "http_input_timing_closed" {
            query["closed_at"] = json!(chrono::Utc::now());
        }
        json!({"command":command,"case_id":id,"input_timing":query})
    };
    assert_eq!(
        control(&runtime, close("http_input_timing_closed")).await["ok"],
        false,
        "close cannot precede an unstarted Source input prefix"
    );
    let stream = TcpStream::connect(address).await.unwrap();
    let end = crate::dependency::termination::ConnectionControl::new(&stream).unwrap();
    let mut client: Box<dyn TestStream> = if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(runtime.ca.ca_cert_der()).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        Box::new(
            connector
                .connect(
                    rustls::pki_types::ServerName::try_from("stream.test").unwrap(),
                    stream,
                )
                .await
                .unwrap(),
        )
    } else {
        Box::new(stream)
    };
    client.write_all(b"POST /stream HTTP/1.1\r\nHost: stream.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    assert_eq!(chunk(&mut client).await, b"one");
    assert_eq!(chunk(&mut client).await, b"two");
    assert!(
        tokio::time::timeout(Duration::from_millis(30), chunk(&mut client))
            .await
            .is_err(),
        "future Source bytes must wait for the actual primary close acknowledgement"
    );
    let mut ready = control(&runtime, close("http_input_timing_wait")).await;
    while ready["ready"] != true {
        tokio::time::sleep(Duration::from_millis(5)).await;
        ready = control(&runtime, close("http_input_timing_wait")).await;
    }
    assert_eq!(ready["ready"], true, "{ready}");
    if let Some(early) = cancel {
        if early {
            end.reset().unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            control(&runtime, close("http_input_timing_closed")).await["ok"],
            true
        );
        if !early {
            end.reset().unwrap();
        }
        drop(client);
        for _ in 0..200 {
            let state = runtime.state.lock().await;
            if state.protocols.http_exchanges[0].status
                != crate::replay::ReplayExchangeStatus::Responding
            {
                break;
            }
            drop(state);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let state = runtime.state.lock().await;
        assert_eq!(state.http_case_is_dirty(&id), early);
        assert_eq!(
            state.protocols.http_events.cancelled.len(),
            usize::from(!early)
        );
        assert!(
            !state.protocols.http_exchanges[0].status.is_consumed(),
            "cancellation is not complete recorded EOF"
        );
        let report = state.snapshot_report();
        assert_eq!(
            report.native.cancelled_http_streams.len(),
            usize::from(!early)
        );
        assert_eq!(
            report.native.allowed_unused_case_http_exchanges.len(),
            usize::from(!early)
        );
        task.abort();
        return;
    }
    if abandon {
        runtime.state.lock().await.advance_admission_epoch();
        assert_eq!(
            control(&runtime, close("http_input_timing_closed")).await["ok"],
            false
        );
        runtime
            .state
            .lock()
            .await
            .primary_close_timing
            .as_ref()
            .unwrap()
            .abort();
        let mut rest = Vec::new();
        let _ = client.read_to_end(&mut rest).await;
        assert!(!rest.windows(4).any(|v| v == b"late"));
    } else {
        assert_eq!(
            control(&runtime, close("http_input_timing_closed")).await["ok"],
            true
        );
        assert_eq!(chunk(&mut client).await, b"late");
        assert!(chunk(&mut client).await.is_empty());
    }
    task.abort();
}

#[tokio::test]
async fn fast_http_timeline_preserves_wire_prefix_close_and_future_data_order() {
    tokio::time::timeout(Duration::from_secs(4), async {
        exercise_shared_close(5, false, None, false).await;
        exercise_shared_close(0, false, None, false).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn abandoned_http_timeline_cannot_release_future_source_bytes() {
    tokio::time::timeout(
        Duration::from_secs(4),
        exercise_shared_close(5, true, None, false),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn real_dependency_cancel_after_primary_close_is_audited_without_fabricating_eof() {
    tokio::time::timeout(Duration::from_secs(4), async {
        exercise_shared_close(50, false, Some(false), false).await;
        exercise_shared_close(50, false, Some(false), true).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dependency_cancel_before_the_actual_primary_close_remains_dirty() {
    tokio::time::timeout(Duration::from_secs(4), async {
        exercise_shared_close(50, false, Some(true), false).await;
        exercise_shared_close(50, false, Some(true), true).await;
    })
    .await
    .unwrap();
}
