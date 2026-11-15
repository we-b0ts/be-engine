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

async fn exercise_shared_close(
    cap: u64,
    abandon: bool,
    cancel: Option<bool>,
    tls: bool,
    cache_tail: bool,
) {
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
    let policy = if cache_tail {
        let capture = |value: &str| json!({"encoding":"utf8","data":value,"truncated":false});
        let mut records = vec![dep];
        for (sequence, command, args, returned) in [
            (1, "EXPIRE", vec!["content:1", "600"], 1),
            (2, "APPEND", vec!["content:1", "onet"], 4),
        ] {
            records.push(json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),
                "sequence":sequence,"timestamp":epoch,"request_started_at":epoch,"duration_ms":0,
                "outcome":"response","target_host":"redis.test","target_port":6379,"database":0,
                "resp_version":2,"command":command,"args":args.into_iter().map(capture).collect::<Vec<_>>(),
                "response":capture(&format!(":{returned}\r\n")),"response_kind":"integer","replay_safe":true}));
        }
        tokio::fs::write(
            case.join("dependencies.jsonl"),
            records.iter().map(|v| format!("{v}\n")).collect::<String>(),
        )
        .await
        .unwrap();
        tokio::fs::write(case.join("expected-response.json"), json!({"status":200,"interaction":{
            "version":1,"protocol":"sse","events":[{"sequence":1,"offset_ms":99000,
                "message":{"kind":"text","data":json!({"data":json!({"delta":"onetwo"}).to_string()}).to_string()}}],
            "end":{"reason":"client_close","offset_ms":100000,"pending":[0],"clean":true}
        }}).to_string()).await.unwrap();
        let path = temp.path().join("policy.yaml");
        tokio::fs::write(&path, json!({"format":"traffic-policy/v3","rules":[{
            "id":"append","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},
                "operation":"APPEND","key":{"kind":"exact","value":"content:1"}},
            "effect":{"kind":"redis_append_stream"},"proof":{"source":"stream.py:1","fact":"Source buffers ordered response text into an expiring cache"}
        }]}).to_string()).await.unwrap();
        Some(path)
    } else {
        None
    };
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
    let (mut address, runtime, task) =
        crate::protocols::replay::http::tests::spawn_http_replay_with_policy(
            &case,
            vec![],
            policy,
            None,
        )
        .await;
    if cache_tail {
        // Two native resources need their own destinations; the single-target
        // localhost fallback cannot choose between HTTP and Redis.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        address = listener.local_addr().unwrap();
        let shared = runtime.state.clone();
        let ca = runtime.ca.clone();
        tokio::spawn(async move {
            let (accepted, peer) = listener.accept().await.unwrap();
            let _ = super::super::super::handle_http_replay_connection(
                accepted,
                peer,
                crate::replay::ReplayTarget {
                    host: "stream.test".into(),
                    port: if tls { 443 } else { 80 },
                    fake_ip: "198.18.0.8".parse().unwrap(),
                    protocol: if tls {
                        crate::replay::ReplayProtocol::Https
                    } else {
                        crate::replay::ReplayProtocol::Http
                    },
                },
                shared,
                ca,
            )
            .await;
        });
    }
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
    let mut redis_peer = if cache_tail {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let shared = runtime.state.clone();
        tokio::spawn(async move {
            crate::protocols::replay::redis::handle_connection(
                accepted,
                crate::replay::ReplayTarget {
                    host: "redis.test".into(),
                    port: 6379,
                    fake_ip: "198.18.0.9".parse().unwrap(),
                    protocol: crate::replay::ReplayProtocol::Redis,
                },
                shared,
            )
            .await
            .unwrap();
        });
        peer.write_all(b"*3\r\n$6\r\nEXPIRE\r\n$9\r\ncontent:1\r\n$3\r\n600\r\n*3\r\n$6\r\nAPPEND\r\n$9\r\ncontent:1\r\n$2\r\non\r\n").await.unwrap();
        let mut replies = [0; 8];
        peer.read_exact(&mut replies).await.unwrap();
        assert_eq!(&replies, b":1\r\n:2\r\n");
        Some(peer)
    } else {
        None
    };
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
        if cache_tail {
            assert_eq!(
                report
                    .native
                    .protocols
                    .redis
                    .allowed_cancelled_cache_tails
                    .len(),
                1
            );
            drop(state);
            let ended = control(
                &runtime,
                json!({"command":"end","case_id":id,"fail_on_dirty":true}),
            )
            .await;
            assert_eq!(ended["ok"], true, "{ended}");
            assert_eq!(ended["dirty"], false, "{ended}");
            let state = runtime.state.lock().await;
            assert!(state.snapshot_report().case_execution_failures.is_empty());
            assert!(
                !state
                    .protocols
                    .redis
                    .exchange_status(1)
                    .unwrap()
                    .is_consumed()
            );
            drop(state);
            redis_peer.take().unwrap().shutdown().await.unwrap();
        }
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
        exercise_shared_close(5, false, None, false, false).await;
        exercise_shared_close(0, false, None, false, false).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn abandoned_http_timeline_cannot_release_future_source_bytes() {
    tokio::time::timeout(
        Duration::from_secs(4),
        exercise_shared_close(5, true, None, false, false),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn real_dependency_cancel_after_primary_close_is_audited_without_fabricating_eof() {
    tokio::time::timeout(Duration::from_secs(4), async {
        exercise_shared_close(50, false, Some(false), false, false).await;
        exercise_shared_close(50, false, Some(false), true, false).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dependency_cancel_before_the_actual_primary_close_remains_dirty() {
    tokio::time::timeout(Duration::from_secs(4), async {
        exercise_shared_close(50, false, Some(true), false, false).await;
        exercise_shared_close(50, false, Some(true), true, false).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_http_and_partial_cache_finish_the_case_without_false_no_progress() {
    tokio::time::timeout(
        Duration::from_secs(4),
        exercise_shared_close(50, false, Some(false), true, true),
    )
    .await
    .unwrap();
}
