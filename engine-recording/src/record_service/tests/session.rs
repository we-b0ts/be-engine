use super::*;
use crate::dependency_index::{RecordStream, recording, scoped};
use crate::protocols::recording::events::{RecorderEvent, RedisExchangeEvent};
use traffic_model::session::{ENGINE_SHUTDOWN_CANCEL_REASON, SessionEvent};
use traffic_model::trace::{CaptureEvent, OutputKind};
use traffic_model::{DependencyExchangeOutcome, capture::capture_body};
use traffic_recording_store::{session::PrimaryEventKind, session_timeline::SessionTimelineEvent};

#[test]
fn session_ingress_opens_while_startup_is_active_and_records_overlapping_responses() {
    runtime().block_on(async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        tokio::time::timeout(Duration::from_secs(5), verify_session())
            .await
            .unwrap();
    });
}

#[tokio::test]
async fn managed_source_exit_seals_only_the_flushed_http_stream_prefix() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    for flush_before_exit in [true, false] {
        tokio::time::timeout(
            Duration::from_secs(5),
            stream_at_source_exit(flush_before_exit),
        )
        .await
        .unwrap();
    }
}

async fn stream_at_source_exit(flush_before_exit: bool) {
    use hyper_util::rt::TokioIo;
    use std::time::Instant;
    use tokio::net::TcpStream;

    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.session_events = true;
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.encrypt_request_headers.clear();
    config.dns_mock.registry_path = temp.path().join("fake-dns.json");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = crate::AppState::new(config).await.unwrap();
    state.session_event(SessionEvent::SourceStart).unwrap();
    state.session_event(SessionEvent::Ready).unwrap();

    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = upstream.local_addr().unwrap();
    let (send_chunk, chunk_requested) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        assert!(read_request(&mut socket).await.starts_with("GET /stream "));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        chunk_requested.await.unwrap();
        socket.write_all(b"6\r\nprefix\r\n").await.unwrap();
        std::future::pending::<()>().await;
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let proxy = tokio::spawn(crate::proxy::http::run_with_listener(
        state.clone(),
        listener,
    ));
    let (mut source, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let mut body = source
        .send_request(
            Request::builder()
                .uri(format!("http://{authority}/stream"))
                .header("host", authority.to_string())
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body();

    let source_exit = || {
        state.session_event(SessionEvent::Stop).unwrap();
        let boundary = Instant::now();
        state
            .session_event(SessionEvent::SourceExit {
                status: Some(0),
                forced_by_recorder: false,
            })
            .unwrap();
        boundary
    };
    let early_exit = (!flush_before_exit).then(source_exit);
    send_chunk.send(()).unwrap();
    assert_eq!(
        body.frame().await.unwrap().unwrap().into_data().unwrap(),
        "prefix"
    );
    let boundary = early_exit.unwrap_or_else(source_exit);
    state.begin_case_quiescing();
    super::super::reset_dependencies_after_source_exit(&state, Some(boundary));
    assert!(body.frame().await.is_none_or(|frame| frame.is_err()));
    assert!(state.close_dependency_capture().await);
    state.recorder().finish_run().await.unwrap();

    let run_dir = &state.recorder().run_dir;
    let (_, manifest) = recording::manifest(run_dir).unwrap();
    assert_eq!(manifest.capture_complete, flush_before_exit);
    assert_eq!(
        manifest.coverage.capture_failures,
        u64::from(!flush_before_exit)
    );
    let mut records = RecordStream::open(&recording::dependency_path(run_dir)).unwrap();
    let (_, row) = records.next().unwrap().unwrap();
    let record: serde_json::Value = serde_json::from_slice(row).unwrap();
    assert!(records.next().unwrap().is_none());
    assert_eq!(record["outcome"], "response");
    assert_eq!(record["response_body"]["data"], "cHJlZml4");
    assert_eq!(record["response_stream"]["complete"], false);
    assert_eq!(record["error"].is_null(), flush_before_exit);
    if flush_before_exit {
        assert_eq!(record["response_stream"]["stopped_at_source_exit"], true);
        let events = traffic_recording_store::session_timeline::read(run_dir).unwrap();
        let mut output = Vec::new();
        let mut exit = None;
        for event in events {
            match event.unwrap() {
                SessionTimelineEvent::Primary(row)
                    if matches!(row.event, PrimaryEventKind::SourceExit) =>
                {
                    exit = Some(row.sequence);
                }
                SessionTimelineEvent::Dependency(row) => {
                    if let CaptureEvent::Output { output: kind, .. } = row.event {
                        output.push((row.sequence, kind));
                    }
                }
                _ => {}
            }
        }
        assert_eq!(
            output.iter().map(|(_, kind)| *kind).collect::<Vec<_>>(),
            [
                OutputKind::Headers,
                OutputKind::Part,
                OutputKind::TargetStop
            ]
        );
        let exit = exit.unwrap();
        assert!(output[1].0 < exit && exit < output[2].0);
    } else {
        assert!(record["response_stream"]["stopped_at_source_exit"].is_null());
    }
    proxy.abort();
    upstream.abort();
    connection.abort();
}

async fn verify_session() {
    let temp = tempfile::tempdir().unwrap();
    let project = super::project::fixture(&temp);
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut options = super::project::options(&project);
    options.session_events = true;
    options.recorder_listen = gateway.local_addr().unwrap();
    options.source_origin = format!("http://{}", source.local_addr().unwrap());
    options.data_root = temp.path().join("data");
    options.no_interception = true;
    let mut config = options.config().unwrap();
    config.http_gateway.ready.interval_ms = 1;
    config.http_gateway.rules.clear();
    config.http_gateway.exclude_rules.clear();
    config.recording.encrypt_request_headers.clear();
    let state = crate::AppState::new(config).await.unwrap();
    let startup = state.capture_dependency_targets();
    let relay: proxy::Relay<RedisService> = proxy::Relay::new(
        None,
        format!("http://{}", options.recorder_listen)
            .parse()
            .unwrap(),
        None,
        Duration::from_secs(2),
        1024,
    )
    .with_session_events(state.clone(), options.ingress_capacity(state.config()));
    let (stop, stopping) = watch::channel(false);
    let adapter = tokio::spawn(proxy::serve(listener, relay.clone(), stopping));
    let source = tokio::spawn(run_source(source));

    state.session_event(SessionEvent::SourceStart).unwrap();
    state.inner.source_started.send_replace(true);
    record_redis_read(&state);
    let gateway = tokio::spawn(crate::gateway::http::run_with_listener(
        state.clone(),
        gateway,
    ));
    while !state.inner.recording_lifecycle.snapshot().ready {
        tokio::task::yield_now().await;
    }
    relay.open();

    let slow = tokio::spawn(send(address, "/api/slow"));
    let mut slow_body = slow.await.unwrap().into_body();
    assert_eq!(
        slow_body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"start")
    );
    let fast = send(address, "/api/fast").await;
    assert_eq!(fast.status(), StatusCode::OK);
    assert_eq!(fast.into_body().collect().await.unwrap().to_bytes(), "fast");
    assert_eq!(slow_body.collect().await.unwrap().to_bytes(), "done");
    drop(startup);

    let long = send(address, "/api/long").await;
    assert_eq!(long.status(), StatusCode::OK);
    let mut long_body = long.into_body();
    assert_eq!(
        long_body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"open")
    );
    relay.close();
    super::super::shutdown::drain_session(&state, &relay, Duration::from_millis(20))
        .await
        .unwrap();
    state.session_event(SessionEvent::Stop).unwrap();
    assert!(long_body.frame().await.is_none_or(|frame| frame.is_err()));
    // Source observes the disconnect while its HTTP gateway is still running.
    source.await.unwrap();
    stop.send_replace(true);
    adapter.await.unwrap().unwrap();
    gateway.abort();
    let _ = gateway.await;
    state
        .session_event(SessionEvent::SourceExit {
            status: Some(0),
            forced_by_recorder: false,
        })
        .unwrap();
    state.recorder().finish_run().await.unwrap();
    let rows: Vec<SessionEvent> = traffic_recording_store::session::read(&state.recorder().run_dir)
        .unwrap()
        .into_iter()
        .map(|row| row.event)
        .collect();
    let (slow_index, slow_id) = request(&rows, "/api/slow");
    let (fast_index, _) = request(&rows, "/api/fast");
    let (long_index, long_id) = request(&rows, "/api/long");
    let ready = rows
        .iter()
        .position(|event| matches!(event, SessionEvent::Ready))
        .unwrap();
    let slow_end = rows.iter().position(|event| matches!(event, SessionEvent::PrimaryResponseEnd { exchange } if *exchange == slow_id)).unwrap();
    assert!(ready < slow_index && slow_index < fast_index && fast_index < slow_end);
    assert!(slow_end < long_index);
    assert!(matches!(
        &rows[..],
        [
            ..,
            SessionEvent::PrimaryCancel { exchange, reason },
            SessionEvent::Stop,
            SessionEvent::SourceExit { status: Some(0), forced_by_recorder: false }
        ] if *exchange == long_id && reason == ENGINE_SHUTDOWN_CANCEL_REASON
    ));
    let run_dir = &state.recorder().run_dir;
    let (_, manifest) = recording::manifest(run_dir).unwrap();
    assert!(manifest.sealed && manifest.capture_complete);
    for path in [
        "apis",
        "request-response.tsv",
        "dependencies.tsv",
        "dependencies-push.tsv",
        "dependencies-process.tsv",
        "dependencies-unattributed.tsv",
        "dependency-locations.bin",
        "event-locations.bin",
        "event-spans.bin",
        "indexes/process-scope.bin",
        "indexes/shutdown-scope.bin",
        "indexes/startup-scope.bin",
        "indexes/unattributed-scope.bin",
        "global-dependencies-summary.json",
        "pre-readiness-traffic-summary.json",
        "recording-shutdown.json",
        traffic_recorder::source_process::SUMMARY_FILENAME,
    ] {
        assert!(!run_dir.join(path).exists(), "unexpected artifact {path}");
        assert!(
            manifest.files.iter().all(|file| file.path != path),
            "unexpected manifest entry {path}"
        );
    }
    recording::authenticate(run_dir).unwrap();
    let central = recording::dependency_path(run_dir);
    assert!(scoped::selected_bytes(&central).unwrap() > 0);
    assert_eq!(manifest.semantic_inventory.total_mandatory, 1);
    let mut records = RecordStream::open(&central).unwrap();
    let (location, row) = records.next().unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(row).unwrap()["command"],
        "GET"
    );
    let source = scoped::resolve(&central).unwrap();
    let mut locations = source.replay_locations().unwrap();
    let indexed = locations.next().unwrap().unwrap();
    assert_eq!(
        (indexed.line, indexed.offset, indexed.length),
        (location.line, location.offset, location.length)
    );
    assert!(locations.next().is_none());
    let summary = traffic_recording_store::session_summary::read(run_dir).unwrap();
    assert_eq!(summary.primary_cancelled, 1);
    assert_eq!(summary.mandatory_by_protocol.get("redis"), Some(&1));
    assert_eq!(
        summary
            .routes
            .iter()
            .map(|route| (route.path.as_str(), route.requests))
            .collect::<Vec<_>>(),
        [("/api/fast", 1), ("/api/long", 1), ("/api/slow", 1)]
    );
    let report: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(state.recorder().run_dir.join("recording-run.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["status"], "completed");
    assert_eq!(report["published_cases"], 0);
}

fn record_redis_read(state: &crate::AppState) {
    let now = chrono::Utc::now();
    state.record_event(RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: uuid::Uuid::new_v4(),
        connection_id: uuid::Uuid::new_v4(),
        sequence: 1,
        timestamp: now,
        request_started_at: now,
        client_addr: None,
        target_host: "cache.session.test".into(),
        target_port: 6379,
        target_addr: "cache.session.test:6379".into(),
        upstream_addr: "127.0.0.1:6379".into(),
        resp_version: 2,
        database: 0,
        username: None,
        command: "GET".into(),
        args: vec![capture_body(b"key", 3)],
        response_kind: "bulk".into(),
        response: capture_body(b"$5\r\nvalue\r\n", 11),
        rpc_callback_capture: None,
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    }));
}

async fn send(
    address: std::net::SocketAddr,
    path: &'static str,
) -> hyper::Response<hyper::body::Incoming> {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    client
        .get(format!("http://{address}{path}").parse().unwrap())
        .await
        .unwrap()
}

fn request(rows: &[SessionEvent], uri: &str) -> (usize, uuid::Uuid) {
    rows.iter()
        .enumerate()
        .find_map(|(index, event)| match event {
            SessionEvent::PrimaryRequest { exchange, request } if request["uri"] == uri => {
                Some((index, *exchange))
            }
            _ => None,
        })
        .unwrap()
}

async fn run_source(source: TcpListener) {
    // Transport readiness itself sends no HTTP input.
    let (mut connect_probe, _) = source.accept().await.unwrap();
    assert_eq!(connect_probe.read(&mut [0]).await.unwrap(), 0);
    let (mut ready, _) = source.accept().await.unwrap();
    assert!(read_request(&mut ready).await.starts_with("GET "));
    ready
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    drop(ready);
    let (mut slow, _) = source.accept().await.unwrap();
    assert!(read_request(&mut slow).await.starts_with("GET /api/slow "));
    slow.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nstart\r\n").await.unwrap();
    let (mut fast, _) = source.accept().await.unwrap();
    assert!(read_request(&mut fast).await.starts_with("GET /api/fast "));
    fast.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfast")
        .await
        .unwrap();
    slow.write_all(b"4\r\ndone\r\n0\r\n\r\n").await.unwrap();
    drop(slow);
    let (mut long, _) = source.accept().await.unwrap();
    assert!(read_request(&mut long).await.starts_with("GET /api/long "));
    long.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nopen\r\n").await.unwrap();
    match long.read(&mut [0]).await {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        result => panic!("Source SSE connection was not closed: {result:?}"),
    }
}
