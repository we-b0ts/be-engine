use super::*;
use crate::dependency_index::{recording, scoped};
use traffic_model::session::SessionEvent;

#[test]
fn session_ingress_opens_while_startup_is_active_and_records_overlapping_responses() {
    runtime().block_on(async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        tokio::time::timeout(Duration::from_secs(5), verify_session())
            .await
            .unwrap();
    });
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
        "all-apis".into(),
        Duration::from_secs(2),
        1024,
    )
    .with_session_events(state.clone());
    let (stop, stopping) = watch::channel(false);
    let adapter = tokio::spawn(proxy::serve(listener, relay.clone(), stopping));
    let source = tokio::spawn(run_source(source));

    state.session_event(SessionEvent::SourceStart).unwrap();
    state.inner.source_started.send_replace(true);
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

    relay.close();
    relay.drain().await;
    stop.send_replace(true);
    adapter.await.unwrap().unwrap();
    gateway.abort();
    let _ = gateway.await;
    source.await.unwrap();
    state.session_event(SessionEvent::Stop).unwrap();
    state
        .session_event(SessionEvent::SourceExit { status: Some(0) })
        .unwrap();
    state.recorder().finish_run().await.unwrap();
    let path = state.recorder().run_dir.join("request-response.tsv");
    let events = tokio::fs::read_to_string(path).await.unwrap();
    let rows: Vec<SessionEvent> = events
        .lines()
        .map(|row| serde_json::from_str(row.splitn(4, '\t').nth(3).unwrap()).unwrap())
        .collect();
    let (slow_index, slow_id) = request(&rows, "/api/slow");
    let (fast_index, _) = request(&rows, "/api/fast");
    let ready = rows
        .iter()
        .position(|event| matches!(event, SessionEvent::Ready))
        .unwrap();
    let slow_end = rows.iter().position(|event| matches!(event, SessionEvent::PrimaryResponseEnd { exchange } if *exchange == slow_id)).unwrap();
    assert!(ready < slow_index && slow_index < fast_index && fast_index < slow_end);
    let run_dir = &state.recorder().run_dir;
    let (_, manifest) = recording::manifest(run_dir).unwrap();
    for path in [
        "apis",
        "dependencies-process.tsv",
        "dependencies-unattributed.tsv",
        "indexes/process-scope.bin",
        "indexes/shutdown-scope.bin",
        "indexes/unattributed-scope.bin",
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
    let report: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(state.recorder().run_dir.join("recording-run.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["status"], "completed");
    assert_eq!(report["published_cases"], 0);
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
    slow.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nstart\r\n").await.unwrap();
    let (mut fast, _) = source.accept().await.unwrap();
    assert!(read_request(&mut fast).await.starts_with("GET /api/fast "));
    fast.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfast")
        .await
        .unwrap();
    slow.write_all(b"4\r\ndone\r\n0\r\n\r\n").await.unwrap();
}
