//! Empty subscriptions release their recording slot without stopping Source.

use super::*;
use crate::interaction::model::EndReason;

async fn heartbeat_stream(stream: &mut tokio::net::TcpStream, interval_ms: u64) {
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
    let interval = Duration::from_millis(interval_ms.max(1));
    let mut heartbeat = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    let mut input = [0; 1];
    loop {
        tokio::select! {
            read = stream.read(&mut input) => { assert_eq!(read.unwrap(), 0); break; },
            _ = heartbeat.tick(), if interval_ms > 0 => {
                if stream.write_all(b"8\r\n: ping\n\n\r\n").await.is_err() { break; }
            }
        }
    }
}

#[tokio::test]
async fn quiet_subscriptions_with_and_without_heartbeats_record_replay_and_release_the_slot() {
    for interval_ms in [0, 20] {
        timeout(
            Duration::from_secs(8),
            subscription_and_next_case(interval_ms),
        )
        .await
        .unwrap();
    }
}

async fn subscription_and_next_case(interval_ms: u64) {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), listener.local_addr().unwrap());
    settings.http_gateway.interaction.business_idle_ms = 180;
    settings.http_gateway.interaction.request_timeout_ms = 2_000;
    let state = AppState::new(settings).await.unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        heartbeat_stream(&mut stream, interval_ms).await;
        drop(stream);
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_head(&mut stream).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnext").await.unwrap();
        }
    });
    let (address, recording) = gateway(state.clone()).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{address}/events"))
                .header("accept", "text/event-stream")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.is_empty(), interval_ms == 0);
    let case = published(&state).await;
    let input: Value = serde_json::from_slice(
        &crate::request_headers::load_request_file(&case.join("request.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(input["interaction"]["http_stream_mode"], "subscription");
    let expected: Value =
        serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap())
            .unwrap();
    assert_eq!(expected["interaction"]["end"]["reason"], "business_idle");
    assert_eq!(expected["interaction"]["end"]["clean"], true);
    assert_eq!(
        expected["interaction"]["end"]["pending"],
        serde_json::json!([])
    );
    assert!(
        expected["interaction"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["heartbeat"] == true)
    );
    assert_eq!(state.recording_lifecycle_phase(), "running");
    assert!(!*state.inner.interactions.source_stop.borrow());

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        read_head(&mut stream).await;
        heartbeat_stream(&mut stream, if interval_ms == 0 { 0 } else { 35 }).await;
    });
    let actual = replay_case(&case, target_address).await;
    assert_eq!(actual.end.reason, EndReason::BusinessIdle);
    assert!(actual.end.clean);
    target_task.await.unwrap();

    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{address}/next"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "next"
    );
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(2))
            .await
    );
    let mut cases = Vec::new();
    find_cases(&state.recorder().run_dir.join("apis"), &mut cases);
    assert_eq!(cases.len(), 2);
    assert!(!state.recorder().run_dir.join("errors.jsonl").exists());
    assert_eq!(state.recording_lifecycle_phase(), "running");
    assert!(!*state.inner.interactions.source_stop.borrow());
    assert!(!source.is_finished());
    source.abort();
    recording.abort();
}

#[tokio::test]
async fn post_stream_waits_for_a_result_beyond_subscription_idle() {
    timeout(Duration::from_secs(5), delayed_post_response())
        .await
        .unwrap();
}

async fn delayed_post_response() {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), listener.local_addr().unwrap());
    settings.http_gateway.interaction.business_idle_ms = 60;
    let state = AppState::new(settings).await.unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n: ping\n\n\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(180)).await;
        let result = "data: result\n\n";
        stream
            .write_all(format!("{:x}\r\n{result}\r\n0\r\n\r\n", result.len()).as_bytes())
            .await
            .unwrap();
    });
    let (address, recording) = gateway(state.clone()).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let response = client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("http://{address}/compute"))
                .header("accept", "text/event-stream")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.ends_with(b"data: result\n\n"));
    source.await.unwrap();
    let case = published(&state).await;
    let input: Value = serde_json::from_slice(
        &crate::request_headers::load_request_file(&case.join("request.json")).unwrap(),
    )
    .unwrap();
    assert!(input["interaction"].get("http_stream_mode").is_none());
    let expected: Value =
        serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap())
            .unwrap();
    assert_eq!(expected["interaction"]["end"]["reason"], "server_eof");
    assert_eq!(expected["interaction"]["end"]["clean"], true);
    assert!(
        expected["interaction"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["heartbeat"] == false)
    );
    recording.abort();
}
