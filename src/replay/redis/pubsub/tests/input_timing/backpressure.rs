//! A claimed response blocked in write_all is not a delivered prerequisite.
use super::*;

#[tokio::test]
async fn full_redis_tcp_buffer_prevents_fast_input_until_response_is_written() {
    let temp = tempfile::tempdir().unwrap();
    let request = input(30_000);
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    let bytes = vec![b'x'; 8 * 1024 * 1024];
    let response = [format!("${}\r\n", bytes.len()).as_bytes(), &bytes, b"\r\n"].concat();
    let mut dependency = exchange(Uuid::new_v4(), 1, "GET", &[b"large"], &response);
    dependency["response_kind"] = "bulk_string".into();
    dependency["timestamp"] = "2020-01-01T00:00:00.180Z".into();
    let runtime = runtime(temp.path(), &[dependency], &[], false)
        .await
        .unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target_runtime = runtime.clone();
    let target = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(
                "0{\"sid\":\"live\",\"upgrades\":[],\"pingInterval\":10000,\"pingTimeout\":10000}"
                    .into(),
            ))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, "40");
        socket
            .send(Message::Text("40{\"sid\":\"ns\"}".into()))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, "421[\"work\"]");
        let (mut redis, task) = connect(&target_runtime).await;
        redis.max_frame_bytes = 16 * 1024 * 1024;
        redis
            .inner
            .write_all(&crate::redis::encode_array(&[b"GET", b"large"]))
            .await
            .unwrap();
        socket
            .send(Message::Text("431[\"done\"]".into()))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), socket.next())
                .await
                .is_err()
        );
        assert_eq!(
            target_runtime.state.lock().await.protocols.redis.exchanges[0].status,
            ReplayExchangeStatus::Responding
        );
        assert_eq!(read(&mut redis).await, response);
        assert_eq!(text(&mut socket).await, "422[\"work\"]");
        socket
            .send(Message::Text("432[\"done\"]".into()))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, "1");
        socket.send(Message::Close(None)).await.unwrap();
        task.abort();
    });
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        crate::recorded_request::RecordedHttpClient::new(
            format!("http://{address}"),
            Duration::from_secs(5),
            1024 * 1024,
        )
        .with_input_registration(&session, "case")
        .send_bytes(&serde_json::to_vec(&request).unwrap(), "backpressure"),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.interaction.unwrap().end.clean);
    target.await.unwrap();
    control.abort();
}
