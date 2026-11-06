//! A finite native input must not cap the number of actual Target output events.
use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

const EVENTS: usize = 12_553;

#[tokio::test]
async fn native_clock_keeps_large_ws_output_without_unused_event_feedback() {
    let temp = tempfile::tempdir().unwrap();
    let (globals, original) = fixture(temp.path());
    let path = temp.path().join("case/request.json");
    let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    request["uri"] = "/socket.io/?EIO=4&transport=websocket".into();
    request["headers"] = json!({});
    request["body"] = capture(b"");
    request["interaction"]["policy"]["max_duration_ms"] = 30_000.into();
    request["interaction"]["policy"]["request_timeout_ms"] = 30_000.into();
    request["interaction"]["policy"]["business_idle_ms"] = 5_000.into();
    std::fs::write(path, request.to_string()).unwrap();
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
    assert_eq!(
        guards::control(&runtime, json!({"command":"request_begin","case_id":CASE})).await["ok"],
        true
    );
    let socket_path = temp.path().join("control.sock");
    let session = temp.path().join("session.json");
    std::fs::write(&session, json!({"control_socket":socket_path}).to_string()).unwrap();
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let state = runtime.state.clone();
    let control = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            crate::replay::control::handle_control_stream(stream, state.clone(), None, None)
                .await
                .unwrap();
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target_runtime = runtime.clone();
    let target = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text("0{\"sid\":\"engine-sid\",\"upgrades\":[],\"pingInterval\":30000,\"pingTimeout\":30000}".into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40/chat,{}"
        );
        socket
            .send(Message::Text("40/chat,{\"sid\":\"actual-sid\"}".into()))
            .await
            .unwrap();
        let (mut subscriber, subscriber_task) = connect(&target_runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        assert_eq!(read(&mut subscriber).await, original);
        // Actual Target output is independently received through TCP. These
        // names are not inverse-RPC prerequisites, so retaining each name or
        // output would create a new unbounded inventory.
        for index in 0..EVENTS {
            socket
                .send(Message::Text(
                    format!("42/chat,[\"actual:notice:{index}\",{{\"index\":{index}}}]").into(),
                ))
                .await
                .unwrap();
        }
        socket.close(None).await.unwrap();
        subscriber_task.abort();
    });
    let client = crate::recorded_request::RecordedHttpClient::new(
        format!("http://{address}"),
        Duration::from_secs(30),
        16 * 1024 * 1024,
    )
    .with_input_registration(&session, CASE);
    let response = client
        .send_bytes(&serde_json::to_vec(&request).unwrap(), "native-event-scale")
        .await
        .unwrap();
    target.await.unwrap();
    let output = response.interaction.unwrap();
    assert!(output.end.clean);
    assert_eq!(output.events.len(), EVENTS + 2);
    let epoch = {
        let state = runtime.state.lock().await;
        assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 1);
        assert_eq!(state.redis.pubsub.report().unwrap().failed_pushes, 0);
        state.redis.pubsub.native_clock.epoch(CASE).unwrap()
    };
    // This native clock has no ingress event prerequisites. Capturing a large
    // WS response leaves the control-side event ordinal unused.
    for (at, ordinal) in [
        (epoch, EVENTS as u64 + 1),
        (epoch, 2),
        (epoch + chrono::TimeDelta::milliseconds(1), 1),
    ] {
        let response = guards::control(
            &runtime,
            json!({"command":"native_event","case_id":CASE,"native_event":{
                "epoch":at,"event":{"namespace":"/chat","event":"actual:notice","ordinal":ordinal}}}),
        )
        .await;
        assert_eq!(response["ok"], false);
    }
    assert_eq!(
        guards::control(
            &runtime,
            json!({"command":"native_event","case_id":CASE,"native_event":{
                "epoch":epoch,"event":{"namespace":"/chat","event":"actual:notice","ordinal":1}}})
        )
        .await["ok"],
        true
    );
    control.abort();
}
