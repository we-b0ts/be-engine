//! Real authenticated WS completion gates a finite Redis notification, not future inputs.
use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse as WsErrorResponse, Request as WsRequest, Response as WsResponse,
};

struct QueryToken(tokio::sync::oneshot::Sender<String>);
impl Callback for QueryToken {
    fn on_request(
        self,
        request: &WsRequest,
        response: WsResponse,
    ) -> std::result::Result<WsResponse, WsErrorResponse> {
        let token = url::form_urlencoded::parse(request.uri().query().unwrap().as_bytes())
            .find(|(name, _)| name == "token")
            .unwrap()
            .1
            .into_owned();
        self.0.send(token).unwrap();
        Ok(response)
    }
}

fn action(sequence: u64, offset_ms: u64, data: &str) -> InputAction {
    InputAction {
        sequence,
        offset_ms,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text(data),
        },
    }
}

#[tokio::test]
async fn completion_feedback_keeps_original_scope_and_request_epoch() {
    for (lazy, disconnect) in [(false, false), (true, false), (false, true), (true, true)] {
        let temp = tempfile::tempdir().unwrap();
        let (mut globals, original) = fixture(temp.path());
        let path = temp.path().join("case/request.json");
        let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let actions = request["interaction"]["actions"].as_array_mut().unwrap();
        actions.push(serde_json::to_value(action(2, 10, "42/chat,0[\"join\",{}]")).unwrap());
        if disconnect {
            actions.push(serde_json::to_value(action(3, 500, "41/chat,")).unwrap());
            actions
                .push(json!({"sequence":4,"offset_ms":600,"action":{"kind":"close","reason":""}}));
            let response_path = temp.path().join("case/expected-response.json");
            let mut response: Value =
                serde_json::from_slice(&std::fs::read(&response_path).unwrap()).unwrap();
            response["interaction"]["end"]["reason"] = "client_close".into();
            std::fs::write(response_path, response.to_string()).unwrap();
            let mut after_disconnect = globals[1].clone();
            after_disconnect["timestamp"] = "2020-01-01T00:10:00.550Z".into();
            after_disconnect["duration_ms"] = 600550.into();
            globals.push(after_disconnect);
        }
        std::fs::write(path, request.to_string()).unwrap();
        let runtime = runtime(temp.path(), &[], &globals, lazy).await.unwrap();
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        let epoch = guards::begin(&runtime).await;
        assert_eq!(
            guards::connected(&runtime, epoch.clone(), "/chat").await["ok"],
            true
        );
        let wrong = serde_json::from_value::<chrono::DateTime<chrono::Utc>>(epoch.clone()).unwrap()
            - chrono::TimeDelta::milliseconds(1);
        for metadata in [
            json!({"epoch":wrong,"acknowledged":2}),
            json!({"epoch":epoch,"acknowledged":99}),
            json!({"epoch":epoch,"acknowledged":2,"namespace":"/chat"}),
        ] {
            assert_eq!(
                guards::control(
                    &runtime,
                    json!({"command":"native_input_ack","case_id":CASE,"native_event":metadata})
                )
                .await["ok"],
                false
            );
        }
        guards::silent(&mut subscriber).await;
        assert_eq!(guards::control(&runtime,json!({"command":"native_input_ack","case_id":CASE,"native_event":{"epoch":epoch,"acknowledged":2}})).await["ok"],true);
        assert_eq!(read(&mut subscriber).await, original);
        guards::silent(&mut subscriber).await;
        if disconnect {
            let state = runtime.state.lock().await;
            assert_eq!(
                state.redis.pubsub.native_clock.timing_evidence(CASE).len(),
                1
            );
        }
        task.abort();
    }
}

#[tokio::test]
async fn active_native_delivery_waits_for_real_ack_and_not_a_future_input() {
    use crate::request_rules::RequestRuleRuntime;
    let temp = tempfile::tempdir().unwrap();
    let (globals, original) = fixture(temp.path());
    let path = temp.path().join("case/request.json");
    let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let recorded = START
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap()
        .timestamp();
    let source_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &json!({"sub":"user","exp":recorded+3600}),
        &jsonwebtoken::EncodingKey::from_secret(b"test-key"),
    )
    .unwrap();
    request["uri"] = format!("/socket.io/?EIO=4&transport=websocket&token={source_token}").into();
    request["headers"] = json!({});
    request["body"] = capture(b"");
    let mut input = InputTranscript::new(Protocol::SocketIo, InteractionPolicy::default());
    input.policy.business_idle_ms = 150;
    input.policy.completion = ["task:join", "later"]
        .into_iter()
        .map(|event| crate::interaction::policy::EventCompletion {
            namespace: "/chat".into(),
            event: event.into(),
            completion: crate::interaction::policy::CompletionRule::Ack,
        })
        .collect();
    input.actions = vec![
        action(1, 0, &format!("40/chat,{}", json!({"token":source_token}))),
        action(2, 10, "42/chat,0[\"task:join\",{}]"),
        action(3, 400, "42/chat,1[\"later\",{}]"),
    ];
    request["interaction"] = serde_json::to_value(input).unwrap();
    std::fs::write(&path, request.to_string()).unwrap();
    let local = temp.path().join(".traffic-e2e/local");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("target.env"), "SECRET_KEY=test-key\n").unwrap();
    let policy = temp.path().join(".traffic-e2e/policy.yaml");
    std::fs::write(
        temp.path().join(".traffic-e2e/project.yaml"),
        "version: 18\nproject:\n  policy: .traffic-e2e/policy.yaml\n",
    )
    .unwrap();
    std::fs::write(&policy,"format: traffic-policy/v3\nsignatures:\n  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: SECRET_KEY}}\napi:\n  GET /socket.io/:\n    request:\n      query: {token: default}\n      socketio_connect:\n        /chat:\n          /token: default\n").unwrap();
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
    let socket_path = temp.path().join("control.sock");
    let session = temp.path().join("session.json");
    std::fs::write(&session, json!({"control_socket":socket_path}).to_string()).unwrap();
    let listener = tokio::net::UnixListener::bind(socket_path).unwrap();
    let state = runtime.state.clone();
    let control = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            crate::replay::control::handle_control_stream(stream, state.clone(), None, None)
                .await
                .unwrap();
        }
    });
    assert_eq!(
        guards::control(&runtime, json!({"command":"request_begin","case_id":CASE})).await["ok"],
        true
    );
    let ws = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = ws.local_addr().unwrap();
    let target_runtime = runtime.clone();
    let target = tokio::spawn(async move {
        let (stream, _) = ws.accept().await.unwrap();
        let (query_tx, query_rx) = tokio::sync::oneshot::channel();
        let mut socket = tokio_tungstenite::accept_hdr_async(stream, QueryToken(query_tx))
            .await
            .unwrap();
        let query = query_rx.await.unwrap();
        assert_ne!(query, source_token);
        socket
            .send(Message::Text(
                "0{\"sid\":\"live\",\"upgrades\":[],\"pingInterval\":10000,\"pingTimeout\":10000}"
                    .into(),
            ))
            .await
            .unwrap();
        let connect_frame = socket.next().await.unwrap().unwrap().into_text().unwrap();
        let data: Value =
            serde_json::from_str(connect_frame.strip_prefix("40/chat,").unwrap()).unwrap();
        assert_eq!(data["token"], query);
        jsonwebtoken::decode::<Value>(
            &query,
            &jsonwebtoken::DecodingKey::from_secret(b"test-key"),
            &jsonwebtoken::Validation::default(),
        )
        .unwrap();
        let (mut subscriber, task) = connect(&target_runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        socket
            .send(Message::Text("40/chat,{\"sid\":\"accepted\"}".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "42/chat,0[\"task:join\",{}]"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(90), read_redis_frame(&mut subscriber))
                .await
                .is_err()
        );
        socket
            .send(Message::Text("43/chat,0[{\"ok\":true}]".into()))
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_millis(200), read(&mut subscriber))
            .await
            .expect("notification must not wait for future input");
        assert_eq!(received, original);
        socket
            .send(Message::Text(
                "42/chat,[\"example:notice\",{\"value\":7}]".into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "42/chat,1[\"later\",{}]"
        );
        socket
            .send(Message::Text("43/chat,1[true]".into()))
            .await
            .unwrap();
        while let Some(message) = socket.next().await {
            if matches!(message.unwrap(), Message::Close(_)) {
                break;
            }
        }
        task.abort();
    });
    let rules = RequestRuleRuntime::load(temp.path(), &policy).unwrap();
    let client = crate::recorded_request::RecordedHttpClient::new(
        format!("http://{address}"),
        Duration::from_secs(3),
        1024 * 1024,
    )
    .with_input_registration(&session, CASE)
    .with_request_rule_runtime(Arc::new(rules));
    let output = client
        .send_bytes(&serde_json::to_vec(&request).unwrap(), "active-native")
        .await
        .unwrap()
        .interaction
        .unwrap();
    assert!(output.end.clean);
    assert!(output.end.pending.is_empty());
    assert!(
        serde_json::to_string(&output)
            .unwrap()
            .contains("example:notice")
    );
    assert!(
        !serde_json::to_string(&output)
            .unwrap()
            .contains("NEVER_EXECUTE_EXPECTED")
    );
    target.await.unwrap();
    control.abort();
}
