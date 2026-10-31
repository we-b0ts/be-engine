//! Raw client termination caps input delivery before later Source cleanup ends.
use super::*;
use crate::interaction::model::{ClientTransportEnd, SocketIoHeartbeats};

#[tokio::test]
async fn clean_client_transport_end_keeps_its_original_native_input_window() {
    for end in [ClientTransportEnd::Eof, ClientTransportEnd::Reset] {
        let temp = tempfile::tempdir().unwrap();
        let (mut globals, original) = fixture(temp.path());
        let path = temp.path().join("case/request.json");
        let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut input: InputTranscript =
            serde_json::from_value(request["interaction"].clone()).unwrap();
        input.socket_io_heartbeat = Some(SocketIoHeartbeats::default());
        input.actions.push(InputAction {
            sequence: 2,
            offset_ms: 70,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::TransportEnd { end },
        });
        request["interaction"] = serde_json::to_value(input).unwrap();
        std::fs::write(&path, request.to_string()).unwrap();
        let path = temp.path().join("case/expected-response.json");
        let mut response: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        response["interaction"]["end"]["reason"] = "client_transport_end".into();
        std::fs::write(path, response.to_string()).unwrap();
        let mut after_end = globals[1].clone();
        after_end["timestamp"] = "2020-01-01T00:10:00.100Z".into();
        after_end["duration_ms"] = 600100.into();
        globals.push(after_end);
        let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        let epoch = guards::begin(&runtime).await;
        assert_eq!(
            guards::connected(&runtime, epoch, "/chat").await["ok"],
            true
        );
        assert_eq!(read(&mut subscriber).await, original);
        tokio::time::sleep(Duration::from_millis(100)).await;
        guards::silent(&mut subscriber).await;
        let state = runtime.state.lock().await;
        let report = state.redis.pubsub.report().unwrap();
        assert_eq!(report.recorded_pushes, 2);
        assert_eq!(report.delivered_pushes, 1);
        assert_eq!(report.failed_pushes, 0);
        task.abort();
    }
}
