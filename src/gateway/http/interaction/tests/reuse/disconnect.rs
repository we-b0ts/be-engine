//! Lost clients retain failed evidence; only confirmed Source teardown can resume.
use super::*;

#[derive(Clone, Copy)]
enum End {
    Eof,
    Reset,
    PartialFrame,
    InvalidFrame,
}

async fn lost_client(address: SocketAddr, end: End) {
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{address}/socket.io/?EIO=4&transport=websocket"
    ))
    .await
    .unwrap();
    assert!(
        socket
            .next()
            .await
            .unwrap()
            .unwrap()
            .to_text()
            .unwrap()
            .starts_with('0')
    );
    socket.send(Message::Text("40".into())).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("40{}".into())
    );
    socket
        .send(Message::Text("421[\"ask\",1]".into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("431[1]".into())
    );
    match end {
        End::Eof => socket.get_mut().shutdown().await.unwrap(),
        End::Reset => {
            let tokio_tungstenite::MaybeTlsStream::Plain(tcp) = socket.get_ref() else {
                panic!("test requires plain TCP")
            };
            crate::dependency::termination::ConnectionControl::new(tcp)
                .unwrap()
                .reset()
                .unwrap();
        }
        End::PartialFrame => {
            socket
                .get_mut()
                .write_all(&[0x81, 0xfe, 0x00])
                .await
                .unwrap();
            socket.get_mut().shutdown().await.unwrap();
        }
        End::InvalidFrame => {
            socket
                .get_mut()
                .write_all(&[0x81, 0x01, b'x'])
                .await
                .unwrap();
            let _ = socket.next().await;
        }
    }
}

async fn recover(end: End, probe: AsgiProbe, lease_loss: bool, persistence_failure: bool) {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), listener.local_addr().unwrap());
    settings.http_gateway.interaction.business_idle_ms = 2_000;
    let state = AppState::new(settings).await.unwrap();
    let (dependency, server, capture, _) = redis_capture(state.clone()).await;
    let source = tokio::spawn(asgi_source(listener, dependency, probe));
    let (address, gateway) = gateway(state.clone()).await;
    let client = tokio::spawn(lost_client(address, end));
    // Retain a real writer across application cleanup and verify publication
    // cannot pass that shared barrier even after the Source SID is removed.
    let writers = loop {
        let writers = state.capture_dependency_targets();
        if !writers.cases.is_empty() {
            break writers;
        }
        tokio::task::yield_now().await;
    };
    let case = writers.cases[0].0.clone();
    if lease_loss {
        assert!(state.invalidate_interaction_reservation(
            Some(case.id),
            crate::recorder::CaseInvalidation::new(
                "interaction_reservation_lost",
                "test lease lost"
            )
        ));
    }
    if persistence_failure {
        tokio::fs::create_dir_all(
            state
                .recorder()
                .case_staging_dir(&case)
                .join("request.json.invalid"),
        )
        .await
        .unwrap();
    }
    client.await.unwrap();
    assert!(
        !state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_millis(75))
            .await
    );
    drop(writers);
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(3))
            .await
    );
    let failed = state.recorder().case_failed_dir(&case);
    let error: Value = serde_json::from_slice(
        &tokio::fs::read(failed.join("recording-error.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let isolated = matches!(end, End::InvalidFrame)
        || !matches!(probe, AsgiProbe::RemovedAfterClose)
        || lease_loss
        || persistence_failure;
    assert_eq!(
        *state.inner.interactions.source_stop.borrow(),
        isolated,
        "{error}"
    );
    assert_eq!(state.inner.active_cases.is_quiescing(), isolated);
    assert!(!state.recorder().case_dir(&case).exists());
    if !isolated {
        assert_eq!(error["reason"], "interaction_client_transport_lost");
        let expected: Value = serde_json::from_slice(
            &tokio::fs::read(failed.join("expected-response.json.invalid"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expected["interaction"]["end"]["clean"], false);
        assert_eq!(expected["interaction"]["end"]["reason"], "transport_error");
        assert!(expected["interaction"]["end"]["close"].is_null());
        let request: Value = serde_json::from_slice(
            &tokio::fs::read(failed.join("request.json.invalid"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            !request["interaction"]["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action["action"]["kind"] == "close")
        );
        let dependencies =
            crate::recorder::test_io::read_to_string(failed.join("dependencies.jsonl"))
                .await
                .unwrap();
        let rows: Vec<Value> = dependencies
            .lines()
            .map(|row| serde_json::from_str::<Value>(row).unwrap())
            .filter(|row| row["event_type"] == "redis_exchange")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(rows[0]["args"][0]["data"].as_str().unwrap())
                .unwrap(),
            b"late-1"
        );
        assert!(!source.is_finished());
        client_interaction(address, Protocol::SocketIo, 2, Some(1001), true).await;
        assert!(
            state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        assert!(!*state.inner.interactions.source_stop.borrow());
        let mut cases = Vec::new();
        find_cases(&state.recorder().run_dir.join("apis"), &mut cases);
        assert_eq!(cases.len(), 1);
        let rows = crate::recorder::test_io::read_to_string(cases[0].join("dependencies.jsonl"))
            .await
            .unwrap();
        let rows: Vec<Value> = rows
            .lines()
            .map(|row| serde_json::from_str::<Value>(row).unwrap())
            .filter(|row| row["event_type"] == "redis_exchange")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(rows[0]["args"][0]["data"].as_str().unwrap())
                .unwrap(),
            b"late-2"
        );
        server.await.unwrap();
        capture.await.unwrap();
    } else {
        server.abort();
        capture.abort();
    }
    source.abort();
    gateway.abort();
}

#[tokio::test]
async fn client_eof_reset_and_partial_frame_archive_failure_then_reuse_source() {
    for end in [End::Eof, End::Reset, End::PartialFrame] {
        timeout(
            Duration::from_secs(8),
            recover(end, AsgiProbe::RemovedAfterClose, false, false),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn invalid_client_frame_or_unproven_application_close_still_isolates_source() {
    for (end, probe) in [
        (End::InvalidFrame, AsgiProbe::RemovedAfterClose),
        (End::Eof, AsgiProbe::MissingFromStart),
        (End::Eof, AsgiProbe::WrongSidAfterClose),
        (End::Eof, AsgiProbe::UnrelatedBadRequestAfterClose),
        (End::Eof, AsgiProbe::StaysLiveAfterClose),
    ] {
        timeout(Duration::from_secs(8), recover(end, probe, false, false))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn disconnected_client_lease_loss_or_persistence_failure_still_isolates_source() {
    for (lease, persistence) in [(true, false), (false, true)] {
        timeout(
            Duration::from_secs(8),
            recover(End::Eof, AsgiProbe::RemovedAfterClose, lease, persistence),
        )
        .await
        .unwrap();
    }
}
