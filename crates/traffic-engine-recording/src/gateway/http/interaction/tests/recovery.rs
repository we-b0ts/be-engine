//! Case-local stream failures retain their evidence without ending a healthy Source.

use super::*;
use crate::recorder::{CaseInvalidation, CaseInvalidationContext};

async fn read_head(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
    }
    head
}

#[tokio::test]
async fn failed_dependency_capture_drains_then_accepts_next_http_case() {
    timeout(Duration::from_secs(5), recover(Failure::Capture))
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_dependency_capture_with_lease_loss_still_requests_source_stop() {
    timeout(Duration::from_secs(5), recover(Failure::LeaseLoss))
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_dependency_capture_with_persistence_failure_still_requests_source_stop() {
    timeout(Duration::from_secs(5), recover(Failure::Persistence))
        .await
        .unwrap();
}

enum Failure {
    Capture,
    LeaseLoss,
    Persistence,
}

async fn recover(failure: Failure) {
    let lease_loss = matches!(failure, Failure::LeaseLoss);
    let persistence_failure = matches!(failure, Failure::Persistence);
    let temp = tempdir().unwrap();
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), source.local_addr().unwrap());
    settings.recording.case_dependency_post_response_window_ms = 0;
    let state = AppState::new(settings).await.unwrap();
    let source = tokio::spawn(async move {
        loop {
            let (mut socket, _) = source.accept().await.unwrap();
            let head = read_head(&mut socket).await;
            if String::from_utf8_lossy(&head).contains("/next") {
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nc\r\ndata: next\n\n\r\n0\r\n\r\n").await.unwrap();
            } else {
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nd\r\ndata: first\n\n\r\n").await.unwrap();
                let _ = socket.read_to_end(&mut Vec::new()).await;
            }
        }
    });
    let (address, gateway) = gateway(state.clone()).await;
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"POST /events HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    read_head(&mut client).await;
    client.read_exact(&mut [0; 18]).await.unwrap();
    let writers = state.capture_dependency_targets();
    let case = writers.cases[0].0.clone();
    if persistence_failure {
        // A directory at the exact evidence filename forces a real write error.
        tokio::fs::create_dir_all(
            state
                .recorder()
                .case_staging_dir(&case)
                .join("request.json.invalid"),
        )
        .await
        .unwrap();
    }
    state.invalidate_active_case(
        case.id,
        CaseInvalidation::new(
            "http_stream_capture_incomplete",
            "dependency dropped without observed cancellation",
        )
        .allow_drained_case_recovery()
        .with_context(CaseInvalidationContext {
            category: "http_stream_capture".into(),
            elapsed_ms: 1,
            recorder_phase: "recording".into(),
            native: std::collections::BTreeMap::from([(
                "http_stream".into(),
                serde_json::json!({"client": {"engine_stopped": false}}),
            )]),
        }),
    );
    if lease_loss {
        assert!(state.invalidate_interaction_reservation(
            Some(case.id),
            CaseInvalidation::new(
                "interaction_reservation_lost",
                "lease lost before publication"
            )
        ));
    }
    crate::dependency::termination::ConnectionControl::new(&client)
        .unwrap()
        .reset()
        .unwrap();
    assert!(
        !state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_millis(70))
            .await,
        "publication must retain ownership until its evidence writers drain"
    );
    drop(writers);
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(2))
            .await
    );
    let failed = state.recorder().case_failed_dir(&case);
    let error: Value = serde_json::from_slice(
        &tokio::fs::read(failed.join("recording-error.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        error["reason"],
        if persistence_failure {
            "interaction_finalization_failed"
        } else if lease_loss {
            "interaction_reservation_lost"
        } else {
            "http_stream_capture_incomplete"
        }
    );
    assert_eq!(
        failed.join("expected-response.json.invalid").exists(),
        !persistence_failure
    );
    assert!(!state.recorder().case_dir(&case).exists());
    if lease_loss || persistence_failure {
        assert!(*state.inner.interactions.source_stop.borrow());
        assert!(state.inner.active_cases.is_quiescing());
    } else {
        assert!(!*state.inner.interactions.source_stop.borrow());
        assert!(!state.inner.active_cases.is_quiescing());
        let mut next = tokio::net::TcpStream::connect(address).await.unwrap();
        next.write_all(b"GET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        next.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).contains("data: next"));
        let next_case = published(&state).await;
        let expected: Value = serde_json::from_slice(
            &tokio::fs::read(next_case.join("expected-response.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expected["interaction"]["end"]["clean"], true);
        assert!(!source.is_finished());
    }
    source.abort();
    gateway.abort();
}
