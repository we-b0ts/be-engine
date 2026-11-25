//! Finite response bytes and case publication have independent lifetimes.
use super::*;

#[tokio::test]
async fn finite_response_finishes_after_publication_without_cancellation_and_preserves_trailers() {
    finite_response(false).await;
}

#[tokio::test]
async fn finite_response_eof_keeps_slot_until_case_publication() {
    finite_response(true).await;
}

async fn finite_response(body_first: bool) {
    let temp = tempfile::tempdir().unwrap();
    let state = state(&temp).await;
    let case = case();
    let mut guard = Some(state.try_reserve_active_case(case.clone()).unwrap());
    state
        .activate_case_dependencies(guard.as_ref().unwrap())
        .unwrap();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(state.clone(), inner.local_addr().unwrap()).await;
    let (finish, finished) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = inner.accept().await.unwrap();
        let head = head(&mut stream).await;
        assert!(!head.contains("x-traffic-e2e-"));
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nConnection: close\r\n{}: {}\r\n{}: 1\r\n\r\n5\r\nfirst\r\n", wire::CASE_ID, case.id, wire::FINITE_RESPONSE).as_bytes()).await.unwrap();
        finished.await.unwrap();
        stream
            .write_all(b"6\r\nsecond\r\n0\r\nX-Checksum: complete\r\n\r\n")
            .await
            .unwrap();
    });
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut response = client
        .request(
            Request::builder()
                .uri(format!("http://{}/ordinary", fixture.address))
                .header(hyper::header::TE, "trailers")
                .header(wire::FINITE_RESPONSE, "forged")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.headers().get(wire::CASE_ID).is_none());
    assert!(response.headers().get(wire::FINITE_RESPONSE).is_none());
    assert_eq!(response.headers()[hyper::header::TRAILER], "X-Checksum");
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "first"
    );
    if !body_first {
        drop(guard.take());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), response.body_mut().frame())
                .await
                .is_err(),
            "publication must not manufacture response EOF"
        );
        assert_eq!(
            fixture.relay.slot.available_permits(),
            0,
            "response lifetime still owns its slot"
        );
    }
    finish.send(()).unwrap();
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(body.trailers().unwrap()["x-checksum"], "complete");
    assert_eq!(body.to_bytes(), "second");
    if body_first {
        assert_eq!(
            fixture.relay.slot.available_permits(),
            0,
            "case publication still owns its slot"
        );
        drop(guard.take());
    }
    tokio::time::timeout(BOUND, fixture.relay.drain())
        .await
        .unwrap();
    assert!(fixture.relay.ready.load(Ordering::SeqCst));
    assert_eq!(state.recording_lifecycle_phase(), "running");
    upstream.await.unwrap();
}

#[tokio::test]
async fn stalled_finite_delivery_uses_original_deadline_and_keeps_case_tail_owned() {
    for publication_first in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let state = state(&temp).await;
        let case = case();
        let case_id = case.id;
        let mut guard = Some(state.try_reserve_active_case(case.clone()).unwrap());
        state
            .activate_case_dependencies(guard.as_ref().unwrap())
            .unwrap();
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = inner.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = inner.accept().await.unwrap();
            head(&mut socket).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n{}: {}\r\n{}: 1\r\n\r\n",
                        wire::CASE_ID,
                        case.id,
                        wire::FINITE_RESPONSE
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{address}/ordinary"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let relay = Relay::<RedisService>::new(
            None,
            format!("http://{address}").parse().unwrap(),
            None,
            BOUND,
            1024,
        )
        .with_interactions(state.clone(), format!("http://{address}").parse().unwrap());
        relay.open();
        let permit = relay.slot.clone().try_acquire_owned().unwrap();
        tokio::time::pause();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        // Response headers used most of the original request budget.
        tokio::time::advance(Duration::from_millis(80)).await;
        let response = relay.adopt_interaction_response(response, permit, None, None, deadline);
        if publication_first {
            drop(guard.take());
        }
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(21)).await;
        tokio::task::yield_now().await;
        if !publication_first {
            assert_eq!(
                relay.slot.available_permits(),
                0,
                "delivery timeout cannot release a live Source/case tail"
            );
            assert!(state.inner.active_cases.has_case(case_id));
            drop(guard.take());
        }
        tokio::time::timeout(Duration::from_millis(100), relay.drain())
            .await
            .expect("stalled delivery retained the slot past its original request deadline");
        assert!(
            response.into_body().collect().await.is_err(),
            "delivery timeout must not manufacture successful HTTP body EOF"
        );
        assert!(relay.ready.load(Ordering::SeqCst));
        assert_eq!(state.recording_lifecycle_phase(), "running");
        tokio::time::resume();
        upstream.abort();
    }
}
