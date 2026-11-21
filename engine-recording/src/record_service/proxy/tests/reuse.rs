//! Reuse one ingress and Source epoch across independently admitted sessions.

use super::*;

#[tokio::test]
async fn sequential_cases_reclaim_the_slot_without_reusing_an_old_sid_or_stopping_source() {
    tokio::time::timeout(BOUND, exercise()).await.unwrap();
}

async fn exercise() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(&temp).await;
    let first_case = case();
    let second_case = case();
    let first_guard = state.try_reserve_active_case(first_case.clone()).unwrap();
    state.activate_case_dependencies(&first_guard).unwrap();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(state.clone(), inner.local_addr().unwrap()).await;
    let upstream = tokio::spawn(async move {
        let fresh = "/socket.io/?EIO=4&transport=polling";
        let old = "/socket.io/?EIO=4&transport=polling&sid=first-sid";
        let current = "/socket.io/?EIO=4&transport=polling&sid=second-sid";
        for (path, status, owner, sid, payload) in [
            (
                fresh,
                "200 OK",
                Some(first_case.id),
                Some("first-sid"),
                "first",
            ),
            (old, "400 Bad Request", None, None, "unknown"),
            (
                fresh,
                "200 OK",
                Some(second_case.id),
                Some("second-sid"),
                "second",
            ),
            (old, "400 Bad Request", None, None, "unknown"),
            (current, "200 OK", Some(second_case.id), None, "follow-up"),
        ] {
            let (mut stream, _) = inner.accept().await.unwrap();
            let request = head(&mut stream).await;
            assert!(request.starts_with(&format!("GET {path} HTTP/1.1")));
            let mut headers = String::new();
            if let Some(owner) = owner {
                headers.push_str(&format!("x-traffic-e2e-case-id: {owner}\r\n"));
            }
            if let Some(sid) = sid {
                headers.push_str(&format!("x-traffic-e2e-session-id: {sid}\r\n"));
            }
            stream
                .write_all(
                    format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len())
                        .as_bytes(),
                )
                .await
                .unwrap();
        }
    });

    let fresh = "/socket.io/?EIO=4&transport=polling";
    let old = "/socket.io/?EIO=4&transport=polling&sid=first-sid";
    let current = "/socket.io/?EIO=4&transport=polling&sid=second-sid";
    let first = fixture.request(fresh, None).await;
    assert_eq!(first.status(), StatusCode::OK);
    assert!(first.headers().get(wire::CASE_ID).is_none());
    assert_eq!(
        first.into_body().collect().await.unwrap().to_bytes(),
        "first"
    );
    assert_eq!(fixture.relay.slot.available_permits(), 0);

    drop(first_guard);
    fixture.relay.drain().await;
    assert_eq!(fixture.relay.slot.available_permits(), 1);
    assert!(fixture.relay.ready.load(Ordering::SeqCst));
    assert_eq!(
        fixture.request(old, None).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(fixture.relay.slot.available_permits(), 1);

    let second_guard = state.try_reserve_active_case(second_case).unwrap();
    state.activate_case_dependencies(&second_guard).unwrap();
    let second = fixture.request(fresh, None).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert!(second.headers().get(wire::SESSION_ID).is_none());
    assert_eq!(
        second.into_body().collect().await.unwrap().to_bytes(),
        "second"
    );
    assert_eq!(fixture.relay.slot.available_permits(), 0);
    assert_eq!(
        fixture.request(old, None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let follow_up = fixture.request(current, None).await;
    assert_eq!(follow_up.status(), StatusCode::OK);
    assert_eq!(
        follow_up.into_body().collect().await.unwrap().to_bytes(),
        "follow-up"
    );
    assert_eq!(fixture.relay.slot.available_permits(), 0);

    drop(second_guard);
    fixture.relay.drain().await;
    assert_eq!(fixture.relay.slot.available_permits(), 1);
    assert!(fixture.relay.ready.load(Ordering::SeqCst));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            state.wait_for_interaction_source_stop(),
        )
        .await
        .is_err()
    );
    upstream.await.unwrap();
}
