//! Closing fresh admission must preserve an existing polling session.

use super::*;

#[tokio::test]
async fn closed_admission_rejects_fresh_sessions_and_allows_owned_polling_followups() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(&temp).await;
    let case = case();
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(state.clone(), inner.local_addr().unwrap()).await;
    let upstream = tokio::spawn(async move {
        for path in [
            "/socket.io/?EIO=4&transport=polling",
            "/socket.io/?EIO=4&transport=polling&sid=session",
        ] {
            let (mut stream, _) = inner.accept().await.unwrap();
            assert!(
                head(&mut stream)
                    .await
                    .starts_with(&format!("GET {path} HTTP/1.1"))
            );
            stream.write_all(format!("HTTP/1.1 200 OK\r\nx-traffic-e2e-case-id: {}\r\nx-traffic-e2e-session-id: session\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", case.id).as_bytes()).await.unwrap();
        }
    });
    fixture
        .request("/socket.io/?EIO=4&transport=polling", None)
        .await
        .into_body()
        .collect()
        .await
        .unwrap();
    fixture.relay.close();
    state.inner.active_cases.close_admission();
    for path in [
        "/socket.io/?EIO=4&transport=polling",
        "/socket.io/?EIO=4&transport=polling&sid=unknown",
    ] {
        assert_eq!(
            fixture.request(path, None).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let followup = fixture
        .request("/socket.io/?EIO=4&transport=polling&sid=session", None)
        .await;
    assert_eq!(followup.status(), StatusCode::OK);
    assert_eq!(
        followup.into_body().collect().await.unwrap().to_bytes(),
        "ok"
    );
    assert!(!state.inner.active_cases.is_quiescing());
    drop(guard);
    tokio::time::timeout(BOUND, fixture.relay.drain())
        .await
        .unwrap();
    upstream.await.unwrap();
}
