use super::*;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket};

#[tokio::test]
async fn pending_real_connect_is_cancelled_by_source_stop_without_inventing_upstream_failure() {
    use std::future::Future as _;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("key.pem");
    config.async_api.insert(
        "POST /jobs".into(),
        serde_json::from_value(serde_json::json!({
            "when":{"/background":true},"end":[{"redis":{"operation":"DEL","key":"done:*"}}]
        }))
        .unwrap(),
    );
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: uuid::Uuid::new_v4(),
        rule_name: "jobs".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (peer, client) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let mut peer = peer.unwrap();
    let client = client.unwrap().0;
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let blocked = socket.listen(1).unwrap();
    let address = blocked.local_addr().unwrap();
    // Linux permits backlog + 1 completed connections. Keep both unaccepted,
    // so a third real SYN remains pending without a timing-dependent firewall.
    let _first = TcpStream::connect(address).await.unwrap();
    let _second = TcpStream::connect(address).await.unwrap();
    state.configure_case_observation(
        case.id,
        &hyper::Method::POST,
        &"/jobs".parse().unwrap(),
        br#"{"background":true}"#,
        Instant::now(),
        Duration::from_millis(20),
    );
    guard.activate_dependencies().unwrap();
    let connecting = connect_upstream(
        &state,
        &client,
        "mysql",
        ("mysql.test", address.port()),
        address,
    );
    tokio::pin!(connecting);
    // Poll the real attempt into its I/O wait before starting the Case drain.
    // This establishes actual admission without racing a short wall-clock sleep.
    std::future::poll_fn(|context| {
        assert!(connecting.as_mut().poll(context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    state.begin_case_quiescing();
    let (result, invalidation) = tokio::join!(
        connecting.as_mut(),
        state.drain_active_case_dependencies(case.id)
    );
    assert!(result.unwrap().is_none());
    assert_eq!(invalidation, None);
    let observed = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(observed.kind(), io::ErrorKind::ConnectionReset);
    let report = state
        .inner
        .active_cases
        .async_api_report(case.id)
        .unwrap()
        .1;
    assert_eq!(report["end_reason"], "stopped");
    assert_eq!(report["source_stop_required"], true);
    assert!(report["source_stop_after_ms"].as_u64().is_some());
    assert_eq!(report["completed_refs"].as_array().unwrap().len(), 1);
    assert_eq!(report["cleanup_refs"], report["completed_refs"]);
    assert!(
        state
            .recorder()
            .case_dependency_safety_issue(&case)
            .await
            .unwrap()
            .is_none()
    );
    let raw = crate::recorder::test_io::read_to_string(
        state
            .recorder()
            .case_staging_dir(&case)
            .join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let event: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
    assert_eq!(event["failure_kind"], "engine_cancelled");
    assert_eq!(event["protocol"], "mysql");
}

#[tokio::test]
async fn refused_upstream_is_a_complete_async_dependency_with_a_real_client_reset() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("key.pem");
    config.async_api.insert(
        "POST /jobs".into(),
        serde_json::from_value(serde_json::json!({
            "when":{"/background":true},"end":[{"redis":{"operation":"DEL","key":"done:*"}}]
        }))
        .unwrap(),
    );
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: uuid::Uuid::new_v4(),
        rule_name: "jobs".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.configure_case_observation(
        case.id,
        &hyper::Method::POST,
        &"/jobs".parse().unwrap(),
        br#"{"background":true}"#,
        Instant::now(),
        Duration::from_secs(1),
    );
    guard.activate_dependencies().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (peer, client) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let mut peer = peer.unwrap();
    let client = client.unwrap().0;
    // A bound non-listening socket guarantees refusal without a free-port race.
    let refusing = TcpSocket::new_v4().unwrap();
    refusing.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let started = Instant::now();
    let error = TcpStream::connect(refusing.local_addr().unwrap())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    record_connect_failure(
        &state,
        &client,
        state.capture_dependency_targets(),
        "redis",
        ("redis.test", refusing.local_addr().unwrap().port()),
        started,
        &error,
    )
    .unwrap();
    let observed = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(observed.kind(), io::ErrorKind::ConnectionReset);
    state.begin_case_quiescing();
    assert_eq!(state.drain_active_case_dependencies(case.id).await, None);
    let report = state
        .inner
        .active_cases
        .async_api_report(case.id)
        .unwrap()
        .1;
    assert_eq!(report["end_reason"], "stopped");
    assert_eq!(report["capture_complete"], true);
    assert_eq!(report["business_complete"], false);
    assert_eq!(report["business_completion"], "unobserved");
    assert_eq!(report["inventory_complete"], true);
    assert_eq!(report["completed_refs"][0]["protocol"], "connect");
    assert!(
        state
            .recorder()
            .case_dependency_safety_issue(&case)
            .await
            .unwrap()
            .is_none()
    );
    let raw = crate::recorder::test_io::read_to_string(
        state
            .recorder()
            .case_staging_dir(&case)
            .join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let events = raw
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let event = &events[0];
    assert_eq!(event["event_type"], "dependency_connect_failure");
    assert_eq!(event["protocol"], "redis");
    assert_eq!(event["failure_kind"], "connection_refused");
    assert_eq!(event["client_outcome"], "reset");
    assert_eq!(report["completed_refs"][0]["event_id"], event["id"]);
    assert!(state.inner.active_cases.is_quiescing());
}
