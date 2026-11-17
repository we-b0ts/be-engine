use super::*;

#[test]
fn idle_socketio_tail_gets_the_full_initial_window() {
    let closed = Instant::now();
    let check = |seconds| {
        decision(
            closed,
            closed + Duration::from_secs(seconds),
            0,
            closed - Duration::from_secs(1),
            INITIAL_QUIET,
            ACTIVE_QUIET,
        )
    };
    assert_eq!(check(14), TailDecision::Wait(closed + INITIAL_QUIET));
    assert_eq!(check(15), TailDecision::Quiet);
}

#[test]
fn socketio_tail_uses_rolling_silence_but_never_extends_the_limit() {
    let closed = Instant::now();
    let check = |now, in_flight, last| {
        decision(
            closed,
            closed + Duration::from_secs(now),
            in_flight,
            closed + Duration::from_secs(last),
            INITIAL_QUIET,
            ACTIVE_QUIET,
        )
    };
    assert_eq!(
        check(1, 1, 0),
        TailDecision::Wait(closed + SOCKETIO_CLOSE_LIMIT)
    );
    assert_eq!(
        check(15, 0, 14),
        TailDecision::Wait(closed + Duration::from_secs(74))
    );
    assert_eq!(check(74, 0, 14), TailDecision::Quiet);
    assert_eq!(
        check(74, 0, 72),
        TailDecision::Wait(closed + Duration::from_secs(132))
    );
    assert_eq!(
        check(299, 0, 275),
        TailDecision::Wait(closed + SOCKETIO_CLOSE_LIMIT)
    );
    assert_eq!(check(300, 0, 275), TailDecision::Limit);
    assert_eq!(check(300, 1, 299), TailDecision::Limit);
}

#[tokio::test]
async fn socketio_tail_limit_freezes_shutdown_owner_and_retains_admitted_io() {
    let registry = ActiveCaseRegistry::default();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "socketio".into(),
        uri_group: None,
    };
    let guard = registry.try_reserve(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    let request = registry.current_targets_for_http_request(true);
    assert_eq!(request.cases[0].0.id, case.id);
    let observer = {
        let registry = registry.clone();
        let closed = Instant::now() - SOCKETIO_CLOSE_LIMIT;
        tokio::spawn(async move { registry.observe_socketio_close_tail(case.id, closed).await })
    };
    tokio::time::timeout(Duration::from_secs(1), registry.wait_for_quiescing())
        .await
        .unwrap();
    assert_eq!(registry.socketio_close_limit_case(), Some(case.id));
    let shutdown = registry.current_targets_for_event();
    assert!(shutdown.cases.is_empty());
    assert_eq!(shutdown.shutdown_case_id, Some(case.id));
    assert_eq!(
        registry.invalidation_for(case.id).unwrap().reason,
        SOCKETIO_CLOSE_TAIL_TIMEOUT
    );
    assert!(!observer.is_finished());
    drop(request);
    observer.await.unwrap();
}
