use super::*;
use crate::replay::redis::activity::tests::{create, document, events, now_string};
use crate::replay::redis::append::tests::request;
use crate::replay::{ReplayExchangeStatus, ReplayRuntime};

async fn runtime() -> (tempfile::TempDir, ReplayRuntime, Vec<u8>) {
    let (root, runtime) = super::tests::runtime_with_source(&events(), document(true)).await;
    let current = create(&mut runtime.state.lock().await.redis);
    (root, runtime, current)
}

fn target() -> TargetKey {
    TargetKey {
        host: "redis.test".into(),
        port: 6379,
    }
}

fn refresh(current: &[u8]) -> RedisCommand {
    let mut next: serde_json::Value = serde_json::from_slice(current).unwrap();
    next["last_activity_at"] = serde_json::json!(now_string());
    let next = serde_json::to_vec(&next).unwrap();
    redis_command(&bytes::Bytes::from(crate::redis::encode_array(&[
        b"SET",
        b"activity:1",
        &next,
        b"EX",
        b"3600",
    ])))
    .unwrap()
}

#[tokio::test]
async fn activity_set_waits_for_get_delivery_bookkeeping_without_reobserving() {
    let (_root, runtime, current) = runtime().await;
    let read = request(
        &mut runtime.state.lock().await.redis,
        "GET",
        &[b"activity:1"],
    )
    .unwrap();
    let target = target();
    let command = refresh(&current);
    let mut binding = CaseConnectionBinding::default();
    let refresh = match_command(
        &runtime.state,
        &target,
        Uuid::new_v4(),
        &mut binding,
        2,
        0,
        None,
        &command,
    );
    tokio::pin!(refresh);
    tokio::select! {
        biased;
        result = &mut refresh => panic!("SET must await the admitted GET: {result:?}"),
        _ = std::future::ready(()) => {},
    }
    let (event, clock, observation);
    {
        let mut state = runtime.state.lock().await;
        event = state.redis.request_event_index;
        clock = state.redis.request_observed_at;
        observation = state.redis.request_observation_id;
        assert!(state.redis.events.unmatched.is_empty());
        assert_eq!(
            state.redis.exchanges[3].status,
            ReplayExchangeStatus::Available
        );
        // Another connection advances the request clock and index while SET waits.
        let append = request(&mut state.redis, "APPEND", &[b"content:1", b"abcd"]).unwrap();
        state.redis.complete_exchange(&append);
        state.redis.complete_exchange(&read);
    }
    let matched = tokio::time::timeout(Duration::from_secs(1), refresh)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(matched.report.target_event_index, event);
    let mut state = runtime.state.lock().await;
    assert_eq!(state.redis.request_observed_at, clock);
    assert_eq!(state.redis.request_observation_id, observation);
    state.redis.complete_exchange(&matched);
    let deletion = request(&mut state.redis, "DEL", &[b"activity:1"]).unwrap();
    state.redis.complete_exchange(&deletion);
    let content = request(&mut state.redis, "GET", &[b"content:1"]).unwrap();
    state.redis.complete_exchange(&content);
    assert!(state.redis.snapshot().unused_case.is_empty());
    assert!(!state.redis.snapshot().is_dirty());
}

#[tokio::test]
async fn activity_set_rejects_a_failed_get_or_changed_case() {
    for change_case in [false, true] {
        let (_root, runtime, current) = runtime().await;
        let read = request(
            &mut runtime.state.lock().await.redis,
            "GET",
            &[b"activity:1"],
        )
        .unwrap();
        let target = target();
        let command = refresh(&current);
        let mut binding = CaseConnectionBinding::default();
        let refresh = match_command(
            &runtime.state,
            &target,
            Uuid::new_v4(),
            &mut binding,
            2,
            0,
            None,
            &command,
        );
        tokio::pin!(refresh);
        tokio::select! {
            biased;
            result = &mut refresh => panic!("SET must await GET: {result:?}"),
            _ = std::future::ready(()) => {},
        }
        {
            let mut state = runtime.state.lock().await;
            if change_case {
                state.active_case_id = Some("new-case".into());
                state.redis.complete_exchange(&read);
            } else {
                state
                    .redis
                    .fail_exchange(&read, "synthetic failed GET delivery".into());
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(1), refresh)
                .await
                .unwrap()
                .is_err()
        );
        let state = runtime.state.lock().await;
        assert_eq!(state.redis.events.unmatched.len(), 1);
        assert_eq!(
            state.redis.events.unmatched[0].case_id.as_deref(),
            Some("case")
        );
        assert_eq!(
            state.redis.exchanges[3].status,
            ReplayExchangeStatus::Available
        );
    }
}

#[tokio::test]
async fn activity_set_without_an_admitted_get_is_rejected_immediately() {
    let (_root, runtime, current) = runtime().await;
    let mut binding = CaseConnectionBinding::default();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            match_command(
                &runtime.state,
                &target(),
                Uuid::new_v4(),
                &mut binding,
                2,
                0,
                None,
                &refresh(&current),
            )
        )
        .await
        .unwrap()
        .is_err()
    );
    let state = runtime.state.lock().await;
    assert_eq!(state.redis.events.unmatched.len(), 1);
    assert_eq!(
        state.redis.exchanges[2].status,
        ReplayExchangeStatus::Available
    );
}

#[tokio::test]
async fn activity_set_cannot_borrow_a_future_get_while_it_waits() {
    let (_root, runtime, current) = runtime().await;
    let read = request(
        &mut runtime.state.lock().await.redis,
        "GET",
        &[b"activity:1"],
    )
    .unwrap();
    let target = target();
    let command = refresh(&current);
    let mut binding = CaseConnectionBinding::default();
    let waiting = match_command(
        &runtime.state,
        &target,
        Uuid::new_v4(),
        &mut binding,
        2,
        0,
        None,
        &command,
    );
    tokio::pin!(waiting);
    tokio::select! {
        biased;
        result = &mut waiting => panic!("SET must await GET: {result:?}"),
        _ = std::future::ready(()) => {},
    }
    {
        let mut state = runtime.state.lock().await;
        state.redis.complete_exchange(&read);
        // A concurrent SET consumes that read credit before this waiter resumes.
        let other = request(
            &mut state.redis,
            "SET",
            &command.args.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
        .unwrap();
        state.redis.complete_exchange(&other);
        // This later GET is pending, but did not precede the waiting SET.
        request(&mut state.redis, "GET", &[b"activity:1"]).unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(runtime.state.lock().await.redis.events.unmatched.len(), 1);
}
