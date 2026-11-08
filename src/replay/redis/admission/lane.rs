//! A pooled Socket.IO producer can reach an exact Redis lane slot first.
use super::*;
use crate::replay::{
    ReplayStreamTiming, command_matching::CommandExchangeScope,
    report::command::CommandExchangeRefReport,
};

pub(super) fn enabled(state: &ReplayState) -> bool {
    state.input_timing.is_some() && state.stream_timing == Some(ReplayStreamTiming::Fast)
}

pub(super) fn pending_predecessor(
    state: &RedisReplayState,
    case: Option<&str>,
    diagnostic: &CommandMatchDiagnostic,
) -> bool {
    let Some(case) = case else {
        return false;
    };
    let CommandMatchDiagnostic::LaneBlocked {
        candidate,
        blocked_by,
    } = diagnostic
    else {
        return false;
    };
    if !matches!(
        (candidate.command.as_str(), blocked_by.command.as_str()),
        ("PUBLISH", "GET" | "PUBLISH") | ("GET", "PUBLISH")
    ) || candidate.source != ReplaySource::Case
        || blocked_by.source != ReplaySource::Case
        || candidate.case_id.as_deref() != Some(case)
        || blocked_by.case_id.as_deref() != Some(case)
        || candidate.connection_id != blocked_by.connection_id
        || candidate.sequence <= blocked_by.sequence
    {
        return false;
    }
    let Some(candidate) = ordinary_slot(state, case, candidate) else {
        return false;
    };
    let Some(blocker) = ordinary_slot(state, case, blocked_by) else {
        return false;
    };
    state.exchanges[candidate].status.is_available()
        && state.exchanges[blocker].status.is_available()
        && !state.exchanges[blocker].satisfies_lane_order()
}

pub(super) fn ordinary_slot(
    state: &RedisReplayState,
    case: &str,
    reference: &CommandExchangeRefReport,
) -> Option<usize> {
    let index =
        state
            .candidates
            .case_lane_slot(case, reference.connection_id, reference.sequence)?;
    let exchange = &state.exchanges[index];
    (exchange.record.command == reference.command
        && exchange.record.replay_safe
        && exchange.record.parse_warnings.is_empty()
        && exchange.record.outcome == crate::DependencyExchangeOutcome::Response
        && exchange.preserves_connection_order()
        && exchange.shared_rule_id.is_none()
        && !exchange.reusable_snapshot
        && !exchange.subscription_alias)
        .then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interaction::model::{InputTranscript, Protocol};
    use crate::replay::redis::append::tests::event;
    use serde_json::json;

    #[tokio::test]
    async fn only_a_zero_subscriber_publish_can_pass_a_proven_state_deletion_in_fast_replay() {
        for (fast, count, observe) in [
            (true, 0, true),
            (false, 0, true),
            (true, 1, true),
            (true, 0, false),
        ] {
            let publish_reply = format!(":{count}\r\n");
            let policy = if observe {
                json!({"format":"traffic-policy/v3","redis":{"keys":{"device:online":{"state":{"get":"observe"}}}}})
            } else {
                json!({"format":"traffic-policy/v3","rules":[]})
            };
            let (_root, runtime) = super::super::tests::runtime_with_request(
                &[
                    event(1, "SET", &[b"device:online", b"up"], b"+OK\r\n"),
                    event(2, "GET", &[b"device:online"], b"$2\r\nup\r\n"),
                    event(3, "DEL", &[b"device:online"], b":1\r\n"),
                    event(4, "PUBLISH", &[b"live", b"event"], publish_reply.as_bytes()),
                ],
                policy,
                json!({"method":"GET","uri":"/socket.io/","timestamp":"2020-01-01T00:00:00Z",
                    "interaction":InputTranscript::new(Protocol::SocketIo, Default::default())}),
                crate::replay::ReplayLifecycleConfig {
                    stream_timing: fast.then_some(ReplayStreamTiming::Fast),
                    ..Default::default()
                },
            )
            .await;
            let (begin, _) = crate::replay::control::handle_control_request(
                serde_json::from_value(json!({"command":"input_timing_begin","case_id":"case"}))
                    .unwrap(),
                runtime.state.clone(),
                None,
                None,
            )
            .await;
            assert_eq!(begin["ok"], true, "{begin}");
            let target = TargetKey {
                host: "redis.test".into(),
                port: 6379,
            };
            let client = Uuid::new_v4();
            let mut binding = CaseConnectionBinding::default();
            let set = RedisCommand {
                name: "SET".into(),
                args: vec![b"device:online".to_vec(), b"up".to_vec()],
            };
            let get = RedisCommand {
                name: "GET".into(),
                args: vec![b"device:online".to_vec()],
            };
            let publish = RedisCommand {
                name: "PUBLISH".into(),
                args: vec![b"live".to_vec(), b"event".to_vec()],
            };
            let delete = RedisCommand {
                name: "DEL".into(),
                args: vec![b"device:online".to_vec()],
            };
            for request in [&set, &get] {
                let matched = match_command(
                    &runtime.state,
                    &target,
                    client,
                    &mut binding,
                    2,
                    0,
                    None,
                    request,
                )
                .await
                .unwrap();
                runtime.state.lock().await.redis.complete_exchange(&matched);
            }
            let early = match_command(
                &runtime.state,
                &target,
                client,
                &mut binding,
                2,
                0,
                None,
                &publish,
            )
            .await;
            if fast && count == 0 && observe {
                let published = early.unwrap();
                assert_eq!(published.report.sequence, 4);
                {
                    let mut state = runtime.state.lock().await;
                    state.redis.complete_exchange(&published);
                    assert_eq!(state.redis.snapshot().unused_case[0].command, "DEL");
                }
                let removed = match_command(
                    &runtime.state,
                    &target,
                    client,
                    &mut binding,
                    2,
                    0,
                    None,
                    &delete,
                )
                .await
                .unwrap();
                let mut state = runtime.state.lock().await;
                state.redis.complete_exchange(&removed);
                assert!(!state.redis.snapshot().is_dirty());
            } else {
                assert!(early.is_err());
                let state = runtime.state.lock().await;
                assert!(matches!(state.redis.events.unmatched[0].diagnostic,
                    Some(CommandMatchDiagnostic::LaneBlocked { ref blocked_by, .. }) if blocked_by.sequence == 3));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn earlier_pooled_publish_waits_for_the_exact_case_lane_slot() {
        for send_predecessor in [true, false] {
            let (_root, runtime) = super::super::tests::runtime_with_request(
                &[
                    event(1, "GET", &[b"device"], b"$1\r\nx\r\n"),
                    event(2, "PUBLISH", &[b"live", b"update"], b":1\r\n"),
                ],
                json!({"format":"traffic-policy/v3","rules":[]}),
                json!({
                    "method":"GET","uri":"/socket.io/",
                    "timestamp":"2020-01-01T00:00:00Z",
                    "interaction":InputTranscript::new(Protocol::SocketIo, Default::default())
                }),
                crate::replay::ReplayLifecycleConfig {
                    stream_timing: Some(ReplayStreamTiming::Fast),
                    ..Default::default()
                },
            )
            .await;
            let (begin, _) = crate::replay::control::handle_control_request(
                serde_json::from_value(json!({"command":"input_timing_begin","case_id":"case"}))
                    .unwrap(),
                runtime.state.clone(),
                None,
                None,
            )
            .await;
            assert_eq!(begin["ok"], true, "{begin}");

            let target = TargetKey {
                host: "redis.test".into(),
                port: 6379,
            };
            let publish = redis_command(&bytes::Bytes::from(crate::redis::encode_array(&[
                b"PUBLISH", b"live", b"update",
            ])))
            .unwrap();
            let mut first = CaseConnectionBinding::default();
            let mut second = CaseConnectionBinding::default();
            let pending = match_command(
                &runtime.state,
                &target,
                Uuid::new_v4(),
                &mut first,
                2,
                0,
                None,
                &publish,
            );
            tokio::pin!(pending);
            tokio::select! {
                biased;
                result = &mut pending => panic!("exact lane predecessor is still unclaimed: {result:?}"),
                _ = std::future::ready(()) => {},
            }
            if send_predecessor {
                let get = redis_command(&bytes::Bytes::from(crate::redis::encode_array(&[
                    b"GET", b"device",
                ])))
                .unwrap();
                let read = match_command(
                    &runtime.state,
                    &target,
                    Uuid::new_v4(),
                    &mut second,
                    2,
                    0,
                    None,
                    &get,
                )
                .await
                .unwrap();
                assert_eq!(read.report.sequence, 1);
                assert_eq!(read.report.target_event_index, Some(1));
                let published = pending.await.unwrap();
                assert_eq!(published.report.sequence, 2);
                assert_eq!(published.report.target_event_index, Some(0));
                let mut state = runtime.state.lock().await;
                state.redis.complete_exchange(&read);
                state.redis.complete_exchange(&published);
                assert!(!state.redis.snapshot().is_dirty());
                assert!(state.redis.snapshot().unused_case.is_empty());
            } else {
                tokio::time::advance(POOLED_LANE_WAIT).await;
                assert!(pending.await.is_err());
                let state = runtime.state.lock().await;
                assert!(matches!(
                    &state.redis.events.unmatched[0].diagnostic,
                    Some(CommandMatchDiagnostic::LaneBlocked { blocked_by, .. })
                        if blocked_by.sequence == 1
                ));
                assert_eq!(state.redis.snapshot().unused_case.len(), 2);
            }
        }
    }
}
