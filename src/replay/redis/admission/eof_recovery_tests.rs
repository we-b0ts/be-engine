use super::*;
use crate::ReplayStreamTiming;
use crate::interaction::{
    model::{EndReason, Protocol, WireMessage},
    observation::Observation,
};
use crate::replay::{ReplayLifecycleConfig, ReplayRuntime, control::handle_control_request};
use bytes::Bytes;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Recovered,
    Missing,
    BeforeClose,
    PrefixUnmatched,
    BeforeHeartbeatTimeout,
}

async fn command(
    runtime: &ReplayRuntime,
    args: &[&[u8]],
) -> Result<MatchedRedisExchange, &'static str> {
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let command = redis_command(&Bytes::from(crate::redis::encode_array(args))).unwrap();
    match_command(
        &runtime.state,
        &target,
        Uuid::new_v4(),
        &mut Default::default(),
        2,
        0,
        None,
        &command,
    )
    .await
}

async fn deliver(runtime: &ReplayRuntime, matched: &MatchedRedisExchange) {
    let mut state = runtime.state.lock().await;
    let scope = input_timing::scope(&state);
    state.redis.complete_exchange(matched);
    input_timing::response_delivered(&mut state, matched, scope.as_ref());
}

async fn control(runtime: &ReplayRuntime, value: Value) -> Value {
    let (reply, _) = handle_control_request(
        serde_json::from_value(value).unwrap(),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(reply["ok"], true, "{reply}");
    reply
}

#[tokio::test(start_paused = true)]
async fn eof_recovery_requires_a_delivered_prefix_and_the_exact_post_close_get() {
    use super::super::append::tests::event;
    for outcome in [
        Outcome::Recovered,
        Outcome::Missing,
        Outcome::BeforeClose,
        Outcome::PrefixUnmatched,
        Outcome::BeforeHeartbeatTimeout,
    ] {
        let mut source = Observation::new(Protocol::SocketIo, Default::default()).unwrap();
        source
            .output(
                WireMessage::text(r#"0{"sid":"source","pingInterval":1000,"pingTimeout":1000}"#),
                0,
            )
            .unwrap();
        source.output(WireMessage::text("2"), 1_000).unwrap();
        source.server_close(Some(1000), String::new());
        let (input, output) = source.finish(EndReason::ServerEof, 7_000, true).unwrap();
        let mut events = [
            event(1, "GET", &[b"prefix"], b"$1\r\np\r\n"),
            event(3, "GET", &[b"blocker"], b"$1\r\nx\r\n"),
            event(4, "PUBLISH", &[b"live", b"update"], b":1\r\n"),
            event(5, "GET", &[b"cleanup"], b"$1\r\ny\r\n"),
            event(6, "PUBLISH", &[b"live", b"more"], b":1\r\n"),
            event(8, "PUBLISH", &[b"live", b"shutdown"], b":1\r\n"),
        ];
        if matches!(outcome, Outcome::BeforeHeartbeatTimeout) {
            events[1]["request_started_at"] = json!("2020-01-01T00:00:01.500Z");
        }
        // An unmatched request in the required prefix must not itself block
        // selection of the PUBLISH's own lane predecessor.
        events[0]["connection_id"] = json!(Uuid::from_u128(42));
        let (_root, runtime) = tests::runtime_with_response(
            &events,
            json!({"format":"traffic-policy/v3","rules":[]}),
            json!({"method":"GET","uri":"/socket.io/","timestamp":"2020-01-01T00:00:00Z","interaction":input}),
            json!({"timestamp":"2020-01-01T00:00:07Z","duration_ms":7000,"interaction":output}),
            ReplayLifecycleConfig {stream_timing: Some(ReplayStreamTiming::Fast), ..Default::default()},
        ).await;
        let begin = control(
            &runtime,
            json!({"command":"input_timing_begin","case_id":"case"}),
        )
        .await;
        assert!(begin["fast_tail"]["heartbeat_acks"].is_array(), "{begin}");
        let query = |command, closed_at| {
            json!({"command":command,"case_id":"case","input_timing":{
            "epoch":begin["epoch"],"sequence":0,"completed":[],"closed_at":closed_at}})
        };
        let tail = || query("input_timing_tail", None);
        assert_eq!(control(&runtime, tail()).await["ready"], false);
        if !matches!(outcome, Outcome::PrefixUnmatched) {
            deliver(
                &runtime,
                &command(&runtime, &[b"GET", b"prefix"]).await.unwrap(),
            )
            .await;
        }
        assert!(
            command(&runtime, &[b"PUBLISH", b"live", b"update"])
                .await
                .is_err()
        );
        if matches!(
            outcome,
            Outcome::PrefixUnmatched | Outcome::BeforeHeartbeatTimeout
        ) {
            assert_eq!(
                control(&runtime, tail()).await["ready"],
                false,
                "{outcome:?}"
            );
        } else {
            let grant = control(&runtime, tail()).await;
            assert_eq!(grant["advance"]["probe_eof"], true, "{grant} {outcome:?}");
            assert!(runtime.state.lock().await.redis.events.unmatched.is_empty());
            let confirm = |at| query("input_timing_eof_recovery", Some(at));
            if matches!(outcome, Outcome::BeforeClose) {
                deliver(
                    &runtime,
                    &command(&runtime, &[b"GET", b"blocker"]).await.unwrap(),
                )
                .await;
            }
            let closed_at = chrono::Utc::now();
            if matches!(outcome, Outcome::Recovered) {
                let read = command(&runtime, &[b"GET", b"blocker"]).await.unwrap();
                // A matched request alone is insufficient, even after close.
                assert!(control(&runtime, confirm(closed_at)).await["recovered"].is_null());
                deliver(&runtime, &read).await;
                assert_eq!(
                    control(&runtime, confirm(closed_at)).await["recovered"],
                    true
                );
                let cleanup = command(&runtime, &[b"GET", b"cleanup"]).await.unwrap();
                assert_eq!(cleanup.report.sequence, 5);
                deliver(&runtime, &cleanup).await;
                let mut state = runtime.state.lock().await;
                crate::replay::control::input_timing::finish_eof_recovery(&mut state, "case");
                let snapshot = state.redis.snapshot();
                assert!(snapshot.unmatched.is_empty());
                assert!(snapshot.unused_case.is_empty());
                assert_eq!(snapshot.matched_count, 3);
                let audit = state.dependency_tails.eof_recovery("case").unwrap();
                assert_eq!(audit["omitted_unstarted_suffix"], 3);
                assert_eq!(audit["omitted_after_source_eof"], 1);
                assert_eq!(audit["blocker"]["sequence"], 3);
                continue;
            }
            if matches!(outcome, Outcome::Missing) {
                assert!(control(&runtime, confirm(closed_at)).await["recovered"].is_null());
                tokio::time::advance(POOLED_LANE_WAIT).await;
            }
            assert_eq!(
                control(&runtime, confirm(closed_at)).await["recovered"],
                false
            );
        }
        let state = runtime.state.lock().await;
        assert!(matches!(&state.redis.events.unmatched[0].diagnostic,
            Some(CommandMatchDiagnostic::LaneBlocked { blocked_by, .. }) if blocked_by.sequence == 3));
        assert!(state.dependency_tails.eof_recovery("case").is_none());
    }
}
