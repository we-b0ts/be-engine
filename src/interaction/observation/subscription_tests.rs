use super::*;

#[test]
fn heartbeat_only_subscription_uses_default_ten_second_idle_without_pending_business() {
    let mut subscription =
        Observation::new_sse_subscription(InteractionPolicy::default(), 0).unwrap();
    assert!(subscription.pending().is_empty());
    subscription.stream_bytes(b": ping\r\n\r\n", 9_000).unwrap();
    assert_eq!(subscription.decision(9_999), LifecycleDecision::Continue);
    assert_eq!(
        subscription.decision(10_000),
        LifecycleDecision::Close(EndReason::BusinessIdle)
    );
    let (input, output) = subscription
        .finish(EndReason::BusinessIdle, 10_000, true)
        .unwrap();
    assert_eq!(input.http_stream_mode, HttpStreamMode::Subscription);
    assert!(output.end.clean);
    assert!(output.end.pending.is_empty());
    assert!(output.events.iter().all(|event| event.heartbeat));
}

#[test]
fn subscription_silence_starts_after_headers_and_business_events_reset_idle() {
    let mut subscription =
        Observation::new_sse_subscription(InteractionPolicy::default(), 12_000).unwrap();
    assert_eq!(subscription.decision(20_999), LifecycleDecision::Continue);
    subscription
        .stream_bytes(b"data: notification\n\n", 21_000)
        .unwrap();
    subscription.stream_bytes(b": ping\n\n", 30_000).unwrap();
    assert_eq!(subscription.decision(30_999), LifecycleDecision::Continue);
    assert_eq!(
        subscription.decision(31_000),
        LifecycleDecision::Close(EndReason::BusinessIdle)
    );
    assert!(
        subscription
            .finish(EndReason::BusinessIdle, 31_000, true)
            .unwrap()
            .1
            .end
            .clean
    );
}

#[test]
fn subscription_mode_does_not_certify_a_partial_sse_message() {
    let mut subscription =
        Observation::new_sse_subscription(InteractionPolicy::default(), 0).unwrap();
    subscription.stream_bytes(b"data: unfinished", 1).unwrap();
    assert!(
        subscription
            .finish(EndReason::BusinessIdle, 10_000, true)
            .is_err()
    );
}

#[test]
fn response_streams_and_legacy_inputs_keep_real_completion_requirements() {
    let mut response = Observation::new(Protocol::Sse, InteractionPolicy::default()).unwrap();
    response.stream_bytes(b": ping\n\n", 9_000).unwrap();
    assert_eq!(response.pending(), vec![0]);
    assert_eq!(response.decision(10_000), LifecycleDecision::Continue);
    assert_eq!(
        response.decision(120_000),
        LifecycleDecision::Fail(EndReason::RequestTimeout)
    );
    let raw = serde_json::to_value(InputTranscript::new(
        Protocol::Sse,
        InteractionPolicy::default(),
    ))
    .unwrap();
    assert!(raw.get("http_stream_mode").is_none());
    let legacy: InputTranscript = serde_json::from_value(raw).unwrap();
    assert_eq!(legacy.http_stream_mode, HttpStreamMode::Response);
}

#[test]
fn subscription_mode_rejects_response_completion_barriers_and_other_protocols() {
    let subscription = Observation::new_sse_subscription(InteractionPolicy::default(), 0).unwrap();
    let (mut input, _) = subscription
        .finish(EndReason::BusinessIdle, 10_000, true)
        .unwrap();
    input.protocol = Protocol::Ndjson;
    assert!(input.validate().is_err());
    input.protocol = Protocol::Sse;
    input.policy.stream_terminal = Some(super::super::policy::StreamTerminal::Text {
        value: "done".into(),
    });
    assert!(input.validate().is_err());
    input.policy.stream_terminal = None;
    input.actions.push(InputAction {
        sequence: 1,
        offset_ms: 1,
        after: vec![0],
        compressible_gap: false,
        gap_start_ms: Some(0),
        ack_ref: None,
        action: InputActionKind::Close {
            code: None,
            reason: String::new(),
        },
    });
    assert!(input.validate().is_err());
}
