use super::*;
use crate::interaction::replay::timing::SocketIoTiming;

#[test]
fn socketio_timing_defaults_to_safe_auto_and_accepts_independent_recorded_override() {
    let default: ReplayProjectConfig = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(default.socketio_timing, SocketIoTiming::Auto);
    let recorded: ReplayProjectConfig = serde_json::from_value(
        serde_json::json!({"socketio_timing":"recorded","http_stream_timing":"fast"}),
    )
    .unwrap();
    assert_eq!(recorded.socketio_timing, SocketIoTiming::Recorded);
    assert_eq!(
        recorded.http_stream_timing,
        crate::replay::ReplayHttpStreamTiming::Fast
    );
    assert!(
        serde_json::from_value::<ReplayProjectConfig>(
            serde_json::json!({"socketio_timing":"unconditional_fast"})
        )
        .is_err()
    );
}
