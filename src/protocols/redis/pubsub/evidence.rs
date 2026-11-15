//! Preserve real subscription confirmations without changing case ownership.
use crate::AppState;
use crate::active_case::DependencyTargets;
use crate::protocols::recording::events::RecorderEvent;

pub(in crate::protocols::redis) async fn record_subscription(
    state: &AppState,
    event: RecorderEvent,
    targets: DependencyTargets,
) -> anyhow::Result<()> {
    state.record_event_for_targets(event, targets);
    // A FIFO writer barrier makes the original subscription available before
    // the first push. The immutable exchange is never copied into another owner.
    state.recorder().flush_traffic().await
}
