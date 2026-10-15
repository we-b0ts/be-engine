//! Preserve real subscription confirmations without changing case ownership.
use crate::AppState;
use crate::active_case::DependencyTargets;
use crate::recorder::RecorderEvent;

pub(in crate::recorder::redis) async fn record_subscription(
    state: &AppState,
    event: RecorderEvent,
    targets: DependencyTargets,
) -> anyhow::Result<()> {
    state.recorder().record(event.clone()).await?;
    for (case, matched_by) in &targets.cases {
        state
            .recorder()
            .append_case_dependency(case, &event, matched_by)
            .await?;
    }
    let (reason, phase, matched_by) = if targets.bootstrap_open {
        ("bootstrap_window", "bootstrap", "bootstrap_window")
    } else if targets.cases.is_empty() {
        ("pubsub_subscription", "runtime", "confirmed_subscription")
    } else {
        // This is the identical immutable exchange, not another command. Replay
        // aliases its finite consumption with the original case-owned record.
        (
            "pubsub_subscription_mirror",
            "runtime",
            "confirmed_subscription",
        )
    };
    // Await writer admission before the ordered socket writer can publish the
    // first push referring to this subscription's connection and sequence.
    state
        .recorder()
        .append_global_dependency(&event, reason, phase, matched_by)
        .await
}
