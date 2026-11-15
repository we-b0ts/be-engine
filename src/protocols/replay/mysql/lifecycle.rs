//! Complete admitted SQL requests interrupted only by the Source lifecycle.
use super::*;
use crate::replay::control::dependency_tail::RecordedReference;

pub(super) async fn deliver(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedExchange,
    started: tokio::time::Instant,
    row_encoding: ResultRowEncoding,
    fast: bool,
) -> Result<()> {
    let case = matched
        .report
        .case_id
        .as_deref()
        .context("MySQL cleanup lost its Case owner")?;
    let reference = RecordedReference::connection(
        "mysql",
        matched
            .record
            .connection_id
            .context("MySQL cleanup connection identity unavailable")?,
        matched
            .record
            .query_sequence
            .context("MySQL cleanup sequence unavailable")?,
    );
    let gate = state
        .lock()
        .await
        .async_cleanup_gate(case, reference)
        .context("MySQL request has no authenticated async cleanup context")?;
    let prefix = super::termination::prefix_packets(matched, row_encoding)?;
    super::termination::deliver_prefix(stream, matched, started, fast, prefix).await?;
    matched.claim.wait_sequence_delivery().await?;
    {
        let mut replay = state.lock().await;
        let mysql = &mut replay.protocols.mysql;
        ensure!(
            mysql
                .lifecycle
                .wait_client(&matched.claim, &mut mysql.exchanges[matched.index].status),
            "MySQL cleanup claim is no longer active"
        );
    }
    crate::replay::lifecycle_cleanup::await_target_end(stream, &gate, state, case).await
}
