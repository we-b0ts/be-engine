//! Complete admitted SQL requests interrupted only by the Source lifecycle.
use super::*;
use crate::replay::control::dependency_tail::RecordedReference;

impl RecordedMysqlExchange {
    pub(in crate::replay) fn authorize_lifecycle_cleanup(&mut self) -> Result<()> {
        ensure!(
            (self.outcome == crate::DependencyExchangeOutcome::Response
                && self.parse_warnings.as_slice() == ["engine cleanup interrupted MySQL capture"]
                || self
                    .outcome
                    .termination()
                    .is_some_and(|end| end.side != crate::dependency::TerminationSide::Engine
                        && end.scope != crate::dependency::TerminationScope::Stream)
                    && (self.parse_warnings.is_empty()
                        || self.parse_warnings.as_slice()
                            == ["engine cleanup interrupted MySQL capture"]))
                && matches!(
                    self.command.as_str(),
                    "COM_QUERY"
                        | "COM_STMT_EXECUTE"
                        | "COM_STMT_PREPARE"
                        | "COM_PING"
                        | "COM_INIT_DB"
                )
                && (self.command == "COM_PING"
                    || self.sql.as_ref().is_some_and(|sql| !sql.is_empty()))
                && self.connection_id.is_some()
                && self.query_sequence.is_some()
                && self.response.error_code.is_none()
                && self
                    .response
                    .wire_prefix
                    .iter()
                    .all(|prefix| !prefix.packet.truncated),
            "MySQL lifecycle cleanup requires an exact admitted complete request and no independent capture corruption"
        );
        if let Some(params) = &self.params {
            for value in params {
                if let Some(raw) = &value.raw {
                    ensure!(
                        !raw.truncated,
                        "MySQL cleanup parameter capture is incomplete"
                    );
                    mysql_value_bytes(value)?;
                }
            }
        }
        self.lifecycle_cleanup = true;
        Ok(())
    }
}

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
    let reference = RecordedReference::Mysql {
        connection_id: matched
            .record
            .connection_id
            .context("MySQL cleanup connection identity unavailable")?,
        sequence: matched
            .record
            .query_sequence
            .context("MySQL cleanup sequence unavailable")?,
    };
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
        let mysql = &mut replay.mysql;
        ensure!(
            mysql
                .lifecycle
                .wait_client(&matched.claim, &mut mysql.exchanges[matched.index].status),
            "MySQL cleanup claim is no longer active"
        );
    }
    super::super::lifecycle_cleanup::await_target_end(stream, &gate, state, case).await
}
