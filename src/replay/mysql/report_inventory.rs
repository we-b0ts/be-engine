//! Global report projection and optional-session visibility, without delivery state changes.
use super::*;
use crate::replay::report::global_evidence::{
    regular::Row,
    regular_usage::{Change, Position, Usage},
};

#[cfg(test)]
mod tests;

impl MysqlReplayState {
    pub(crate) fn freeze_global_report_layout(&mut self) {
        self.events
            .global_report
            .freeze_layout(vec![self.exchanges.len()]);
    }
    pub(crate) fn global_report_usage(&self) -> &Usage {
        &self.events.global_report
    }
    pub(crate) fn initialize_global_report_usage(&mut self, count: usize) {
        self.events.global_report.initialize(count);
    }

    pub(in crate::replay) fn global_report_count(&self) -> Option<usize> {
        let usage = &self.events.global_report;
        let mut count = usage.count()?;
        for index in self.lifecycle.cancelled_indices() {
            let Some(exchange) = self
                .exchanges
                .get(index)
                .filter(|exchange| exchange.source.is_run_owned())
            else {
                continue;
            };
            if usage
                .layout()
                .first()
                .is_none_or(|boundary| index < *boundary)
                && !usage.visibility_at(
                    Position { section: 0, index },
                    exchange.optional_session.is_none(),
                )
            {
                count = count.checked_add(1)?;
            }
        }
        Some(count)
    }

    /// Cancellation publishes through the shared receipt without taking Replay's
    /// mutex. Fold only those sparse failures into the immutable run baseline.
    pub(crate) fn global_report_snapshot(&self) -> Result<(usize, Vec<Change>)> {
        let (mut count, changes) = self.events.global_report.snapshot()?;
        let cancelled = self.lifecycle.cancelled_indices();
        if cancelled.is_empty() {
            return Ok((count, changes));
        }
        let mut changes = changes
            .into_iter()
            .map(|change| (change.position, change))
            .collect::<BTreeMap<_, _>>();
        for index in cancelled {
            let Some(exchange) = self
                .exchanges
                .get(index)
                .filter(|exchange| exchange.source.is_run_owned())
            else {
                continue;
            };
            let position = Position { section: 0, index };
            let before = exchange.optional_session.is_none();
            let previous = changes.remove(&position).unwrap_or(Change {
                position,
                before,
                after: before,
            });
            if !previous.after
                && self
                    .events
                    .global_report
                    .layout()
                    .first()
                    .is_none_or(|boundary| index < *boundary)
            {
                count = count
                    .checked_add(1)
                    .context("cancelled MySQL run visibility overflow")?;
            }
            if !previous.before {
                changes.insert(
                    position,
                    Change {
                        position,
                        before: previous.before,
                        after: true,
                    },
                );
            }
        }
        Ok((count, changes.into_values().collect()))
    }
}

impl ReplayState {
    pub(in crate::replay) fn global_mysql_extra_unused_count(&self) -> usize {
        self.protocols
            .mysql
            .events
            .global_report
            .rows(0, &self.protocols.mysql.exchanges, true)
            .filter(|(index, exchange)| {
                let status = self
                    .protocols
                    .mysql
                    .lifecycle
                    .live_status(*index, exchange.status);
                let optional = exchange.optional_session.filter(|kind| {
                    status.is_available()
                        || matches!(
                            kind,
                            OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                        ) && status == ReplayExchangeStatus::Responding
                });
                exchange.source.is_run_owned() && !status.is_consumed() && optional.is_none()
            })
            .count()
    }
    pub(in crate::replay) fn refresh_mysql_global_report(&mut self, index: usize) {
        let Some(exchange) = self
            .protocols
            .mysql
            .exchanges
            .get(index)
            .filter(|exchange| exchange.source.is_run_owned())
        else {
            return;
        };
        let status = self
            .protocols
            .mysql
            .lifecycle
            .live_status(index, exchange.status);
        let optional = exchange.optional_session.filter(|kind| {
            status.is_available()
                || matches!(
                    kind,
                    OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                ) && status == ReplayExchangeStatus::Responding
        });
        self.protocols.mysql.events.global_report.observe(
            0,
            index,
            exchange.optional_session.is_none(),
            !status.is_consumed() && optional.is_none(),
        );
    }

    #[cfg(test)]
    pub(in crate::replay) fn visit_mysql_global_report_rows(
        &self,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        self.protocols
            .mysql
            .visit_global_report_range(false, visitor)
    }
}

impl MysqlReplayState {
    pub(crate) fn visit_global_report_range(
        &self,
        extras: bool,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        for (index, exchange) in self
            .events
            .global_report
            .rows(0, &self.exchanges, extras)
            .filter(|(_, exchange)| exchange.source.is_run_owned())
        {
            visitor(Row {
                position: Position { section: 0, index },
                visible: exchange.optional_session.is_none(),
                value: serde_json::to_value(RecordedExchangeSummary {
                    connection_id: exchange.record.connection_id,
                    query_sequence: exchange.record.query_sequence,
                    index,
                    case_id: exchange.case_id.clone(),
                    target: Some(exchange.identity.target.clone()),
                    database: exchange.identity.database.clone(),
                    username: exchange.identity.username.clone(),
                    command: exchange.record.command.clone(),
                    sql_summary: exchange.record.sql.as_deref().map(SqlSummary::new),
                    status: exchange.record.response.status.clone(),
                    row_count: exchange.record.result_row_count(),
                    // Immutable Global rows retain Source-only diagnostics.
                    diagnostic: self.transaction_equivalence.diagnostic(index),
                })?,
            })?;
        }
        Ok(())
    }
}
