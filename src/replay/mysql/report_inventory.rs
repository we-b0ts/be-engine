//! Global report projection and optional-session visibility, without delivery state changes.
use super::*;
use crate::replay::report::global_evidence::{
    regular::Row,
    regular_usage::{Position, Usage},
};

#[cfg(test)]
mod tests;

impl MysqlReplayState {
    pub(in crate::replay) fn freeze_global_report_layout(&mut self) {
        self.events
            .global_report
            .freeze_layout(vec![self.exchanges.len()]);
    }
    pub(in crate::replay) fn global_report_usage(&self) -> &Usage {
        &self.events.global_report
    }
    pub(in crate::replay) fn initialize_global_report_usage(&mut self, count: usize) {
        self.events.global_report.initialize(count);
    }
}

impl ReplayState {
    pub(in crate::replay) fn global_mysql_extra_unused_count(&self) -> usize {
        self.mysql
            .events
            .global_report
            .rows(0, &self.mysql.exchanges, true)
            .filter(|(_, exchange)| {
                let optional = exchange.optional_session.filter(|kind| {
                    exchange.status.is_available()
                        || matches!(
                            kind,
                            OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                        ) && exchange.status == ReplayExchangeStatus::Responding
                });
                exchange.source == ReplaySource::Global
                    && !exchange.status.is_consumed()
                    && optional.is_none()
            })
            .count()
    }
    pub(in crate::replay) fn refresh_mysql_global_report(&mut self, index: usize) {
        let Some(exchange) = self
            .mysql
            .exchanges
            .get(index)
            .filter(|exchange| exchange.source == ReplaySource::Global)
        else {
            return;
        };
        let optional = exchange.optional_session.filter(|kind| {
            exchange.status.is_available()
                || matches!(
                    kind,
                    OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                ) && exchange.status == ReplayExchangeStatus::Responding
        });
        self.mysql.events.global_report.observe(
            0,
            index,
            exchange.optional_session.is_none(),
            !exchange.status.is_consumed() && optional.is_none(),
        );
    }

    #[cfg(test)]
    pub(in crate::replay) fn visit_mysql_global_report_rows(
        &self,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        self.mysql.visit_global_report_range(false, visitor)
    }
    pub(in crate::replay) fn visit_mysql_global_report_extras(
        &self,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        self.mysql.visit_global_report_range(true, visitor)
    }
}

impl MysqlReplayState {
    pub(in crate::replay) fn visit_global_report_range(
        &self,
        extras: bool,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        for (index, exchange) in self
            .events
            .global_report
            .rows(0, &self.exchanges, extras)
            .filter(|(_, exchange)| exchange.source == ReplaySource::Global)
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
                })?,
            })?;
        }
        Ok(())
    }
}
