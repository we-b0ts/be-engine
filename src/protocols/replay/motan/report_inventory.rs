//! Native Global summaries and report-only visibility tracking.
use super::*;
use crate::replay::report::global_evidence::{
    regular::Row,
    regular_usage::{Position, Usage},
};

impl MotanReplayState {
    pub(crate) fn global_report_extra_count(&self) -> usize {
        self.events
            .global_report
            .rows(0, &self.exchanges, true)
            .filter(|(_, exchange)| {
                exchange.source.is_run_owned() && !exchange.status.is_consumed()
            })
            .count()
    }
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
    pub(super) fn refresh_global_report(&mut self, index: usize) {
        let Some(exchange) = self
            .exchanges
            .get(index)
            .filter(|exchange| exchange.source.is_run_owned())
        else {
            return;
        };
        self.events
            .global_report
            .observe(0, index, true, !exchange.status.is_consumed());
    }
    pub(crate) fn visit_global_report_rows(
        &self,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        self.visit_global_report_range(false, visitor)
    }
    pub(crate) fn visit_global_report_extras(
        &self,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        self.visit_global_report_range(true, visitor)
    }
    fn visit_global_report_range(
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
                visible: true,
                value: serde_json::to_value(CommandUnusedReport {
                    source_exchange_id: None,
                    index,
                    case_id: exchange.case_id.clone(),
                    source: exchange.source,
                    target: TargetKey {
                        host: normalize_host(&exchange.record.target_host),
                        port: exchange.record.target_port,
                    },
                    connection_id: exchange.record.connection_id,
                    sequence: exchange.record.sequence,
                    command: exchange.record.command.clone(),
                })?,
            })?;
        }
        Ok(())
    }
}

pub(super) fn unused_iter(
    exchanges: &[ReplayExchange],
    source: ReplaySource,
) -> impl Iterator<Item = CommandUnusedReport> + '_ {
    exchanges
        .iter()
        .enumerate()
        .filter(move |(_, exchange)| {
            exchange.source.matches_scope(source) && !exchange.status.is_consumed()
        })
        .map(move |(index, exchange)| CommandUnusedReport {
            source_exchange_id: None,
            index,
            case_id: exchange.case_id.clone(),
            source: exchange.source,
            target: TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            connection_id: exchange.record.connection_id,
            sequence: exchange.record.sequence,
            command: exchange.record.command.clone(),
        })
}

pub(super) fn unused(
    exchanges: &[ReplayExchange],
    source: ReplaySource,
) -> Vec<CommandUnusedReport> {
    unused_iter(exchanges, source)
        .take(if source.is_run_owned() {
            100
        } else {
            usize::MAX
        })
        .collect()
}
