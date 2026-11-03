//! Global visibility preserves reusable snapshot first-match semantics.
use super::*;
use crate::replay::report::global_evidence::{
    regular::Row,
    regular_usage::{Change, Position},
};

#[cfg(test)]
mod tests;

impl RedisReplayState {
    pub(in crate::replay) fn global_report_extra_count(&self) -> usize {
        self.events
            .global_report
            .rows(0, &self.exchanges, true)
            .filter(|(_, exchange)| {
                exchange.source.is_run_owned()
                    && if exchange.reusable_snapshot {
                        !exchange.matched_once
                    } else {
                        !exchange.status.is_consumed()
                    }
            })
            .count()
            + self.pubsub.global_report_extra_count()
    }
    pub(in crate::replay) fn freeze_global_report_layout(&mut self) {
        self.events
            .global_report
            .freeze_layout(vec![self.exchanges.len()]);
        self.pubsub.freeze_global_report_layout();
    }
    pub(in crate::replay) fn global_report_layout(&self) -> Vec<usize> {
        vec![
            self.events
                .global_report
                .layout()
                .first()
                .copied()
                .unwrap_or(0),
            self.pubsub
                .global_report_usage()
                .layout()
                .get(1)
                .copied()
                .unwrap_or(0),
        ]
    }
    pub(in crate::replay) fn global_report_snapshot(&self) -> Result<(usize, Vec<Change>)> {
        self.events
            .global_report
            .snapshot_with(self.pubsub.global_report_usage())
    }
    pub(in crate::replay) fn global_regular_report_count(&self) -> Option<usize> {
        self.events
            .global_report
            .count_with(self.pubsub.global_report_usage())
    }
    pub(in crate::replay) fn initialize_global_report_usage(&mut self, count: usize) {
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
        let visible = if exchange.reusable_snapshot {
            !exchange.matched_once
        } else {
            !exchange.status.is_consumed()
        };
        self.events.global_report.observe(0, index, true, visible);
    }
    pub(in crate::replay) fn visit_global_report_rows(
        &self,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        self.visit_global_report_range(false, visitor)
    }
    pub(in crate::replay) fn visit_global_report_extras(
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
        if extras {
            self.pubsub.visit_global_report_extras(visitor)
        } else {
            self.pubsub.visit_global_report_rows(visitor)
        }
    }
}
