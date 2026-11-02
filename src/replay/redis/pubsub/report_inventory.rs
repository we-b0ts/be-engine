//! Inline/RPC push reports compose with ordinary Redis Global summaries. The
//! large indexed notification inventory remains a separate immutable section.
use super::*;
use crate::replay::report::global_evidence::{
    regular::Row,
    regular_usage::{Position, Usage},
};

impl PubSubState {
    pub(in crate::replay) fn global_report_extra_count(&self) -> usize {
        self.global_report
            .rows(1, &self.pushes, true)
            .filter(|(_, push)| push.source.is_run_level() && !push.status.is_consumed())
            .count()
    }
    pub(in crate::replay) fn freeze_global_report_layout(&mut self) {
        self.global_report.freeze_layout(vec![0, self.pushes.len()]);
    }
    pub(in crate::replay) fn indexed_global_remaining(&self) -> usize {
        self.indexed.total - self.indexed.delivered
    }
    pub(in crate::replay) fn global_report_usage(&self) -> &Usage {
        &self.global_report
    }
    pub(super) fn refresh_global_report(&mut self, index: usize) {
        let Some(push) = self
            .pushes
            .get(index)
            .filter(|push| push.source.is_run_level())
        else {
            return;
        };
        self.global_report
            .observe(1, index, true, !push.status.is_consumed());
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
        for (index, push) in self
            .global_report
            .rows(1, &self.pushes, extras)
            .filter(|(_, push)| push.source.is_run_level())
        {
            visitor(Row {
                position: Position { section: 1, index },
                visible: true,
                value: serde_json::to_value(CommandUnusedReport {
                    source_exchange_id: push.record.source_exchange_id(),
                    index: push.report_index.unwrap_or(index),
                    case_id: None,
                    source: push.source,
                    target: TargetKey {
                        host: normalize_host(&push.record.target_host),
                        port: push.record.target_port,
                    },
                    connection_id: push.record.connection_id,
                    sequence: push.record.subscription_sequence,
                    command: "PUBSUB_PUSH".into(),
                })?,
            })?;
        }
        Ok(())
    }
}
