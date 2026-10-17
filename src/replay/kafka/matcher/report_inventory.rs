//! Preserve native produce/fetch/delivery sections and each section's index.
use super::*;
use crate::replay::report::global_evidence::{
    regular::Row,
    regular_usage::{Position, Usage},
};

#[cfg(test)]
mod tests;

impl KafkaReplayState {
    pub(in crate::replay) fn global_report_extra_count(&self) -> usize {
        self.events
            .global_report
            .rows(0, &self.produces, true)
            .filter(|(_, exchange)| {
                exchange.source == ReplaySource::Global && !exchange.status.is_consumed()
            })
            .count()
            + self
                .events
                .global_report
                .rows(1, &self.fetches, true)
                .filter(|(_, exchange)| {
                    exchange.source == ReplaySource::Global && !exchange.status.is_consumed()
                })
                .count()
            + self
                .events
                .global_report
                .rows(2, &self.deliveries, true)
                .filter(|(_, exchange)| {
                    exchange.source == ReplaySource::Global && !exchange.status.is_consumed()
                })
                .count()
    }
    pub(in crate::replay) fn freeze_global_report_layout(&mut self) {
        self.events.global_report.freeze_layout(vec![
            self.produces.len(),
            self.fetches.len(),
            self.deliveries.len(),
        ]);
    }
    pub(in crate::replay) fn global_report_usage(&self) -> &Usage {
        &self.events.global_report
    }
    pub(in crate::replay) fn initialize_global_report_usage(&mut self, count: usize) {
        self.events.global_report.initialize(count);
    }
    pub(super) fn refresh_global_report(&mut self, section: u8, index: usize) {
        let exchange = match section {
            0 => self
                .produces
                .get(index)
                .map(|exchange| (exchange.source, exchange.status)),
            1 => self
                .fetches
                .get(index)
                .map(|exchange| (exchange.source, exchange.status)),
            2 => self
                .deliveries
                .get(index)
                .map(|exchange| (exchange.source, exchange.status)),
            _ => None,
        };
        if let Some((ReplaySource::Global, status)) = exchange {
            self.events
                .global_report
                .observe(section, index, true, !status.is_consumed());
        }
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
            .rows(0, &self.produces, extras)
            .filter(|(_, exchange)| exchange.source == ReplaySource::Global)
        {
            emit(
                visitor,
                0,
                index,
                KafkaUnusedReport {
                    index,
                    case_id: exchange.case_id.clone(),
                    source: ReplaySource::Global,
                    target: exchange.target.clone(),
                    operation: "produce".into(),
                    topic: exchange.record.topic.clone(),
                },
            )?;
        }
        for (index, exchange) in self
            .events
            .global_report
            .rows(1, &self.fetches, extras)
            .filter(|(_, exchange)| exchange.source == ReplaySource::Global)
        {
            emit(
                visitor,
                1,
                index,
                KafkaUnusedReport {
                    index,
                    case_id: exchange.case_id.clone(),
                    source: ReplaySource::Global,
                    target: exchange.target.clone(),
                    operation: "fetch".into(),
                    topic: exchange
                        .topics
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(","),
                },
            )?;
        }
        for (index, exchange) in self
            .events
            .global_report
            .rows(2, &self.deliveries, extras)
            .filter(|(_, exchange)| exchange.source == ReplaySource::Global)
        {
            emit(
                visitor,
                2,
                index,
                KafkaUnusedReport {
                    index,
                    case_id: exchange.case_id.clone(),
                    source: ReplaySource::Global,
                    target: exchange.target.clone(),
                    operation: "delivery".into(),
                    topic: exchange.record.topic.clone(),
                },
            )?;
        }
        Ok(())
    }
}

fn emit(
    visitor: &mut dyn FnMut(Row) -> Result<()>,
    section: u8,
    index: usize,
    value: KafkaUnusedReport,
) -> Result<()> {
    visitor(Row {
        position: Position { section, index },
        visible: true,
        value: serde_json::to_value(value)?,
    })
}
