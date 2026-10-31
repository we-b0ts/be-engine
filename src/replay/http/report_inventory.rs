//! Stable native Global summaries, separate from Case cross-route projections.
use super::*;
use crate::replay::report::global_evidence::{
    regular::Row,
    regular_usage::{Position, Usage},
};

#[cfg(test)]
mod tests;

impl ReplayState {
    pub(in crate::replay) fn http_global_report_sharing_is_stable(&self) -> bool {
        // Cross-case sharing may reclassify and reorder original Global rows.
        // Those native indexes belong to this session; preserve them through
        // the existing complete visitor instead of reusing an unmodified core.
        !self.http_exchanges.iter().any(|exchange| {
            exchange.available_in_run_pool()
                && exchange.case_id.is_none()
                && exchange.shared_origin.is_some()
        })
    }
    pub(in crate::replay) fn global_http_extra_unused_count(&self) -> usize {
        self.http_events
            .global_report
            .rows(0, &self.http_exchanges, true)
            .filter(|(_, exchange)| {
                exchange.available_in_run_pool() && !exchange.status.is_consumed()
            })
            .count()
    }
    pub(in crate::replay) fn http_global_report_usage(&self) -> &Usage {
        &self.http_events.global_report
    }
    pub(in crate::replay) fn initialize_http_global_report_usage(&mut self, count: usize) {
        self.http_events.global_report.initialize(count);
    }
    pub(in crate::replay) fn refresh_http_global_report(&mut self, index: usize) {
        let Some(exchange) = self
            .http_exchanges
            .get(index)
            .filter(|exchange| exchange.available_in_run_pool())
        else {
            return;
        };
        self.http_events
            .global_report
            .observe(0, index, true, !exchange.status.is_consumed());
    }
    pub(in crate::replay) fn visit_http_global_report_extras(
        &self,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        visit_global_report_range(
            &self.http_exchanges,
            &self.http_events.global_report,
            true,
            visitor,
        )
    }
}

pub(in crate::replay) fn visit_global_report_range(
    exchanges: &[ReplayHttpExchange],
    usage: &Usage,
    extras: bool,
    visitor: &mut dyn FnMut(Row) -> Result<()>,
) -> Result<()> {
    for (index, exchange) in usage
        .rows(0, exchanges, extras)
        .filter(|(_, exchange)| exchange.available_in_run_pool())
    {
        visitor(Row {
            position: Position { section: 0, index },
            visible: true,
            value: serde_json::to_value(RecordedHttpExchangeSummary {
                source: exchange.source,
                source_http_id: exchange.record.id.clone(),
                shared_origin: exchange.shared_origin.clone(),
                index,
                case_id: exchange.case_id.clone(),
                scheme: exchange.identity.scheme,
                target: exchange.identity.target.clone(),
                method: exchange.record.method.clone(),
                uri: uri_path_only(&exchange.record.uri),
                status: exchange.record.response_status,
            })?,
        })?;
    }
    Ok(())
}
