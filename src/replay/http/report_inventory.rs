//! Stable native Global summaries, separate from Case cross-route projections.
use super::*;
use crate::replay::report::global_evidence::{
    regular::Row,
    regular_usage::{Position, Usage},
};

#[cfg(test)]
mod tests;

impl ReplayState {
    pub(in crate::replay) fn global_http_extra_unused_count(&self) -> usize {
        self.protocols
            .http_events
            .global_report
            .rows(0, &self.protocols.http_exchanges, true)
            .filter(|(_, exchange)| {
                exchange.available_in_run_pool() && !exchange.status.is_consumed()
            })
            .count()
    }
    pub(in crate::replay) fn http_global_report_usage(&self) -> &Usage {
        &self.protocols.http_events.global_report
    }
    pub(in crate::replay) fn refresh_http_global_report(&mut self, index: usize) {
        let Some(exchange) = self
            .protocols
            .http_exchanges
            .get(index)
            .filter(|exchange| exchange.available_in_run_pool())
        else {
            return;
        };
        self.protocols.http_events.global_report.observe(
            0,
            index,
            true,
            !exchange.status.is_consumed(),
        );
    }
}

pub(crate) fn visit_global_report_range(
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
                source_http_id: exchange.record.native.id.clone(),
                shared_origin: exchange.shared_origin.clone(),
                index,
                case_id: exchange.case_id.clone(),
                scheme: exchange.identity.scheme,
                target: exchange.identity.target.clone(),
                method: exchange.record.native.method.clone(),
                uri: uri_path_only(&exchange.record.native.uri),
                status: exchange.record.native.response_status,
            })?,
        })?;
    }
    Ok(())
}

pub(crate) fn global_report_sharing_is_stable(exchanges: &[ReplayHttpExchange]) -> bool {
    !exchanges.iter().any(|exchange| {
        exchange.available_in_run_pool()
            && exchange.case_id.is_none()
            && exchange.shared_origin.is_some()
    })
}
