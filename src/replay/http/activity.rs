use super::*;
use traffic_replay::ReplayExchangeStatus;

/// Actual ingress and response activity, projected for the shared runtime port.
pub(crate) fn has_in_flight(
    exchanges: &[ReplayHttpExchange],
    ingress: &ingress::HttpIngress,
    case: Option<Option<&str>>,
) -> bool {
    let ingress_pending = match case {
        Some(case) => ingress.has_case_pending(case),
        None => ingress.has_pending(),
    };
    ingress_pending
        || exchanges.iter().any(|exchange| {
            (case.is_none() || exchange.source == ReplaySource::Case)
                && matches!(
                    exchange.status,
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
        })
}

pub(crate) fn case_in_flight_diagnostic(exchanges: &[ReplayHttpExchange]) -> serde_json::Value {
    let pending = exchanges.iter().enumerate().filter(|(_, e)| {
        e.source == ReplaySource::Case
            && matches!(
                e.status,
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
            )
    });
    let count = pending.clone().count();
    let references = pending
        .take(4)
        .map(|(index, e)| {
            serde_json::json!({"index":index, "case_id":e.case_id,
                "exchange_id":e.record.id, "status":format!("{:?}", e.status)})
        })
        .collect::<Vec<_>>();
    serde_json::json!({"count":count, "references":references,
            "omitted":count.saturating_sub(4)})
}

#[cfg(test)]
impl ReplayState {
    pub(in crate::replay) fn http_has_case_in_flight(&self) -> bool {
        has_in_flight(
            &self.protocols.http_exchanges,
            &self.protocols.http_ingress,
            Some(self.active_case_id.as_deref()),
        )
    }
    pub(in crate::replay) fn http_has_in_flight(&self) -> bool {
        has_in_flight(
            &self.protocols.http_exchanges,
            &self.protocols.http_ingress,
            None,
        )
    }
}

/// Native protocol probes remain available; business initialization closes once.
pub(crate) fn startup_counts(
    exchanges: &mut [ReplayHttpExchange],
    close: bool,
) -> traffic_replay::StartupCounts {
    let mut counts = traffic_replay::StartupCounts::default();
    for exchange in exchanges {
        let mandatory = !exchange.is_repeatable_preflight_probe();
        counts.observe(exchange.source, &mut exchange.status, mandatory, close);
    }
    counts
}

pub(crate) fn case_is_dirty(
    exchanges: &[ReplayHttpExchange],
    index: &CaseExchangeIndex,
    ingress: &ingress::HttpIngress,
    events: &HttpReplayEvents,
    allowed_unused: Option<&crate::replay::ReplayAllowedUnusedHttpConfig>,
    case: &str,
) -> bool {
    ingress.case_failed(case)
        || events.dirty_case_ids.contains(case)
        || index.any(case, |index| {
            exchanges.get(index).is_some_and(|exchange| {
                let allowed = allowed_unused
                    .is_some_and(|config| config.hosts.contains(&exchange.identity.target.host));
                !exchange.status.is_covered()
                    && !allowed
                    && !(exchange.status == ReplayExchangeStatus::Cancelled
                        && events.cancelled.contains_key(&index))
            })
        })
}
