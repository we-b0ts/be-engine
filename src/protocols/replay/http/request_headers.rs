//! Post-match HTTP request-header auditing and protected difference evidence.
use super::*;
mod fingerprint;
mod global;
pub(crate) mod time_reference;
pub(super) use global::preview as preview_global;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeaderDifferenceReport {
    pub(crate) case_id: Option<String>,
    source: ReplaySource,
    index: usize,
    target_event_index: usize,
    scheme: HttpReplayScheme,
    target: TargetKey,
    method: String,
    uri: String,
    source_case_id: Option<String>,
    source_request_started_at: Option<chrono::DateTime<Utc>>,
    target_request_started_at: chrono::DateTime<Utc>,
    recorded_request_fingerprint: String,
    #[serde(flatten)]
    difference: traffic_protocol_http::headers::audit::Difference,
}

pub(crate) use traffic_protocol_http::headers::{
    capture, exact_contract_match, native_contract_match, normalized,
};

impl ReplayState {
    pub(super) fn audit_http_request_headers(
        &mut self,
        exchange: &ReplayHttpExchange,
        index: usize,
        actual: &HeaderSnapshot,
        request_started_at: chrono::DateTime<Utc>,
    ) {
        let projected = global::audit_projection(self, exchange, actual, request_started_at);
        let actual = projected.as_ref().unwrap_or(actual);
        let target_event_index = self
            .protocols
            .http_events
            .matched_details
            .next_event_index(self.active_case_id.as_deref());
        let audit = traffic_protocol_http::headers::audit::compare(
            &exchange.record.native.request_headers,
            actual,
            &exchange.record.protected_request_headers,
            target_event_index < crate::replay::report::SUCCESS_DETAIL_LIMIT,
        );
        self.protocols.http_events.header_observation_count += audit.observation_count;
        let source_time_reference = time_reference::source(&exchange.record);
        let mut witness_fingerprint = None;
        for (dirty, difference) in audit
            .mismatches
            .into_iter()
            .map(|row| (true, row))
            .chain(audit.observations.into_iter().map(|row| (false, row)))
        {
            let report = HeaderDifferenceReport {
                case_id: self.active_case_id.clone(),
                source: exchange.source,
                index,
                target_event_index,
                scheme: exchange.identity.scheme,
                target: exchange.identity.target.clone(),
                method: exchange.record.native.method.clone(),
                uri: uri_path_only(&exchange.record.native.uri),
                source_case_id: exchange.case_id.clone(),
                source_request_started_at: source_time_reference,
                target_request_started_at: request_started_at,
                recorded_request_fingerprint: witness_fingerprint
                    .get_or_insert_with(|| fingerprint::recorded_fingerprint(&exchange.record))
                    .clone(),
                difference,
            };
            if dirty {
                if let Some(case_id) = &self.active_case_id {
                    self.protocols
                        .http_events
                        .dirty_case_ids
                        .insert(case_id.clone());
                }
                self.protocols.http_events.header_mismatches.push(report);
            } else {
                self.protocols.http_events.header_observations.push(report);
            }
        }
    }
}

#[cfg(test)]
mod tests;
