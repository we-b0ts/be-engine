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
    header: String,
    reason: String,
    kind: &'static str,
    comparison: &'static str,
    source_case_id: Option<String>,
    source_request_started_at: Option<chrono::DateTime<Utc>>,
    target_request_started_at: chrono::DateTime<Utc>,
    recorded_request_fingerprint: String,
    expected: HeaderObservation,
    actual: HeaderObservation,
}

#[derive(Debug, Clone, Serialize)]
struct HeaderObservation {
    presence: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<Vec<String>>,
    protected: bool,
}

pub(crate) use traffic_protocol_http::headers::{
    Mode, capture, exact_contract_match, mode, native_contract_match, normalized, protected,
};

fn observation(name: &str, values: Option<&Vec<String>>, encrypted: bool) -> HeaderObservation {
    let protected = encrypted || protected(name);
    HeaderObservation {
        presence: if values.is_some() {
            "present"
        } else {
            "missing"
        },
        values: values.map(|values| {
            if protected {
                vec!["<redacted>".into()]
            } else {
                values
                    .iter()
                    .take(8)
                    .map(|value| value.chars().take(256).collect())
                    .collect()
            }
        }),
        protected,
    }
}

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
        let expected = normalized(&exchange.record.native.request_headers);
        let actual = normalized(actual);
        let source_time_reference = time_reference::source(&exchange.record);
        let mut witness_fingerprint = None;
        let connection_headers = [&expected, &actual]
            .into_iter()
            .filter_map(|headers| headers.get("connection"))
            .flatten()
            .flat_map(|value| value.split(','))
            .map(|name| name.trim().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let names = expected
            .keys()
            .chain(actual.keys())
            .collect::<BTreeSet<_>>();
        let target_event_index = self
            .protocols
            .http_events
            .matched_details
            .next_event_index(self.active_case_id.as_deref());
        for name in names {
            let mode = mode(name, &connection_headers);
            let recorded = expected.get(name);
            let sent = actual.get(name);
            if mode == Mode::Ignore {
                continue;
            }
            if mode == Mode::SourcePresence && (recorded.is_none() || sent.is_some()) {
                continue;
            }
            let presence_differs = recorded.is_some() != sent.is_some();
            let unavailable = !presence_differs
                && recorded.is_some_and(|values| values.iter().any(|v| v == "<redacted>"));
            if recorded == sent && !unavailable {
                continue;
            }
            let dirty = !unavailable
                && (mode == Mode::Strict
                    || mode == Mode::Presence && presence_differs
                    || mode == Mode::SourcePresence && recorded.is_some() && sent.is_none());
            if !dirty {
                self.protocols.http_events.header_observation_count += 1;
                if target_event_index >= crate::replay::report::SUCCESS_DETAIL_LIMIT {
                    continue;
                }
            }
            let kind = if unavailable {
                "header_unavailable"
            } else if recorded.is_none() {
                "header_added"
            } else if sent.is_none() {
                "header_missing"
            } else {
                "header_value_mismatch"
            };
            let encrypted = exchange.record.protected_request_headers.contains(name);
            let mut expected = observation(name, recorded, encrypted);
            let mut actual = observation(name, sent, encrypted);
            if mode == Mode::SourcePresence {
                expected.values = None;
                actual.values = None;
            }
            if unavailable {
                expected.presence = "unavailable";
                expected.values = None;
            }
            let report = HeaderDifferenceReport {
                case_id: self.active_case_id.clone(),
                source: exchange.source,
                index,
                target_event_index,
                scheme: exchange.identity.scheme,
                target: exchange.identity.target.clone(),
                method: exchange.record.native.method.clone(),
                uri: uri_path_only(&exchange.record.native.uri),
                header: name.clone(),
                reason: format!("{kind}: {name}"),
                kind,
                comparison: match mode {
                    Mode::Ignore => "ignore",
                    Mode::Observe => "observe",
                    Mode::Presence => "presence",
                    Mode::SourcePresence => "source_presence",
                    Mode::Strict => "strict",
                },
                source_case_id: exchange.case_id.clone(),
                source_request_started_at: source_time_reference,
                target_request_started_at: request_started_at,
                recorded_request_fingerprint: witness_fingerprint
                    .get_or_insert_with(|| fingerprint::recorded_fingerprint(&exchange.record))
                    .clone(),
                expected,
                actual,
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
