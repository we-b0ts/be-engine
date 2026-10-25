//! Post-match HTTP request-header auditing and protected difference evidence.
use super::*;
mod fingerprint;
mod global;
pub(in crate::replay) mod time_reference;
pub(super) use global::preview as preview_global;

const TRANSPORT_HEADERS: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "content-length",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
];
const IGNORED_HEADERS: &[&str] = &[
    "user-agent",
    "accept-encoding",
    "traceparent",
    "tracestate",
    "b3",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-cloud-trace-context",
];
const IGNORED_PREFIXES: &[&str] = &["x-b3-", "x-datadog-"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ignore,
    Observe,
    Presence,
    SourcePresence,
    Strict,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct HeaderDifferenceReport {
    pub(in crate::replay) case_id: Option<String>,
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

pub(super) fn capture(headers: &hyper::HeaderMap) -> HeaderSnapshot {
    let mut snapshot = HeaderSnapshot::new();
    for (name, value) in headers {
        snapshot.entry(name.as_str().to_string()).or_default().push(
            value
                .to_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|_| STANDARD.encode(value.as_bytes())),
        );
    }
    snapshot
}

fn normalized(headers: &HeaderSnapshot) -> HeaderSnapshot {
    let mut normalized = HeaderSnapshot::new();
    for (name, values) in headers {
        normalized
            .entry(name.to_ascii_lowercase())
            .or_default()
            .extend(
                values
                    .iter()
                    .map(|value| value.trim_matches([' ', '\t']).to_string()),
            );
    }
    normalized
}

pub(in crate::replay) fn exact_contract_match(
    expected: &HeaderSnapshot,
    actual: &HeaderSnapshot,
) -> bool {
    let filter = |headers: &HeaderSnapshot| {
        normalized(headers)
            .into_iter()
            .filter(|(name, _)| mode(name, &BTreeSet::new()) != Mode::Ignore)
            .collect::<HeaderSnapshot>()
    };
    filter(expected) == filter(actual)
}

/// Match the native audit's acceptance modes. Body contracts cannot turn
/// presence-only credentials or observational negotiation into exact values.
pub(super) fn native_contract_match(expected: &HeaderSnapshot, actual: &HeaderSnapshot) -> bool {
    let expected = normalized(expected);
    let actual = normalized(actual);
    let connection_headers = [&expected, &actual]
        .into_iter()
        .filter_map(|headers| headers.get("connection"))
        .flatten()
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    expected.keys().chain(actual.keys()).all(|name| {
        let before = expected.get(name);
        let after = actual.get(name);
        match mode(name, &connection_headers) {
            Mode::Ignore | Mode::Observe => true,
            Mode::Presence => before.is_some() == after.is_some(),
            Mode::SourcePresence => before.is_none() || after.is_some(),
            Mode::Strict => {
                if before.is_some_and(|values| values.iter().any(|value| value == "<redacted>")) {
                    before.is_some() == after.is_some()
                } else {
                    before == after
                }
            }
        }
    })
}

fn mode(name: &str, connection_headers: &BTreeSet<String>) -> Mode {
    if TRANSPORT_HEADERS.contains(&name)
        || name.starts_with("x-recorder-")
        || connection_headers.contains(name)
        || IGNORED_HEADERS.contains(&name)
        || IGNORED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    {
        Mode::Ignore
    } else if name == "x-request-id" {
        Mode::SourcePresence
    } else if matches!(name, "content-type" | "accept" | "accept-language") {
        Mode::Observe
    } else if matches!(name, "authorization" | "cookie") {
        Mode::Presence
    } else {
        Mode::Strict
    }
}

fn protected(name: &str) -> bool {
    matches!(name, "authorization" | "cookie" | "set-cookie")
        || [
            "token",
            "secret",
            "password",
            "credential",
            "api-key",
            "apikey",
            "signature",
            "session",
        ]
        .iter()
        .any(|part| name.contains(part))
}

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
        let expected = normalized(&exchange.record.request_headers);
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
                self.http_events.header_observation_count += 1;
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
                method: exchange.record.method.clone(),
                uri: uri_path_only(&exchange.record.uri),
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
                    self.http_events.dirty_case_ids.insert(case_id.clone());
                }
                self.http_events.header_mismatches.push(report);
            } else {
                self.http_events.header_observations.push(report);
            }
        }
    }
}

#[cfg(test)]
mod tests;
