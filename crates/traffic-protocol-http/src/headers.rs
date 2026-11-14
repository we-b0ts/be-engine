//! Native HTTP header normalization and comparison modes.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::{BTreeMap, BTreeSet};
pub type HeaderSnapshot = BTreeMap<String, Vec<String>>;

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
pub enum Mode {
    Ignore,
    Observe,
    Presence,
    SourcePresence,
    Strict,
}

pub fn normalized(headers: &HeaderSnapshot) -> HeaderSnapshot {
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

pub fn exact_contract_match(expected: &HeaderSnapshot, actual: &HeaderSnapshot) -> bool {
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
pub fn native_contract_match(expected: &HeaderSnapshot, actual: &HeaderSnapshot) -> bool {
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

pub fn mode(name: &str, connection_headers: &BTreeSet<String>) -> Mode {
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

pub fn protected(name: &str) -> bool {
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

pub fn capture(headers: &hyper::HeaderMap) -> HeaderSnapshot {
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
