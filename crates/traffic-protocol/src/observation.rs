//! Native traffic observations projected into framework-owned aggregation.
use std::collections::BTreeMap;

use serde_json::Value;

pub struct TrafficInteraction {
    pub protocol: String,
    pub endpoint: Option<String>,
    pub operation: String,
}

pub trait NativeSummary: Send + Sync {
    fn observe(&mut self, event: &Value, endpoint: Option<&str>);
    fn value(&self) -> Value;
}

#[derive(Default)]
pub struct NativeSummaries {
    pub(crate) values: BTreeMap<String, Box<dyn NativeSummary>>,
}

impl NativeSummaries {
    pub fn snapshot(&self) -> BTreeMap<String, Value> {
        self.values
            .iter()
            .map(|(name, summary)| (name.clone(), summary.value()))
            .collect()
    }
}

impl std::fmt::Debug for NativeSummaries {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_set().entries(self.values.keys()).finish()
    }
}

pub fn format_endpoint(host: &str, port: u16) -> String {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn normalize_endpoint(value: &str) -> Option<String> {
    let authority = value.parse::<http::uri::Authority>().ok()?;
    Some(format_endpoint(authority.host(), authority.port_u16()?))
}

pub fn optional_endpoint(
    host: Option<&str>,
    port: Option<u16>,
    fallback: Option<&str>,
) -> Option<String> {
    host.zip(port)
        .map(|(host, port)| format_endpoint(host, port))
        .or_else(|| fallback.and_then(normalize_endpoint))
}
