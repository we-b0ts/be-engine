//! Native HTTP request positions, selectors and immutable request identities.
use crate::{
    headers::HeaderSnapshot,
    recorded::{RecordedExchange, decode_body},
};
use anyhow::{Result, ensure};
use hyper::{Method, Uri, http::uri::Authority};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use traffic_protocol::connection::Endpoint;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpDependencySelector {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
}

impl HttpDependencySelector {
    pub fn validate(&self) -> Result<()> {
        let authority = self.host.parse::<Authority>().ok();
        ensure!(
            authority.is_some_and(|a| a.host() == self.host && a.port().is_none())
                && !self.host.contains('*')
                && self.port > 0,
            "HTTP dependency rules require an exact host and nonzero port"
        );
        ensure!(
            Method::from_bytes(self.method.as_bytes()).is_ok(),
            "invalid HTTP dependency method"
        );
        let uri = self.path.parse::<Uri>().ok();
        ensure!(
            self.path.starts_with('/')
                && !self.path.contains('*')
                && uri.is_some_and(|u| u.query().is_none() && u.path() == self.path),
            "HTTP dependency rules require an exact path without a query or wildcard"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCrossCaseSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub method: String,
    pub path: String,
}

impl HttpCrossCaseSelector {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.host.is_some() || self.port.is_none(),
            "HTTP shared port requires a host"
        );
        if let Some(host) = &self.host {
            let authority = host.parse::<Authority>().ok();
            ensure!(
                host.len() <= 255
                    && !host.contains('*')
                    && authority.is_some_and(
                        |authority| authority.host() == host && authority.port().is_none()
                    ),
                "HTTP shared host requires a literal host without port, path or wildcard"
            );
        }
        if let (Some(host), Some(port)) = (&self.host, self.port) {
            HttpDependencySelector {
                host: host.clone(),
                port,
                method: self.method.clone(),
                path: self.path.clone(),
            }
            .validate()?;
        } else {
            ensure!(
                self.method.len() <= 32 && Method::from_bytes(self.method.as_bytes()).is_ok(),
                "invalid shared HTTP method"
            );
            crate::path_pattern::validate_literal_path(&self.path)?;
            ensure!(
                !self.path.contains(['?', '*']),
                "shared HTTP path cannot include a query or wildcard"
            );
        }
        Ok(())
    }

    pub fn matches(&self, record: &RecordedExchange) -> bool {
        record.identity().is_ok_and(|(_, target)| {
            self.host.as_ref().is_none_or(|host| {
                target.host == traffic_protocol::observation::normalize_host(host)
            }) && self.port.is_none_or(|port| target.port == port)
                && record.method.eq_ignore_ascii_case(&self.method)
                && crate::uri::uri_path_only(&record.uri) == self.path
        })
    }

    pub fn covers(&self, concrete: &Self) -> bool {
        concrete
            .host
            .as_ref()
            .zip(concrete.port)
            .is_some_and(|(host, port)| {
                self.host.as_ref().is_none_or(|expected| {
                    traffic_protocol::observation::normalize_host(expected)
                        == traffic_protocol::observation::normalize_host(host)
                }) && self.port.is_none_or(|expected| expected == port)
            })
            && self.method.eq_ignore_ascii_case(&concrete.method)
            && self.path == concrete.path
    }
}

/// Keep the already decoded body only when multipart may use it next.
pub fn compare_request(
    record: &RecordedExchange,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    ignored_query_params: &[String],
    body_matches: impl Fn(&[u8], &[u8]) -> bool,
) -> (Option<String>, Option<Vec<u8>>) {
    if !record.method.eq_ignore_ascii_case(method.as_str()) {
        return (
            Some(format!(
                "HTTP method mismatch: recorded {} actual {}",
                record.method, method
            )),
            None,
        );
    }
    if let Some(reason) = uri_mismatch_reason(&record.uri, &uri.to_string(), ignored_query_params) {
        return (Some(reason), None);
    }
    match decode_body(&record.request_body) {
        Ok(recorded_body) => {
            let mismatch = (!body_matches(&recorded_body, body))
                .then(|| "HTTP request body did not match the recorded body".to_string());
            let multipart_body = (!record.request_body.truncated
                && crate::multipart::supports_headers(&record.request_headers))
            .then_some(recorded_body);
            (mismatch, multipart_body)
        }
        Err(error) => (
            Some(format!("failed to decode recorded request body: {error}")),
            None,
        ),
    }
}

pub fn host_matches_target(host: &str, target: &Endpoint) -> bool {
    let Ok(authority) = host.parse::<Authority>() else {
        return false;
    };
    traffic_protocol::observation::normalize_host(authority.host()) == target.host
        && authority.port_u16().unwrap_or(target.port) == target.port
}

pub fn normalize_uri(
    value: &str,
    ignored_query_params: &[String],
) -> (String, Vec<(String, String)>) {
    let (path, mut query) = crate::uri::normalize_uri(value);
    query.retain(|(key, _)| {
        !ignored_query_params
            .iter()
            .any(|ignored| ignored.eq_ignore_ascii_case(key))
    });
    (path, query)
}

pub fn uri_mismatch_reason(
    recorded: &str,
    actual: &str,
    ignored_query_params: &[String],
) -> Option<String> {
    let (recorded_path, recorded_query) = normalize_uri(recorded, ignored_query_params);
    let (actual_path, actual_query) = normalize_uri(actual, ignored_query_params);
    if recorded_path != actual_path {
        return Some("HTTP path did not match the recorded request".to_string());
    }

    let ignored_count_differences = ignored_query_params
        .iter()
        .filter_map(|ignored| {
            let recorded_count = query_param_count(recorded, ignored);
            let actual_count = query_param_count(actual, ignored);
            (recorded_count != actual_count)
                .then(|| format!("{ignored} (recorded {recorded_count}, actual {actual_count})"))
        })
        .collect::<Vec<_>>();
    if !ignored_count_differences.is_empty() {
        return Some(format!(
            "HTTP ignored query parameter presence differed: {}",
            ignored_count_differences.join(", ")
        ));
    }

    if recorded_query == actual_query {
        return None;
    }

    let recorded_keys = query_key_counts(&recorded_query);
    let actual_keys = query_key_counts(&actual_query);
    if recorded_keys != actual_keys {
        let differing_keys = recorded_keys
            .keys()
            .chain(actual_keys.keys())
            .filter(|key| recorded_keys.get(*key) != actual_keys.get(*key))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        return Some(format!(
            "HTTP stable query parameter names or counts differed: {}",
            differing_keys.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    let differing_value_keys = recorded_keys
        .keys()
        .filter(|key| query_values(&recorded_query, key) != query_values(&actual_query, key))
        .cloned()
        .collect::<Vec<_>>();
    Some(format!(
        "HTTP stable query parameter values differed for: {}",
        differing_value_keys.join(", ")
    ))
}

fn query_key_counts(query: &[(String, String)]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (key, _) in query {
        *counts.entry(key.clone()).or_default() += 1;
    }
    counts
}

fn query_values(query: &[(String, String)], key: &str) -> Vec<String> {
    query
        .iter()
        .filter(|(query_key, _)| query_key == key)
        .map(|(_, value)| value.clone())
        .collect()
}

fn query_param_count(uri: &str, key: &str) -> usize {
    crate::uri::count_query_parameters(uri, |name| name.eq_ignore_ascii_case(key))
}

/// Fingerprint a native request after the host canonicalizes its selected body codec.
pub fn request_fingerprint(uri: &str, canonical_body: &[u8], headers: &HeaderSnapshot) -> String {
    use sha2::{Digest, Sha256};
    let significant = ["authorization", "cookie", "content-type"].map(|name| {
        let values: Vec<_> = headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .flat_map(|(_, values)| values.iter())
            .collect();
        (name, values)
    });
    let material = serde_json::to_vec(&(normalize_uri(uri, &[]), significant))
        .expect("HTTP identity is serializable");
    let mut digest = Sha256::new();
    digest.update(b"traffic-e2e-http-cross-case-v1\0");
    digest.update((material.len() as u64).to_be_bytes());
    digest.update(material);
    digest.update(canonical_body);
    format!("sha256:{:x}", digest.finalize())
}

pub fn recorded_header_fingerprint(record: &RecordedExchange) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&serde_json::json!({
        "scheme":record.scheme, "authority":record.authority, "method":record.method,
        "uri":record.uri, "headers":crate::headers::normalized(&record.request_headers),
        "request_started_at":record.request_started_at,
        "timestamp":record.timestamp, "duration_ms":record.duration_ms,
        "body_encoding":record.request_body.encoding, "body":record.request_body.data,
        "response_status":record.response_status,
    }))
    .expect("native HTTP header identity serializes");
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests;
