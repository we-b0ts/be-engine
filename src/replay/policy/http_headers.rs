//! Explicit timestamp semantics for outbound HTTP request headers.
use super::config::{DependencyProtocol, ReplayDependencyRule, ReplayScope};
use super::response::ResponseTimestampFormat;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpHeaderTimestampSelector {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub header: String,
    pub format: ResponseTimestampFormat,
}

impl HttpHeaderTimestampSelector {
    pub(crate) fn validate_times(
        &self,
        expected: &[String],
        actual: &[String],
        source: Option<chrono::DateTime<chrono::Utc>>,
        target: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), String> {
        crate::replay::http::request_headers::timestamp::validate(
            self.format,
            Some(expected),
            Some(actual),
            crate::replay::assertion::RequestTimes { source, target },
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.path
                .split('/')
                .all(|part| !part.contains('*') || part == "*"),
            "HTTP header timestamp paths support only whole-segment * wildcards"
        );
        crate::HttpCrossCaseSelector {
            host: self.host.clone(),
            port: self.port,
            method: self.method.clone(),
            path: self.path.replace('*', "timestamp-selector"),
        }
        .validate()?;
        let name = hyper::header::HeaderName::from_bytes(self.header.as_bytes())?;
        ensure!(
            crate::replay::http::request_headers::allows_timestamp_rule(name.as_str()),
            "HTTP timestamp rules require a non-credential header subject to strict auditing"
        );
        Ok(())
    }

    pub(in crate::replay) fn matches(
        &self,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
    ) -> bool {
        self.host.eq_ignore_ascii_case(host)
            && self.port == port
            && self.method.eq_ignore_ascii_case(method)
            && super::pattern::path_pattern_matches(&self.path, path)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum HttpHeaderRule {
    Timestamp {
        format: ResponseTimestampFormat,
        source_evidence: String,
    },
}

impl HttpHeaderRule {
    pub(super) fn format(&self) -> ResponseTimestampFormat {
        match self {
            Self::Timestamp { format, .. } => *format,
        }
    }
}

pub(super) fn validate(rule: &ReplayDependencyRule) -> Result<()> {
    let Some(http) = rule.http.as_ref().filter(|h| !h.headers.is_empty()) else {
        return Ok(());
    };
    ensure!(
        rule.protocol == DependencyProtocol::Http
            && rule.replay_scope == ReplayScope::Case
            && rule.case_selector.is_none()
            && http.query.is_empty()
            && http.json.is_empty(),
        "HTTP header timestamp rules select dependency endpoints without changing ownership, queries or bodies"
    );
    ensure!(
        http.headers.len() <= 32,
        "HTTP header rules support at most 32 fields"
    );
    let mut names = std::collections::BTreeSet::new();
    for (header, field) in &http.headers {
        HttpHeaderTimestampSelector {
            host: rule.target.host.clone().unwrap_or_default(),
            port: rule.target.port.unwrap_or_default(),
            method: http.method.clone(),
            path: http.path.clone(),
            header: header.clone(),
            format: field.format(),
        }
        .validate()?;
        ensure!(
            names.insert(header.to_ascii_lowercase()),
            "duplicate case-insensitive HTTP header rule"
        );
        let HttpHeaderRule::Timestamp {
            source_evidence, ..
        } = field;
        crate::config::process_owned_dependencies::validate_source_evidence(source_evidence)?;
    }
    Ok(())
}

pub(super) fn validate_overlaps(rules: &[ReplayDependencyRule]) -> Result<()> {
    for (index, rule) in rules.iter().enumerate() {
        let Some(http) = rule.http.as_ref().filter(|h| !h.headers.is_empty()) else {
            continue;
        };
        for other in &rules[..index] {
            let Some(rhs) = &other.http else {
                continue;
            };
            if rule
                .target
                .host
                .as_ref()
                .zip(other.target.host.as_ref())
                .is_none_or(|(a, b)| !a.eq_ignore_ascii_case(b))
                || rule.target.port != other.target.port
                || !http.method.eq_ignore_ascii_case(&rhs.method)
            {
                continue;
            }
            let left: Vec<_> = http.path.split('/').collect();
            let right: Vec<_> = rhs.path.split('/').collect();
            let overlap = left.len() == right.len()
                && left
                    .iter()
                    .zip(&right)
                    .all(|(a, b)| a == b || *a == "*" || *b == "*");
            ensure!(
                !overlap
                    || http
                        .headers
                        .keys()
                        .all(|name| rhs.headers.keys().all(|n| !name.eq_ignore_ascii_case(n))),
                "HTTP header timestamp selectors overlap between rules {:?} and {:?}",
                rule.id,
                other.id
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
