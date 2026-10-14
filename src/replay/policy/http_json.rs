//! Configuration for explicit HTTP request JSON array ordering and timestamps.
use super::config::{ReplayDependencyRule, ReplayScope};
use crate::replay::HttpUnorderedSelector;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpJsonRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) unordered: Vec<HttpUnorderedField>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) time: BTreeMap<String, super::request_contract::config::TimeField>,
}

impl HttpJsonRules {
    pub(super) fn is_empty(&self) -> bool {
        self.unordered.is_empty() && self.time.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpUnorderedField {
    pub(super) pointer: String,
    pub(super) source_evidence: String,
}

pub(super) fn validate(rule: &ReplayDependencyRule) -> Result<()> {
    let Some(http) = rule.http.as_ref().filter(|h| !h.json.unordered.is_empty()) else {
        return Ok(());
    };
    ensure!(
        rule.replay_scope == ReplayScope::Case && rule.case_selector.is_none(),
        "HTTP unordered rules select dependency endpoints within ordinary replay scope"
    );
    ensure!(
        http.query.is_empty(),
        "HTTP unordered rules keep query matching exact"
    );
    ensure!(
        http.json.unordered.len() <= 32,
        "HTTP unordered supports at most 32 paths per rule"
    );
    for (index, field) in http.json.unordered.iter().enumerate() {
        HttpUnorderedSelector {
            host: rule.target.host.clone().unwrap_or_default(),
            port: rule.target.port.unwrap_or_default(),
            method: http.method.clone(),
            path: http.path.clone(),
            pointer: field.pointer.clone(),
        }
        .validate()?;
        crate::config::process_owned_dependencies::validate_source_evidence(
            &field.source_evidence,
        )?;
        ensure!(
            http.json.unordered[..index]
                .iter()
                .all(|other| !super::response_locations_overlap(&other.pointer, &field.pointer)),
            "HTTP unordered paths must not overlap"
        );
    }
    Ok(())
}

/// Two rules must not independently authorize overlapping fields at one endpoint.
pub(super) fn validate_overlaps(rules: &[ReplayDependencyRule]) -> Result<()> {
    for (index, rule) in rules.iter().enumerate() {
        let Some(http) = rule.http.as_ref().filter(|h| !h.json.is_empty()) else {
            continue;
        };
        for other in &rules[..index] {
            let Some(other_http) = &other.http else {
                continue;
            };
            if rule
                .target
                .host
                .as_ref()
                .zip(other.target.host.as_ref())
                .is_none_or(|(a, b)| !a.eq_ignore_ascii_case(b))
                || rule.target.port != other.target.port
                || !http.method.eq_ignore_ascii_case(&other_http.method)
                || http.path != other_http.path
            {
                continue;
            }
            for left in &http.json.unordered {
                ensure!(
                    other_http.json.unordered.iter().all(|right| {
                        !super::response_locations_overlap(&left.pointer, &right.pointer)
                    }),
                    "HTTP unordered paths overlap between rules {:?} and {:?}",
                    rule.id,
                    other.id
                );
            }
        }
    }
    Ok(())
}
