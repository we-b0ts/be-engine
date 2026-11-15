//! Header-only proof does not require or reinterpret the response body's codec.
use super::evidence::{Witnesses, read};
use super::*;
use crate::policy::runtime::pattern::uri_path;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn validate(
    feedback: &ResponseHeaderDateRuleFeedback,
    policy: &str,
) -> Result<(usize, usize, Witnesses)> {
    let mut witnesses = Vec::new();
    let observations = super::response_evidence::collect(
        &feedback.evidence,
        &feedback.api,
        policy,
        &mut witnesses,
    )?;
    let mut by_header = BTreeMap::<String, Vec<ResponseHeaderDateRule>>::new();
    for rule in &feedback.rules {
        by_header
            .entry(rule.header.to_ascii_lowercase())
            .or_default()
            .push(rule.clone());
    }
    let matching = observations.len();
    let mut differences = 0;
    for observation in observations {
        let request: Value =
            serde_json::from_slice(&read(observation.request_path.into(), &mut witnesses)?)?;
        ensure!(
            uri_path(request["uri"].as_str().unwrap_or_default()) == observation.path,
            "header request identity differs from assertion evidence"
        );
        let source_bytes = read(observation.expected_response_path.into(), &mut witnesses)?;
        let target_bytes = read(observation.actual_response_path.into(), &mut witnesses)?;
        ensure!(
            fingerprint(&source_bytes) == observation.expected_response_fingerprint
                && fingerprint(&target_bytes) == observation.actual_response_fingerprint,
            "header response evidence changed since assertion"
        );
        let source: Value = serde_json::from_slice(&source_bytes)?;
        let target: Value = serde_json::from_slice(&target_bytes)?;
        let times = crate::primary_protocol::assertion::RequestTimes {
            source: request["timestamp"]
                .as_str()
                .and_then(|time| time.parse().ok()),
            target: target["request_sent_at"]
                .as_str()
                .or_else(|| target["timestamp"].as_str())
                .and_then(|time| time.parse().ok()),
        };
        let source_headers: crate::protocols::recording::events::HeaderMapSnapshot =
            serde_json::from_value(source["headers"].clone())?;
        let target_headers: crate::protocols::recording::events::HeaderMapSnapshot =
            serde_json::from_value(target["headers"].clone())?;
        let mut changed = false;
        for (header, rules) in &by_header {
            let source_values = source_headers
                .get(header)
                .context("source header is absent")?;
            let target_values = target_headers
                .get(header)
                .context("target header is absent")?;
            ensure!(
                !source_values
                    .iter()
                    .chain(target_values)
                    .any(|value| value == "<redacted>"),
                "redacted headers cannot authorize a date rule"
            );
            ensure!(
                crate::primary_protocol::assertion::headers::date::compare(
                    source_values,
                    target_values,
                    rules,
                    times
                )?,
                "stable response header values differ"
            );
            changed |= source_values != target_values;
        }
        differences += usize::from(changed);
    }
    ensure!(
        matching > 0 && differences > 0,
        "header date planning requires a selected dynamic difference"
    );
    Ok((matching, differences, witnesses))
}
