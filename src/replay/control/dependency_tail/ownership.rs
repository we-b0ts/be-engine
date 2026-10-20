//! Exempt only exact Source exchanges authorized by existing process rules.
use super::RecordedReference;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::BufRead;
use std::path::Path;

pub(super) async fn prepare(
    case_dir: &Path,
    case_id: &str,
    references: &[RecordedReference],
    rules: Vec<crate::BackgroundDependencyRuleConfig>,
) -> Result<BTreeSet<RecordedReference>> {
    // API-origin permissions can be report-only and cannot discharge a live
    // finite dependency obligation. Only independent process rules apply here.
    let rules: Vec<_> = rules
        .into_iter()
        .filter(|rule| rule.trigger_source().is_none())
        .collect();
    if rules.is_empty() || references.is_empty() {
        return Ok(BTreeSet::new());
    }
    let case_dir = case_dir.to_owned();
    let case_id = case_id.to_owned();
    let references = references.iter().copied().collect::<BTreeSet<_>>();
    tokio::task::spawn_blocking(move || {
        let origins = crate::api_trigger::OriginIndex::default();
        let matcher = crate::recorder::background::BackgroundDependencyMatcher::from_rules(&rules)?;
        let ports = matcher.resolved_memcached_rule_ports();
        let path = case_dir.join("dependencies.jsonl");
        let input = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut owned = BTreeSet::new();
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(&line)?;
            let Some(reference) =
                reference(&event).filter(|reference| references.contains(reference))
            else {
                continue;
            };
            for rule in &rules {
                // Static SQL selectors require the same complete resultset
                // proof as report reclassification. API-origin rules instead
                // use their exact task/transaction witness, including writes.
                if matches!(reference, RecordedReference::Mysql { .. })
                    && rule.trigger_source().is_none()
                    && !crate::config::process_owned_dependencies::mysql::evidence::complete_response(&event)
                {
                    continue;
                }
                if crate::replay::report::source_owned_match(
                    &event,
                    Some(&case_id),
                    rule,
                    &ports,
                    &origins,
                )? {
                    owned.insert(reference);
                    break;
                }
            }
        }
        Ok(owned)
    })
    .await
    .context("dependency-tail ownership preparation task failed")?
}

fn reference(event: &Value) -> Option<RecordedReference> {
    match event["event_type"].as_str()? {
        "http_exchange" => Some(RecordedReference::Http {
            exchange_id: event["id"].as_str()?.parse().ok()?,
        }),
        "mysql_exchange" => Some(RecordedReference::Mysql {
            connection_id: event["connection_id"].as_str()?.parse().ok()?,
            sequence: event["query_sequence"].as_u64()?,
        }),
        "redis_exchange" => Some(RecordedReference::Redis {
            connection_id: event["connection_id"].as_str()?.parse().ok()?,
            sequence: event["sequence"].as_u64()?,
        }),
        _ => None,
    }
}
