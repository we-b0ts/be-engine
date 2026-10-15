//! Reclassify only unused MySQL summaries backed by complete Case exchanges.
use super::*;
use crate::config::process_owned_dependencies::mysql::evidence::consume_unused;

pub(super) fn reclassify(
    report: &mut Value,
    rules: &[BackgroundDependencyRuleConfig],
    dependencies: &mut BTreeMap<String, Vec<Value>>,
    counts: &mut BTreeMap<String, usize>,
    origins: &crate::api_trigger::OriginIndex,
) {
    let rules = rules
        .iter()
        .filter_map(|rule| match rule {
            BackgroundDependencyRuleConfig::Mysql {
                name,
                selector,
                trigger_source: None,
                ..
            } => Some((name.as_str(), selector)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if rules.is_empty() && origins.witnesses.is_empty() && origins.wire_witnesses.is_empty() {
        return;
    }
    let mut remaining = BTreeMap::<String, usize>::new();
    let mut total_remaining = BTreeMap::<String, usize>::new();
    move_matching_events(
        report,
        "unused_case_exchanges",
        "unused_global_exchanges",
        |unused| {
            let case = unused.get("case_id")?.as_str()?;
            if let Some(witness) = origins.witness(case, unused) {
                let key = crate::config::api_trigger::mysql::summary_key(case, unused)?;
                let used = remaining.entry(key).or_default();
                if *used < witness.exchanges {
                    let fingerprint = crate::config::api_trigger::mysql::key(case, unused)?;
                    if let Some(total) = origins.witnesses.get(&fingerprint) {
                        let used = total_remaining.entry(fingerprint).or_default();
                        if *used >= total.exchanges {
                            return None;
                        }
                        *used += 1;
                    }
                    *used += 1;
                    return Some(witness.rule.as_str());
                }
                return None;
            }
            let events = dependencies.get_mut(case)?;
            rules.iter().find_map(|(name, selector)| {
                // Missing, failed, incomplete or ambiguous immutable evidence
                // stays Case-owned; no SQL preview can authorize reclassification.
                consume_unused(selector, unused, events)
                    .unwrap_or(false)
                    .then_some(*name)
            })
        },
        counts.entry("mysql".to_string()).or_default(),
    );
}

#[cfg(test)]
mod tests;
