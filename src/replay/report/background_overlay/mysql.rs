//! Reclassify only unused MySQL summaries backed by complete Case exchanges.
use super::*;
use crate::config::process_owned_dependencies::mysql::evidence::consume_unused;

pub(super) fn reclassify(
    report: &mut Value,
    rules: &[BackgroundDependencyRuleConfig],
    dependencies: &mut BTreeMap<String, Vec<Value>>,
    counts: &mut BTreeMap<String, usize>,
) {
    let rules = rules
        .iter()
        .filter_map(|rule| match rule {
            BackgroundDependencyRuleConfig::Mysql { name, selector, .. } => {
                Some((name.as_str(), selector))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return;
    }
    move_matching_events(
        report,
        "unused_case_exchanges",
        "unused_global_exchanges",
        |unused| {
            let events = dependencies.get_mut(unused.get("case_id")?.as_str()?)?;
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
