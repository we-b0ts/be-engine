//! Admit immutable snapshot seeds against current process-owned request scope.
use anyhow::{Result, ensure};

use super::{RecordedExchange, ReplaySource};
use crate::DependencyExchangeOutcome;
use crate::config::BackgroundDependencyRuleConfig;
use crate::config::process_owned_dependencies::redis_rule_matches;

#[cfg(test)]
mod tests;

pub(super) fn validate(
    record: &RecordedExchange,
    source: ReplaySource,
    rules: &[BackgroundDependencyRuleConfig],
    args: &[Vec<u8>],
) -> Result<bool> {
    ensure!(
        !record.cache_snapshot_hit,
        "Redis cache snapshot hits are diagnostic events and must not be replay dependencies"
    );
    let Some(recorded_rule) = record.cache_snapshot_rule.as_deref() else {
        return Ok(false);
    };
    ensure!(
        source == ReplaySource::Global
            && record.global_dependency_reason.as_deref() == Some("background_rule"),
        "Redis cache snapshot seed must be a background Global dependency"
    );
    ensure!(
        record.outcome == DependencyExchangeOutcome::Response
            && !record.response_kind.eq_ignore_ascii_case("error"),
        "Redis cache snapshot seed must contain a successful response"
    );
    ensure!(
        rules.iter().any(|rule| {
            rule.uses_redis_snapshot()
                && owner_name_matches(recorded_rule, rule.name())
                && redis_rule_matches(rule, record.target_port, &record.command, args)
        }),
        "Redis cache snapshot seed rule is absent or no longer matches the recording"
    );
    Ok(true)
}

/// Historical generated names included the Source revision. Callers must also
/// validate the complete current Redis selector; this never grants reuse from
/// an old name alone, nor rewrites the original recording's provenance.
pub(super) fn owner_name_matches(recorded: &str, current: &str) -> bool {
    recorded == current || (generated_process_name(recorded) && generated_process_name(current))
}

fn generated_process_name(name: &str) -> bool {
    name.strip_prefix("dependency.process_dependencies.")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
