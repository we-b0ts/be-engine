mod document;
mod evidence;
mod plan;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use hyper::Method;
use serde::{Deserialize, Serialize};

use super::HttpGatewayRuleConfig;

pub use plan::{
    VerifiedApiExcludeEnsureReport, VerifiedApiExcludeEnsureStatus, VerifiedApiExcludeFeedback,
    VerifiedApiExcludePlan, VerifiedApiExcludeReport, ensure_verified_api_exclude,
    plan_verified_api_exclude,
};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct VerifiedApiExcludesConfig {
    pub consecutive_successes: usize,
    pub apis: Vec<VerifiedApiExclude>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifiedApiExclude {
    pub rule: String,
    pub method: String,
    pub path_pattern: String,
}

impl VerifiedApiExcludesConfig {
    pub(super) fn validate(&self, rules: &[HttpGatewayRuleConfig]) -> Result<()> {
        if !self.apis.is_empty() {
            ensure!(
                self.consecutive_successes > 0,
                "http_gateway.verified_excludes.consecutive_successes must be greater than zero when apis are configured"
            );
        }
        let mut unique = BTreeSet::new();
        for api in &self.apis {
            validate_api(api, rules)?;
            ensure!(
                unique.insert(api.clone()),
                "duplicate verified API exclude for {} {} in rule {:?}",
                api.method,
                api.path_pattern,
                api.rule
            );
        }
        Ok(())
    }
}

pub(super) fn validate_api(
    api: &VerifiedApiExclude,
    rules: &[HttpGatewayRuleConfig],
) -> Result<()> {
    ensure!(
        !api.rule.trim().is_empty(),
        "verified exclude rule is empty"
    );
    ensure!(
        rules
            .iter()
            .filter(|rule| rule.name.as_deref() == Some(api.rule.as_str()))
            .count()
            == 1,
        "verified exclude must reference exactly one named [[http_gateway.rules]] entry: {:?}",
        api.rule
    );
    let method = api.method.parse::<Method>().map_err(|error| {
        anyhow::anyhow!("invalid verified exclude method {:?}: {error}", api.method)
    })?;
    ensure!(
        method.as_str() == api.method,
        "verified exclude method must use canonical uppercase form: {:?}",
        api.method
    );
    validate_path_pattern(&api.path_pattern)?;
    Ok(())
}

pub(super) fn validate_path_pattern(pattern: &str) -> Result<()> {
    ensure!(
        pattern.starts_with('/'),
        "verified exclude path_pattern must start with '/': {pattern}"
    );
    ensure!(
        !pattern.contains(['?', '#', '\r', '\n']),
        "verified exclude path_pattern must contain only a URI path: {pattern}"
    );
    let segments = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        !segments.is_empty(),
        "verified exclude path_pattern must not match the root path"
    );
    ensure!(
        format!("/{}", segments.join("/")) == pattern,
        "verified exclude path_pattern must use canonical separators with no trailing slash: {pattern}"
    );
    ensure!(
        segments
            .iter()
            .all(|segment| !segment.contains('*') || *segment == "*" || *segment == "**"),
        "verified exclude wildcards must occupy a whole path segment: {pattern}"
    );
    ensure!(
        segments
            .iter()
            .enumerate()
            .all(|(index, segment)| *segment != "**" || index == segments.len() - 1),
        "verified exclude '**' catch-all must be the final path segment: {pattern}"
    );
    Ok(())
}
