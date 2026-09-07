//! Request-rule projection and section-preserving policy edits.
use super::{JwtRule, RequestRules};
use anyhow::{Context, Result};
use std::path::Path;

pub(crate) fn load(path: &Path) -> Result<RequestRules> {
    crate::replay::validate_replay_policy(path)?;
    let value: serde_yaml::Value = serde_yaml::from_slice(&std::fs::read(path)?)?;
    parse(&value)
}

pub(crate) fn parse(value: &serde_yaml::Value) -> Result<RequestRules> {
    let rules = value
        .get("request_rules")
        .cloned()
        .map(serde_yaml::from_value)
        .transpose()?
        .unwrap_or_default();
    RequestRules::validate(&rules)?;
    Ok(rules)
}

pub(crate) fn add(original: &str, rule: &JwtRule) -> Result<String> {
    let value: serde_yaml::Value = serde_yaml::from_str(original)?;
    let mut rules = parse(&value)?;
    if let Some(existing) = rules.jwt.iter().find(|r| r.id == rule.id) {
        anyhow::ensure!(
            existing == rule,
            "JWT rule id already exists with different settings"
        );
        return Ok(original.to_string());
    }
    rules.jwt.push(rule.clone());
    rules.validate()?;
    let section = serde_yaml::to_string(&std::collections::BTreeMap::from([(
        "request_rules",
        rules,
    )]))?;
    crate::replay::replace_request_rule_section(original, &section)
        .context("cannot update JWT request rules")
}
