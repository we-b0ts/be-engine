//! Request-rule projection and section-preserving policy edits.
use super::{JwtProfile, JwtRule, RequestRules};
use anyhow::{Context, Result};
use std::path::Path;

pub(crate) fn load(path: &Path) -> Result<RequestRules> {
    let policy = crate::policy::parse_policy(&std::fs::read_to_string(path)?)?;
    let compiled = crate::policy::compile_policy(&policy)?;
    crate::replay::compiled_input_rules(&compiled)
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

pub(crate) fn add(original: &str, profile: &JwtProfile, rule: &JwtRule) -> Result<String> {
    let value: serde_yaml::Value = serde_yaml::from_str(original)?;
    let mut rules = parse(&value)?;
    if !rules.jwt.add(profile.clone(), rule.clone())? {
        return Ok(original.to_string());
    }
    rules.validate()?;
    let section = serde_yaml::to_string(&std::collections::BTreeMap::from([(
        "request_rules",
        rules,
    )]))?;
    crate::replay::replace_request_rule_section(original, &section)
        .context("cannot update JWT request rules")
}
