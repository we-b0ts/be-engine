use anyhow::{Context, Result};
use serde::Serialize;

use super::super::config::{ReplayPolicyDocument, ReplayPolicyRule, validate_document};
use super::super::response::ResponseRules;

pub(super) fn replace_response_rules(original: &str, rules: &ResponseRules) -> Result<String> {
    let rendered = render_response_rules(rules)?;
    replace_root_section(original, "response_rules:", &rendered)
}

pub(super) fn replace_dependency_rules(
    original: &str,
    rules: &[ReplayPolicyRule],
) -> Result<String> {
    let rendered = render_dependency_rules(rules)?;
    replace_root_section(original, "rules:", &rendered)
}

fn replace_root_section(original: &str, heading: &str, rendered: &str) -> Result<String> {
    let mut offset = 0;
    let mut start = None;
    let mut end = original.len();
    for line in original.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if start.is_none() && trimmed.starts_with(heading) && !trimmed.starts_with(' ') {
            start = Some(offset);
        } else if start.is_some() && !trimmed.is_empty() && !trimmed.starts_with([' ', '#', '-']) {
            end = offset;
            break;
        }
        offset += line.len();
    }
    let mut updated = String::new();
    if let Some(start) = start {
        updated.push_str(&original[..start]);
        updated.push_str(rendered);
        updated.push_str(&original[end..]);
    } else {
        updated.push_str(original);
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(rendered);
    }
    let document: ReplayPolicyDocument =
        serde_yaml::from_str(&updated).context("generated replay policy is invalid YAML")?;
    validate_document(&document).context("generated replay policy is invalid")?;
    Ok(updated)
}

#[derive(Serialize)]
struct DependencyRulesDocument<'a> {
    rules: &'a [ReplayPolicyRule],
}

pub(super) fn render_dependency_rules(rules: &[ReplayPolicyRule]) -> Result<String> {
    Ok(serde_yaml::to_string(&DependencyRulesDocument { rules })?)
}

#[derive(Serialize)]
struct ResponseRulesDocument<'a> {
    response_rules: &'a ResponseRules,
}

pub(super) fn render_response_rules(rules: &ResponseRules) -> Result<String> {
    Ok(serde_yaml::to_string(&ResponseRulesDocument {
        response_rules: rules,
    })?)
}
