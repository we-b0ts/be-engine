use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;

use super::super::config::{BindingEntry, ReplayPolicyDocument, validate_document};
use super::super::response::ResponseRules;

pub(super) fn replace_response_rules(original: &str, rules: &ResponseRules) -> Result<String> {
    let rendered = render_response_rules(rules)?;
    replace_root_section(original, "response_rules:", &rendered)
}

pub(super) fn replace_dependency_rules(
    original: &str,
    document: &ReplayPolicyDocument,
) -> Result<String> {
    let rendered = render_dependency_rules(document)?;
    replace_root_section(original, "dependency_rules:", &rendered)
}

pub(super) fn replace_process_output_rules(
    original: &str,
    rules: &BTreeMap<String, crate::ProfileByTypeVerificationRules>,
) -> Result<String> {
    let rendered = render_process_output_rules(rules)?;
    replace_root_section(original, "process_output_rules:", &rendered)
}

pub(crate) fn replace_root_section(
    original: &str,
    heading: &str,
    rendered: &str,
) -> Result<String> {
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

pub(super) fn render_dependency_rules(document: &ReplayPolicyDocument) -> Result<String> {
    if document.dependency_rules.is_empty() && document.dynamic_values.is_empty() {
        return Ok("dependency_rules: []\n".into());
    }
    let mut rendered = String::from("dependency_rules:\n");
    for rule in &document.dependency_rules {
        let mut yaml = serde_yaml::to_string(rule)?;
        if let Some(mysql) = &rule.mysql
            && !mysql.sql_values.is_empty()
        {
            let block = serde_yaml::to_string(&mysql.sql_values)?
                .lines()
                .map(|line| format!("    {line}\n"))
                .collect::<String>();
            let slots = mysql
                .sql_values
                .iter()
                .map(|(index, value)| Ok(format!("{index}: {}", serde_json::to_string(value)?)))
                .collect::<Result<Vec<_>>>()?
                .join(", ");
            yaml = yaml.replace(
                &format!("  sql_values:\n{block}"),
                &format!("  sql_values: {{{slots}}}\n"),
            );
        }
        for (index, line) in yaml.lines().enumerate() {
            rendered.push_str(if index == 0 { "- " } else { "  " });
            rendered.push_str(line);
            rendered.push('\n');
        }
    }
    for rule in &document.dynamic_values {
        let yaml = serde_yaml::to_string(&BindingEntry::DynamicValue(rule.clone()))?;
        for (index, line) in yaml.lines().enumerate() {
            rendered.push_str(if index == 0 { "- " } else { "  " });
            rendered.push_str(line);
            rendered.push('\n');
        }
    }
    Ok(rendered)
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

#[derive(Serialize)]
struct ProcessOutputRulesDocument<'a> {
    process_output_rules: &'a BTreeMap<String, crate::ProfileByTypeVerificationRules>,
}

pub(super) fn render_process_output_rules(
    rules: &BTreeMap<String, crate::ProfileByTypeVerificationRules>,
) -> Result<String> {
    Ok(serde_yaml::to_string(&ProcessOutputRulesDocument {
        process_output_rules: rules,
    })?)
}

pub(crate) fn replace_request_rule_section(original: &str, section: &str) -> Result<String> {
    replace_root_section(original, "request_rules:", section)
}
