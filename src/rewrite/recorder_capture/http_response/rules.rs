//! Mechanical selector equality and reviewed path coverage; no ID inference.
use std::collections::BTreeSet;

use anyhow::{Result, ensure};

use crate::AppConfig;
use crate::config::{HttpResponseRewriteRuleConfig as Rule, SourceTrafficPolicyConfig};

fn strings(values: &[String], ignore_case: bool) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| {
            if ignore_case {
                value.to_ascii_lowercase()
            } else {
                value.clone()
            }
        })
        .collect()
}

pub(super) fn related(left: &Rule, right: &Rule) -> bool {
    left.plugin.is_none()
        && right.plugin.is_none()
        && strings(&left.authorities, true) == strings(&right.authorities, true)
        && strings(&left.methods, true) == strings(&right.methods, true)
        && strings(&left.pointers, false) == strings(&right.pointers, false)
}

fn same_filters(left: &Rule, right: &Rule) -> bool {
    left.status_codes.iter().collect::<BTreeSet<_>>()
        == right.status_codes.iter().collect::<BTreeSet<_>>()
        && strings(&left.content_types, true) == strings(&right.content_types, true)
}

pub(super) fn path(rule: &Rule) -> &str {
    rule.path_pattern.as_deref().unwrap_or(&rule.path)
}

pub(super) fn covers(outer: &Rule, inner: &Rule) -> bool {
    match (&outer.path_pattern, &inner.path_pattern) {
        (Some(outer), Some(inner)) => crate::path_pattern::path_pattern_covers(outer, inner),
        (Some(outer), None) => crate::path_pattern::matches_path_pattern(outer, &inner.path),
        (None, Some(inner)) => !inner.contains('*') && outer.path == *inner,
        (None, None) => outer.path == inner.path,
    }
}

pub(super) fn validate_requested(app: &AppConfig, requested: &Rule) -> Result<()> {
    crate::config::source_traffic_policy::http_response::Document::from_rule(requested)?
        .into_rule()?;
    let mut validation = app.clone();
    validation.http_response_rewrite.rules = vec![requested.clone()];
    validation.validate()
}

pub(super) struct Convergence {
    pub rule: Rule,
    pub reused_existing: bool,
    pub replaced_rules: Vec<Rule>,
    pub changed: bool,
}

pub(super) fn converge(
    app: &mut AppConfig,
    policy: &mut SourceTrafficPolicyConfig,
    requested: &Rule,
) -> Result<Convergence> {
    validate_requested(app, requested)?;
    let original = app.http_response_rewrite.rules.clone();
    let reusable = original.iter().find(|rule| {
        related(rule, requested) && same_filters(rule, requested) && covers(rule, requested)
    });
    let effective = reusable.unwrap_or(requested).clone();
    // Managed rules are appended after static project rules by the policy loader.
    let static_count = original
        .len()
        .checked_sub(policy.http_response_rewrite.len())
        .ok_or_else(|| {
            anyhow::anyhow!("managed response rules do not match the loaded recorder")
        })?;
    ensure!(
        original[static_count..] == policy.http_response_rewrite,
        "managed response rules changed during consolidation"
    );
    let effective_is_static = reusable.is_some_and(|rule| {
        original[..static_count]
            .iter()
            .any(|static_rule| std::ptr::eq(static_rule, rule))
    });
    let mut replaced_rules = Vec::new();
    let mut after = Vec::new();
    let mut inserted = effective_is_static;
    let mut retained_effective = effective_is_static;
    for rule in &policy.http_response_rewrite {
        let covered =
            related(rule, &effective) && same_filters(rule, &effective) && covers(&effective, rule);
        if covered {
            if !inserted {
                after.push(effective.clone());
                inserted = true;
            }
            if rule == &effective && !retained_effective {
                retained_effective = true;
            } else {
                replaced_rules.push(rule.clone());
            }
        } else {
            after.push(rule.clone());
        }
    }
    if !inserted {
        after.push(effective.clone());
    }
    let changed = after != policy.http_response_rewrite;
    policy.http_response_rewrite = after;
    app.http_response_rewrite.rules.truncate(static_count);
    app.http_response_rewrite
        .rules
        .extend(policy.http_response_rewrite.iter().cloned());
    app.validate()?;
    Ok(Convergence {
        rule: effective,
        reused_existing: reusable.is_some(),
        replaced_rules,
        changed,
    })
}
