//! Additive Session rule proposals merge through the installed policy compiler.

use anyhow::{Context, Result, ensure};
use serde_yaml::Value;
use std::collections::BTreeMap;

use crate::policy::{NativeDomain, PolicyRule, TrafficPolicy, parse_policy, render_policy};

use super::{change, declarations, proposal, proposal_context, source_proof};

pub fn preview(base: &str, input: &str, allow_api: impl Fn(&str) -> bool) -> Result<String> {
    let mut document = parse_policy(base).context("load the Session policy baseline")?;
    ensure!(
        extend(&mut document, input, allow_api)?,
        "rule proposal does not change the assignment policy"
    );
    render_policy(&document)
}

pub fn assemble<'a>(base: &str, proposals: impl IntoIterator<Item = &'a str>) -> Result<String> {
    let mut document = parse_policy(base).context("load the Session integration policy")?;
    let mut changed = false;
    for input in proposals {
        changed |= extend(&mut document, input, |_| true)?;
    }
    if changed {
        render_policy(&document)
    } else {
        Ok(base.to_owned())
    }
}

/// Carry a plan to a newer attempt only if its authored slots have the reviewed values.
pub fn verify_rebase(old: &str, planned: &str, current: &str) -> Result<()> {
    if old == current {
        return Ok(());
    }
    let normalize = |policy| -> Result<Value> {
        Ok(serde_yaml::from_str(&render_policy(&parse_policy(
            policy,
        )?)?)?)
    };
    let old = normalize(old)?;
    let planned = normalize(planned)?;
    let current = normalize(current)?;
    ensure!(
        old.get("source_revision") == current.get("source_revision")
            && old.get("time") == current.get("time")
            && reviewed_slots_unchanged(Some(&old), Some(&planned), Some(&current)),
        "the Target policy changed a selector or context reviewed by the rule plan"
    );
    Ok(())
}

fn reviewed_slots_unchanged(
    old: Option<&Value>,
    planned: Option<&Value>,
    current: Option<&Value>,
) -> bool {
    if old == planned || old == current || planned == current {
        return true;
    }
    let Some(((old, planned), current)) = entries(old).zip(entries(planned)).zip(entries(current))
    else {
        return false;
    };
    old.keys().chain(planned.keys()).all(|key| {
        reviewed_slots_unchanged(
            old.get(key).copied(),
            planned.get(key).copied(),
            current.get(key).copied(),
        )
    })
}

fn entries(value: Option<&Value>) -> Option<BTreeMap<&str, &Value>> {
    match value {
        None => Some(BTreeMap::new()),
        Some(Value::Mapping(map)) => map
            .iter()
            .map(|(key, value)| Some((key.as_str()?, value)))
            .collect(),
        Some(Value::Sequence(rows)) => rows
            .iter()
            .map(|value| Some((value.get("id")?.as_str()?, value)))
            .collect(),
        _ => None,
    }
}

fn extend(
    document: &mut TrafficPolicy,
    input: &str,
    allow_api: impl Fn(&str) -> bool,
) -> Result<bool> {
    let resolved = proposal_context::resolve(input, document)?;
    let change = change::parse(&resolved.input)?;
    ensure!(
        change.replace_rules.is_empty() && change.replace_sections.is_empty(),
        "Session policy plans add rules or formats to existing selectors"
    );
    let proposed = change.policy;
    ensure!(
        proposed
            .source_revision
            .as_ref()
            .is_none_or(|rev| Some(rev) == document.source_revision.as_ref())
            && (!change.explicit_time || proposed.time == document.time),
        "Session policy plans must preserve the Source revision and time defaults"
    );
    ensure!(
        proposed.async_api.is_none()
            && proposed
                .http
                .as_ref()
                .is_none_or(|http| http.request_metadata.is_empty()),
        "Session policy plans must preserve recording scope and request metadata"
    );
    source_proof::validate_proposal(&resolved.input)?;
    crate::policy::require_source_proofs(&proposed)?;
    for rule in &proposed.rules {
        let api = match rule {
            PolicyRule::Value(rule) => rule.selector.api.as_deref(),
            PolicyRule::Native(rule) => {
                ensure!(
                    matches!(
                        rule.effect.domain(),
                        NativeDomain::Runtime | NativeDomain::Input
                    ),
                    "Session policy plans must preserve Source capture and ownership rules"
                );
                rule.selector.api.as_deref()
            }
        };
        ensure!(
            api.is_none_or(&allow_api),
            "proposed rule belongs to another API group"
        );
    }
    let mut next = document.clone();
    let declarations =
        declarations::merge_with_replacements(&mut next, &proposed, &Default::default())?;
    let rules = proposal::merge(&mut next, proposed.rules)?;
    crate::policy::compile_policy(&next)?;
    *document = next;
    Ok(declarations || rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "format: traffic-policy/v3\n";
    const TIME: &str = "format: traffic-policy/v3\njson:\n  fields:\n    /created: {kind: time, formats: [unix_seconds]}\n";
    const ID: &str =
        "format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [uuid]}\n";

    #[test]
    fn combines_disjoint_rules_and_rejects_conflicting_ownership() {
        assert!(preview(BASE, TIME, |_| true).is_ok());
        let combined = assemble(BASE, [TIME, ID, ID]).unwrap();
        let document = parse_policy(&combined).unwrap();
        let fields = &document.json.unwrap().fields;
        assert!(fields.contains_key("/created") && fields.contains_key("/id"));
        let conflicting = ID.replace("/id", "/created");
        assert!(assemble(BASE, [TIME, &conflicting]).is_err());
        assert!(preview(&combined, TIME, |_| true).is_err());
        let planned = preview(BASE, TIME, |_| true).unwrap();
        assert!(verify_rebase(BASE, &planned, ID).is_ok());
        assert!(verify_rebase(BASE, &planned, &conflicting).is_err());
    }
}
