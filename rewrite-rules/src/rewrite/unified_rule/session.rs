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
    let old = rebase_document(old)?;
    let planned = rebase_document(planned)?;
    let current = rebase_document(current)?;
    ensure!(
        old.get("source_revision") == current.get("source_revision")
            && old.get("time") == current.get("time")
            && reviewed_slots_unchanged(Some(&old), Some(&planned), Some(&current)),
        "the Target policy changed a selector or context reviewed by the rule plan"
    );
    Ok(())
}

fn rebase_document(policy: &str) -> Result<Value> {
    let policy = parse_policy(policy)?;
    let mut normalized: Value = serde_yaml::from_str(&render_policy(&policy)?)?;
    let Some(http) = policy
        .http
        .as_ref()
        .filter(|http| !http.request_sigv4.is_empty())
    else {
        return Ok(normalized);
    };
    let requests = http
        .request_sigv4
        .iter()
        .map(|rule| {
            let selector = declarations::http_request_selector(
                &rule.host,
                &rule.method,
                &rule.path,
                rule.query.as_deref(),
            );
            Ok((selector, serde_yaml::to_value(rule)?))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let http = normalized["http"]
        .as_mapping_mut()
        .context("rendered HTTP declarations are absent")?;
    let rows = http
        .get_mut("requests")
        .and_then(Value::as_sequence_mut)
        .context("rendered HTTP requests are absent")?;
    // SigV4 selectors have unique routes. Keep other request declarations in
    // their original positional review scope.
    rows.retain(|row| row.get("authorization").is_none());
    if rows.is_empty() {
        http.remove("requests");
    }
    http.insert("request_sigv4".into(), serde_yaml::to_value(requests)?);
    Ok(normalized)
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
    const REDIS_KEY: &str = "format: traffic-policy/v3\nredis:\n  keys:\n    'vnc_session:*':\n      key_format: {kind: identity, formats: [{prefix: vnc-, base64url: 24}]}\n";

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

    #[test]
    fn redis_key_identity_survives_session_plan_integration_and_rebase() {
        let previewed = preview(ID, REDIS_KEY, |_| true).unwrap();
        assert_eq!(assemble(ID, [REDIS_KEY, REDIS_KEY]).unwrap(), previewed);
        let policy = parse_policy(&previewed).unwrap();
        assert!(policy.json.unwrap().fields.contains_key("/id"));
        let redis = policy.redis.unwrap();
        assert!(redis.key_identities.contains_key("vnc_session:*"));
        assert!(redis.keys.is_empty());

        let disjoint = preview(ID, TIME, |_| true).unwrap();
        assert!(verify_rebase(ID, &previewed, &disjoint).is_ok());
        let changed = REDIS_KEY.replace("vnc-,", "other-,");
        let same_key_changed = preview(ID, &changed, |_| true).unwrap();
        assert!(verify_rebase(ID, &previewed, &same_key_changed).is_err());
    }

    #[test]
    fn sigv4_requests_survive_session_planning_integration_and_disjoint_rebase() {
        let base = r#"format: traffic-policy/v3
http:
  headers:
    x-amz-date: {kind: time, formats: [amz_date]}
  request_metadata:
    - host: api.example.test
      method: POST
      path: /connections
      json_ipv4: [/localIp]
"#;
        let proposal = r#"format: traffic-policy/v3
http:
  requests:
    - host: s3.example.test:9100
      method: GET
      path: /wegent-archives
      query: 'location='
      authorization: {kind: aws_sigv4}
"#;
        let disjoint = proposal.replace("location=", "location");
        let planned = preview(base, proposal, |_| true).unwrap();
        let current = preview(base, &disjoint, |_| true).unwrap();
        verify_rebase(base, &planned, &current).unwrap();
        assert_eq!(assemble(base, [proposal, proposal]).unwrap(), planned);

        let assembled = assemble(&current, [proposal]).unwrap();
        let policy = parse_policy(&assembled).unwrap().http.unwrap();
        assert_eq!(policy.headers.len(), 1);
        assert_eq!(policy.request_metadata.len(), 1);
        let queries = policy
            .request_sigv4
            .iter()
            .map(|rule| rule.query.as_deref())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            queries,
            std::collections::BTreeSet::from([Some("location="), Some("location")])
        );
    }
}
