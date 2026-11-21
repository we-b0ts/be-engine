//! Extend proven relationships without replacing existing owners or prior proofs.
use crate::policy::{NativeEffect, PolicyRule, Surface, TrafficPolicy};
use anyhow::{Result, ensure};

#[cfg(test)]
pub mod http_scope_tests;

/// The issue owns the transaction, not a dependency resource's matching scope.
/// Existing policy entries retain their proven scope until explicitly migrated.
pub fn prepare_scopes(
    document: &mut TrafficPolicy,
    existing: &TrafficPolicy,
    active_api: &str,
) -> Result<()> {
    for rule in &mut document.rules {
        let authored_http_scope =
            crate::policy::preserves_http_api_scope(rule, &document.resources)?;
        let legacy_scope = existing
            .rules
            .iter()
            .find(|old| old.id() == rule.id())
            .is_some_and(|old| match old {
                PolicyRule::Value(old) => old.selector.api.is_some(),
                PolicyRule::Native(old) => old.selector.api.is_some(),
            });
        let (api, resource, when) = match rule {
            PolicyRule::Value(rule) => (
                &mut rule.selector.api,
                rule.surface != Surface::ApiResponse,
                rule.when.is_some(),
            ),
            PolicyRule::Native(rule) => (
                &mut rule.selector.api,
                rule.selector.resource.is_some(),
                rule.when.is_some(),
            ),
        };
        ensure!(
            api.as_deref().is_none_or(|api| api == active_api),
            "rule proposal belongs to another API issue"
        );
        if resource && !legacy_scope && !authored_http_scope {
            ensure!(
                !when,
                "resource rules cannot depend on an inbound API body; select the dependency resource and value instead"
            );
            *api = None;
        }
    }
    Ok(())
}

pub fn merge(document: &mut TrafficPolicy, rules: Vec<PolicyRule>) -> Result<bool> {
    let mut changed = false;
    for rule in rules {
        if let Some(current) = document.rules.iter_mut().find(|r| r.id() == rule.id()) {
            if same_runtime_rule(current, &rule)? {
                continue;
            }
            ensure!(
                extends_relationships(current, &rule),
                "existing rule ID changes scope, capture or contract; only additive identity references are supported"
            );
            *current = rule;
        } else {
            document.rules.push(rule);
        }
        changed = true;
    }
    Ok(changed)
}

fn same_runtime_rule(left: &PolicyRule, right: &PolicyRule) -> Result<bool> {
    Ok(match (left, right) {
        (PolicyRule::Native(left), PolicyRule::Native(right)) => {
            crate::policy::native_semantics(left)? == crate::policy::native_semantics(right)?
        }
        (PolicyRule::Value(left), PolicyRule::Value(right)) => {
            crate::policy::compile_rule(left)?.fingerprint
                == crate::policy::compile_rule(right)?.fingerprint
        }
        _ => false,
    })
}

fn extends_relationships(current: &PolicyRule, proposed: &PolicyRule) -> bool {
    let (PolicyRule::Native(current), PolicyRule::Native(proposed)) = (current, proposed) else {
        return false;
    };
    let mut base = proposed.clone();
    let (NativeEffect::Identity(old), NativeEffect::Identity(new)) =
        (&current.effect, &mut base.effect)
    else {
        return false;
    };
    if new.references.len() <= old.references.len()
        || !old
            .references
            .iter()
            .zip(&new.references)
            .all(|(old, new)| old.contract == new.contract)
    {
        return false;
    }
    new.references = old.references.clone();
    crate::policy::native_semantics(&base)
        .ok()
        .zip(crate::policy::native_semantics(current).ok())
        .is_some_and(|(base, current)| base == current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn document(rule: Value) -> TrafficPolicy {
        serde_json::from_value(json!({"format":"traffic-policy/v3","rules":[rule]})).unwrap()
    }

    #[test]
    fn resource_scope_omits_api_but_preserves_existing_scopes_and_primary_assertions() {
        let native = json!({"id":"append","match":{"api":"GET /tasks",
            "resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"operation":"APPEND","key":{"kind":"exact","value":"content"}},
            "effect":{"kind":"redis_append_stream"},"proof":{"source":"source.py:2","fact":"Source writes a text stream"}});
        {
            let old = document(native);
            let empty = TrafficPolicy {
                rules: vec![],
                ..old.clone()
            };
            let mut fresh = old.clone();
            prepare_scopes(&mut fresh, &empty, "GET /tasks").unwrap();
            assert!(
                serde_json::to_value(&fresh).unwrap()["redis"]["rules"][0]["match"]
                    .get("api")
                    .is_none()
            );
            crate::policy::compile_policy(&fresh).unwrap();
            let mut update = old.clone();
            prepare_scopes(&mut update, &old, "GET /tasks").unwrap();
            assert_eq!(update, old);
            assert!(!merge(&mut old.clone(), update.rules).unwrap());
            assert!(prepare_scopes(&mut old.clone(), &empty, "POST /other").is_err());
            let mut conditional = serde_json::to_value(&old).unwrap();
            conditional["redis"]["rules"][0]["when"] =
                json!({"request_body_json":{"/enabled":{"equals":true}}});
            let mut conditional: TrafficPolicy = serde_json::from_value(conditional).unwrap();
            assert!(prepare_scopes(&mut conditional, &empty, "GET /tasks").is_err());
        }
        let mut response = document(json!({"id":"response","match":{"api":"GET /tasks"},
            "effect":{"kind":"response_header_date","header":"content-disposition","parameter":"filename","format":"%Y-%m-%d"},
            "proof":{"source":"source.py:3","fact":"Source includes the date in the download filename"}}));
        let original = response.clone();
        prepare_scopes(&mut response, &original, "GET /tasks").unwrap();
        assert_eq!(response, original);
    }

    #[test]
    fn identity_reference_extensions_preserve_capture_scope_and_prior_references() {
        let prior = json!({"id":"block","match":{"api":"GET /tasks","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
            "operation":"SET","key":{"kind":"exact","value":"current:7"}},
            "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
                "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}]},
            "proof":{"source":"source.py:1","fact":"Source writes a generated identity"}});
        let reference = json!({"contract":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"}},
            "proof":{"source":"source.py:complete","fact":"The completed result reuses the captured block identity"}});
        let mut proposed = prior.clone();
        proposed["effect"]["references"]
            .as_array_mut()
            .unwrap()
            .push(reference);
        let baseline = document(prior);
        let mut installed = baseline.clone();
        assert!(merge(&mut installed, document(proposed.clone()).rules).unwrap());
        assert!(!merge(&mut installed, document(proposed.clone()).rules).unwrap());
        for change in 0..4 {
            let mut bad = proposed.clone();
            match change {
                0 => bad["match"]["api"] = json!("GET /other"),
                1 => bad["effect"]["capture"]["index"] = json!(2),
                2 => {
                    bad["effect"]["references"][0]["resource"]["endpoint"] =
                        json!("other.test:6379")
                }
                _ => bad["effect"]["references"]
                    .as_array_mut()
                    .unwrap()
                    .reverse(),
            }
            let mut current = baseline.clone();
            let original = current.clone();
            assert!(
                merge(&mut current, document(bad).rules).is_err(),
                "change {change}"
            );
            assert_eq!(current, original);
        }
    }
}
