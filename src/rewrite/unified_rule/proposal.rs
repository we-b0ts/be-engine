//! Extend proven relationships without replacing existing owners or prior proofs.
use crate::policy::{NativeEffect, PolicyRule, Surface, TrafficPolicy};
use anyhow::{Result, ensure};

/// The issue owns the transaction, not a dependency resource's matching scope.
/// Existing policy entries retain their proven scope until explicitly migrated.
pub(super) fn prepare_scopes(
    document: &mut TrafficPolicy,
    existing: &TrafficPolicy,
    active_api: &str,
) -> Result<()> {
    super::declarations::validate_response_scope(document, active_api)?;
    for rule in &mut document.rules {
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
        if resource && !legacy_scope {
            ensure!(
                !when,
                "resource rules cannot depend on an inbound API body; select the dependency resource and value instead"
            );
            *api = None;
        }
    }
    Ok(())
}

pub(super) fn merge(document: &mut TrafficPolicy, rules: Vec<PolicyRule>) -> Result<bool> {
    let mut changed = false;
    for rule in rules {
        if let Some(current) = document.rules.iter_mut().find(|r| r.id() == rule.id()) {
            if current == &rule {
                continue;
            }
            ensure!(
                extends_relationships(current, &rule),
                "existing rule ID changes scope, capture, contract or prior proof; only additive identity references, read_back declarations or a separately proven finite read_back to state_epochs upgrade are supported. Preserve the existing rule and put new Source proof on each added permission"
            );
            *current = rule;
        } else {
            document.rules.push(rule);
        }
        changed = true;
    }
    Ok(changed)
}

fn extends_relationships(current: &PolicyRule, proposed: &PolicyRule) -> bool {
    let (PolicyRule::Native(current), PolicyRule::Native(proposed)) = (current, proposed) else {
        return false;
    };
    let mut base = proposed.clone();
    match (&current.effect, &mut base.effect) {
        (NativeEffect::Identity(old), NativeEffect::Identity(new)) => {
            let read_extension = new.read_back.len() >= old.read_back.len()
                && old.read_back.iter().zip(&new.read_back).all(|(old, new)| {
                    if old == new {
                        return true;
                    }
                    let mut previous = new.clone();
                    // The typed compiler admits state_epochs only on an
                    // unconditional raw SET-to-GET identity. This merge
                    // preserves that read's original contract and proof.
                    old.contract.state_epochs.is_none()
                        && previous.contract.state_epochs.take().is_some()
                        && &previous == old
                });
            if !new.references.starts_with(&old.references)
                || !read_extension
                || !new.mysql_read_back.starts_with(&old.mysql_read_back)
                || (new.references.len() == old.references.len()
                    && new.read_back == old.read_back
                    && new.mysql_read_back.len() == old.mysql_read_back.len())
            {
                return false;
            }
            new.references = old.references.clone();
            new.read_back = old.read_back.clone();
            new.mysql_read_back = old.mysql_read_back.clone();
        }
        (NativeEffect::RedisSequence(old), NativeEffect::RedisSequence(new)) => {
            if new.read_back.len() <= old.read_back.len()
                || !new.read_back.starts_with(&old.read_back)
            {
                return false;
            }
            new.read_back = old.read_back.clone();
        }
        _ => return false,
    }
    base == *current
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn document(rule: Value) -> TrafficPolicy {
        serde_json::from_value(json!({"format":"traffic-policy/v2","rules":[rule]})).unwrap()
    }

    #[test]
    fn resource_scope_omits_api_but_preserves_existing_scopes_and_primary_assertions() {
        let value = json!({"id":"date","surface":"dependency.request",
            "match":{"api":"GET /tasks","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"operation":"SET","key":{"exact":"members"}},
            "slot":"value","codec":"json","contract":{"/members":"unordered"},
            "proof":{"source":"source.py:1","fact":"Source writes unordered members"}});
        let native = json!({"id":"append","match":{"api":"GET /tasks",
            "resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"operation":"APPEND","key":{"kind":"exact","value":"content"}},
            "effect":{"kind":"redis_append_stream"},"proof":{"source":"source.py:2","fact":"Source writes a text stream"}});
        for raw in [value, native] {
            let old = document(raw);
            let empty = TrafficPolicy {
                rules: vec![],
                ..old.clone()
            };
            let mut fresh = old.clone();
            prepare_scopes(&mut fresh, &empty, "GET /tasks").unwrap();
            assert!(
                serde_json::to_value(&fresh).unwrap()["rules"][0]["match"]
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
            conditional["rules"][0]["when"] =
                json!({"request_body_json":{"/enabled":{"equals":true}}});
            let mut conditional: TrafficPolicy = serde_json::from_value(conditional).unwrap();
            assert!(prepare_scopes(&mut conditional, &empty, "GET /tasks").is_err());
        }
        let mut response = document(json!({"id":"response","surface":"api.response",
            "match":{"api":"GET /tasks"},"slot":"body","codec":"json","contract":{"/members":"unordered"},
            "proof":{"source":"source.py:3","fact":"Source returns unordered members"}}));
        let original = response.clone();
        prepare_scopes(&mut response, &original, "GET /tasks").unwrap();
        assert_eq!(response, original);
    }

    #[test]
    fn read_back_updates_preserve_the_whole_existing_rule_and_prior_declarations() {
        let prior = json!({"id":"block","match":{"api":"GET /tasks","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
            "operation":"SET","key":{"kind":"exact","value":"current:7"}},
            "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
                "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}]},
            "proof":{"source":"source.py:1","fact":"Source writes a generated identity"}});
        let mut proposed = prior.clone();
        proposed["effect"]["read_back"] = json!([{"operation":"GET","write_operation":"SET","argument_index":1,
            "proof":{"source":"source.py:2","fact":"Source reads that same generated identity"}}]);
        let prior = document(prior);
        let mut original = prior.clone();
        let update = document(proposed.clone());
        assert!(merge(&mut original, update.rules.clone()).unwrap());
        assert!(!merge(&mut original, update.rules).unwrap());
        for change in 0..5 {
            let mut changed = proposed.clone();
            match change {
                0 => changed["match"]["api"] = json!("GET /other"),
                1 => changed["effect"]["capture"]["index"] = json!(2),
                2 => changed["proof"]["fact"] = json!("changed existing proof"),
                3 => changed["effect"]["read_back"][0]["operation"] = json!("LRANGE"),
                _ => {
                    changed["effect"]
                        .as_object_mut()
                        .unwrap()
                        .remove("read_back");
                }
            }
            let mut baseline = if change < 3 {
                prior.clone()
            } else {
                original.clone()
            };
            let bytes = serde_json::to_vec(&baseline).unwrap();
            assert!(merge(&mut baseline, document(changed).rules).is_err());
            assert_eq!(serde_json::to_vec(&baseline).unwrap(), bytes);
        }
    }

    #[test]
    fn identity_reference_extensions_preserve_capture_scope_old_proofs_and_read_back() {
        let prior = json!({"id":"block","match":{"api":"GET /tasks","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
            "operation":"SET","key":{"kind":"exact","value":"current:7"}},
            "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
                "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}],
                "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1}]},
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
        for change in 0..7 {
            let mut bad = proposed.clone();
            match change {
                0 => bad["match"]["api"] = json!("GET /other"),
                1 => bad["effect"]["capture"]["index"] = json!(2),
                2 => bad["proof"]["fact"] = json!("changed capture proof"),
                3 => {
                    bad["effect"]["references"][0]["resource"]["endpoint"] =
                        json!("other.test:6379")
                }
                4 => {
                    bad["effect"]["references"][0]["proof"] =
                        json!({"source":"other.py:1","fact":"changed old reference"})
                }
                5 => bad["effect"]["read_back"][0]["operation"] = json!("LRANGE"),
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
        let mut combined = proposed;
        combined["effect"]["read_back"]
            .as_array_mut()
            .unwrap()
            .push(json!({"operation":"GET","write_operation":"SET","argument_index":1}));
        assert!(merge(&mut installed, document(combined).rules).unwrap());
    }

    #[test]
    fn finite_read_back_upgrades_only_add_the_state_proof_and_cannot_reverse_it() {
        let prior = json!({"id":"block","match":{"api":"GET /tasks","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
            "operation":"SET","key":{"kind":"exact","value":"current:7"}},
            "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
                "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}],
                "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1,
                    "proof":{"source":"source.py:2","fact":"Source reads the identity written to the same key"}}]},
            "proof":{"source":"source.py:1","fact":"Source writes a generated identity"}});
        let mut proposed = prior.clone();
        proposed["effect"]["read_back"][0]["state_epochs"] = json!({
            "source":"source.py:3","fact":"Repeated GETs observe the current identity until SET or DEL"});
        let baseline = document(prior.clone());
        let mut installed = baseline.clone();
        assert!(merge(&mut installed, document(proposed.clone()).rules).unwrap());
        assert!(!merge(&mut installed, document(proposed.clone()).rules).unwrap());
        let mut combined = proposed.clone();
        combined["effect"]["references"].as_array_mut().unwrap().push(json!({
            "contract":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"}},
            "proof":{"source":"source.py:4","fact":"The completed SQL result refers to the captured identity"}}));
        assert!(merge(&mut baseline.clone(), document(combined.clone()).rules).unwrap());
        for change in 0..8 {
            let mut bad = combined.clone();
            match change {
                0 => bad["match"]["api"] = json!("GET /other"),
                1 => bad["effect"]["capture"]["index"] = json!(2),
                2 => bad["proof"]["fact"] = json!("changed capture proof"),
                3 => bad["effect"]["read_back"][0]["proof"]["fact"] = json!("changed read proof"),
                4 => bad["effect"]["read_back"][0]["operation"] = json!("LRANGE"),
                5 => bad["effect"]["read_back"][0]["json_pointers"] = json!(["/id"]),
                6 => bad["effect"]["references"] = json!([]),
                _ => {
                    bad["effect"]["references"][0]["resource"]["endpoint"] =
                        json!("other.test:6379")
                }
            }
            let mut current = baseline.clone();
            assert!(
                merge(&mut current, document(bad).rules).is_err(),
                "change {change}"
            );
            assert_eq!(current, baseline);
        }
        for mut bad in [prior, proposed] {
            if let Some(proof) = bad["effect"]["read_back"][0].get_mut("state_epochs") {
                proof["fact"] = json!("replacement state proof");
            }
            let mut current = installed.clone();
            assert!(merge(&mut current, document(bad).rules).is_err());
            assert_eq!(current, installed);
        }
    }
}
