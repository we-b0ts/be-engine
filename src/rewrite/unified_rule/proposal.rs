//! Merge new rules and append proven relationships without replacing existing owners.
use crate::policy::{NativeEffect, PolicyRule, TrafficPolicy};
use anyhow::{Result, ensure};

pub(super) fn merge(document: &mut TrafficPolicy, rules: Vec<PolicyRule>) -> Result<bool> {
    let mut changed = false;
    for rule in rules {
        if let Some(current) = document.rules.iter_mut().find(|r| r.id() == rule.id()) {
            if current == &rule {
                continue;
            }
            ensure!(
                extends_relationships(current, &rule),
                "existing rule ID changes scope, capture, contract or prior proof; only additive identity references or read_back declarations of the same rule are supported. Preserve the existing rule and put new Source proof on each appended relationship"
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
            if !new.references.starts_with(&old.references)
                || !new.read_back.starts_with(&old.read_back)
                || !new.mysql_read_back.starts_with(&old.mysql_read_back)
                || (new.references.len() == old.references.len()
                    && new.read_back.len() == old.read_back.len()
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
        serde_json::from_value(json!({"format":"traffic-policy/v1","rules":[rule]})).unwrap()
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
}
