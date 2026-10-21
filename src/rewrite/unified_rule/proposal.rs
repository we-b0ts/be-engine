//! Merge new rules and narrowly extend existing write rules with read delivery.
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
                extends_read_back(current, &rule),
                "existing rule ID changes scope, effect, contract or proof; only an additive read_back extension of the same write rule is supported"
            );
            *current = rule;
        } else {
            document.rules.push(rule);
        }
        changed = true;
    }
    Ok(changed)
}

fn extends_read_back(current: &PolicyRule, proposed: &PolicyRule) -> bool {
    let (PolicyRule::Native(current), PolicyRule::Native(proposed)) = (current, proposed) else {
        return false;
    };
    let old = current.effect.redis_read_back();
    let new = proposed.effect.redis_read_back();
    if new.len() <= old.len() || !new.starts_with(old) {
        return false;
    }
    let mut base = proposed.clone();
    match &mut base.effect {
        NativeEffect::Identity(effect) => effect.read_back = old.to_vec(),
        NativeEffect::RedisSequence(effect) => effect.read_back = old.to_vec(),
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
}
