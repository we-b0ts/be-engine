//! Partial-attempt eligibility preserves owners and requires ordinary complete preflight.
use crate::policy::CompiledPolicy;

pub(super) fn removes_only_read_back(before: &CompiledPolicy, after: &CompiledPolicy) -> bool {
    let removed = before
        .native
        .iter()
        .filter(|old| !after.native.contains(old))
        .collect::<Vec<_>>();
    if removed.is_empty()
        || !removed
            .iter()
            .all(|old| crate::policy::native::is_key_only_read_back(&old.rule))
    {
        return false;
    }
    let mut expected = before.clone();
    expected.native.retain(|old| after.native.contains(old));
    // Digests identify the resulting policy; compare every compiled permission,
    // owner, format and signature independently of these derived digests.
    expected.fingerprints = after.fingerprints.clone();
    expected == *after
}

/// Narrow identity format changes retain Source-wide validation and independent
/// Target preflight. They never certify the unfinished Replay.
pub(super) fn allows_partial(before: &CompiledPolicy, after: &CompiledPolicy) -> bool {
    if removes_only_read_back(before, after) || changes_only_redis_identities(before, after) {
        return true;
    }
    let (Some(old), Some(new)) = (&before.global_json, &after.global_json) else {
        return false;
    };
    if !old.fields.keys().eq(new.fields.keys()) || old.fields == new.fields {
        return false;
    }
    for (pointer, old) in &old.fields {
        let new = &new.fields[pointer];
        if old == new {
            continue;
        }
        if !same_identity_prefixes(old, new) {
            return false;
        }
    }
    let mut expected = before.clone();
    let json = expected.global_json.as_mut().unwrap();
    json.fields = new.fields.clone();
    json.fingerprint = new.fingerprint.clone();
    expected.fingerprints = after.fingerprints.clone();
    expected == *after
}

fn same_identity_prefixes(
    old: &crate::policy::GlobalField,
    new: &crate::policy::GlobalField,
) -> bool {
    use crate::policy::GlobalField;
    let (GlobalField::Identity { formats: old }, GlobalField::Identity { formats: new }) =
        (old, new)
    else {
        return false;
    };
    let prefixes = |formats: &[crate::policy::GlobalIdentityFormat]| {
        formats
            .iter()
            .map(|format| format.prefix.clone())
            .collect::<std::collections::BTreeSet<_>>()
    };
    prefixes(old) == prefixes(new)
}

/// A failed first streamed Case must be able to declare its generated scalar
/// values without first completing the Cases it correctly stopped. This grants
/// no command/count/state permission. Whole-recording Source and independent
/// Target preflight, frozen evidence and fresh Replay remain mandatory.
fn changes_only_redis_identities(before: &CompiledPolicy, after: &CompiledPolicy) -> bool {
    let Some(new) = &after.redis else {
        return false;
    };
    let empty = crate::policy::RedisPolicy::default();
    let old = before.redis.as_ref().unwrap_or(&empty);
    if old == new || old.keys.keys().any(|key| !new.keys.contains_key(key)) {
        return false;
    }
    for (key, field) in &new.keys {
        let prior = old.keys.get(key);
        if prior == Some(field) {
            continue;
        }
        if key == "*" || key.chars().any(char::is_control) {
            return false;
        }
        match prior {
            Some(prior) if same_identity_prefixes(prior, field) => {}
            None if matches!(field, crate::policy::GlobalField::Identity { .. }) => {}
            _ => return false,
        }
    }
    let mut expected = before.clone();
    expected.redis = after.redis.clone();
    expected.fingerprints = after.fingerprints.clone();
    expected == *after
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn compile(redis: Value) -> CompiledPolicy {
        crate::policy::parse_and_compile_policy(
            &json!({"format":"traffic-policy/v3","redis":{"keys":redis}}).to_string(),
        )
        .unwrap()
    }

    #[test]
    fn partial_redis_identity_permission_preserves_every_other_compiled_contract() {
        let original = json!({
            "kept": {"kind":"time","formats":["unix_seconds"]},
            "old:*": {"kind":"identity","formats":[{"hex":32}]}
        });
        let before = compile(original.clone());
        for scenario in [
            "add",
            "revise",
            "noop",
            "delete",
            "rename",
            "prefix",
            "time",
            "read-back",
            "new-json",
            "new-http",
            "all-keys",
            "control-key",
        ] {
            let mut keys = original.clone();
            match scenario {
                "revise" => keys["old:*"]["formats"] = json!(["string"]),
                "noop" => {}
                "delete" => {
                    keys.as_object_mut().unwrap().remove("old:*");
                }
                "rename" => {
                    let value = keys.as_object_mut().unwrap().remove("old:*").unwrap();
                    keys["broader:*"] = value;
                }
                "prefix" => keys["old:*"]["formats"] = json!([{"prefix":"app-","format":"string"}]),
                "time" => keys["new:*"] = json!({"kind":"time","formats":["unix_seconds"]}),
                "read-back" => keys["old:*"]["read_back"] = json!(true),
                "all-keys" => {
                    keys.as_object_mut().unwrap().remove("kept");
                    keys["*"] = keys["old:*"].clone();
                }
                "control-key" => keys["new:\n*"] = keys["old:*"].clone(),
                _ => keys["new:*"] = json!({"kind":"identity","formats":[{"hex":32}]}),
            }
            let mut document = json!({"format":"traffic-policy/v3","redis":{"keys":keys}});
            if scenario == "new-json" {
                document["json"] = json!({"fields":{"/id":{"kind":"identity","formats":["uuid"]}}});
            }
            if scenario == "new-http" {
                document["http"] =
                    json!({"headers":{"x-id":{"kind":"identity","formats":["uuid"]}}});
            }
            let after = crate::policy::parse_and_compile_policy(&document.to_string()).unwrap();
            assert_eq!(
                allows_partial(&before, &after),
                matches!(scenario, "add" | "revise"),
                "{scenario}"
            );
        }
        let empty = crate::policy::parse_and_compile_policy("format: traffic-policy/v3").unwrap();
        let first = compile(json!({"new:*":{"kind":"identity","formats":[{"hex":32}]}}));
        assert!(allows_partial(&empty, &first));
        let all = compile(json!({"*":{"kind":"identity","formats":[{"hex":32}]}}));
        assert!(!allows_partial(&empty, &all));
        let revised_all = compile(json!({"*":{"kind":"identity","formats":["string"]}}));
        assert!(!allows_partial(&all, &revised_all));
    }
}
