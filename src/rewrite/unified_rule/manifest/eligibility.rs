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
    removes_only_read_back(before, after)
        || allows_target_drift(before, after)
        || json_identity_change(before, after, false)
        || adds_only_json_times(before, after)
}

pub(in crate::rewrite::unified_rule) fn allows_target_drift(
    before: &CompiledPolicy,
    after: &CompiledPolicy,
) -> bool {
    adds_only_json_identities(before, after) || changes_only_redis_identities(before, after)
}

pub(in crate::rewrite::unified_rule) fn adds_only_json_identities(
    before: &CompiledPolicy,
    after: &CompiledPolicy,
) -> bool {
    json_identity_change(before, after, true)
}

fn json_identity_change(before: &CompiledPolicy, after: &CompiledPolicy, additions: bool) -> bool {
    let (Some(old), Some(new)) = (&before.global_json, &after.global_json) else {
        return false;
    };
    if old.fields == new.fields
        || additions != (old.fields.len() < new.fields.len())
        || old.fields.keys().any(|key| !new.fields.contains_key(key))
    {
        return false;
    }
    if new
        .fields
        .iter()
        .any(|(pointer, field)| match old.fields.get(pointer) {
            Some(prior) => prior != field && (additions || !same_identity_prefixes(prior, field)),
            None => !additions || !matches!(field, crate::policy::GlobalField::Identity { .. }),
        })
    {
        return false;
    }
    let mut expected = before.clone();
    let json = expected.global_json.as_mut().unwrap();
    json.fields = new.fields.clone();
    json.fingerprint = new.fingerprint.clone();
    expected.fingerprints = after.fingerprints.clone();
    expected == *after
}

/// A calendar-state read can change the business branch before an attempt
/// finishes. Permit its missing declaration to reach the ordinary planner;
/// Source validation, independent Target checks and fresh Replay still apply.
pub(in crate::rewrite::unified_rule) fn adds_only_json_times(
    before: &CompiledPolicy,
    after: &CompiledPolicy,
) -> bool {
    let (Some(old), Some(new)) = (&before.global_json, &after.global_json) else {
        return false;
    };
    if old.fields.len() >= new.fields.len()
        || old
            .fields
            .iter()
            .any(|(pointer, field)| new.fields.get(pointer) != Some(field))
        || new.fields.iter().any(|(pointer, field)| {
            !old.fields.contains_key(pointer)
                && !matches!(field, crate::policy::GlobalField::Time { .. })
        })
    {
        return false;
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

    #[test]
    fn partial_json_time_additions_preserve_existing_fields_clocks_and_other_owners() {
        let original = json!({"format":"traffic-policy/v3","json":{"fields":{
            "/id":{"kind":"identity","formats":["decimal"]},
            "/at":{"kind":"time","formats":["unix_seconds"]}
        }}});
        let parse =
            |value: &Value| crate::policy::parse_and_compile_policy(&value.to_string()).unwrap();
        let before = parse(&original);
        for scenario in [
            "calendar",
            "timestamp",
            "noop",
            "replace",
            "delete",
            "identity",
            "clock",
            "http",
        ] {
            let mut value = original.clone();
            value["json"]["fields"]["/day"] =
                json!({"kind":"time","formats":[{"format":"calendar_date","utc_offset":"+08:00"}]});
            match scenario {
                "timestamp" => {
                    value["json"]["fields"]["/day"] =
                        json!({"kind":"time","formats":["unix_milliseconds"]})
                }
                "noop" => value = original.clone(),
                "replace" => {
                    value["json"]["fields"]["/at"]["formats"] = json!(["unix_milliseconds"])
                }
                "delete" => {
                    value["json"]["fields"]
                        .as_object_mut()
                        .unwrap()
                        .remove("/id");
                }
                "identity" => {
                    value["json"]["fields"]["/new"] =
                        json!({"kind":"identity","formats":["decimal"]})
                }
                "clock" => value["time"] = json!({"default_utc_offset":"+00:00"}),
                "http" => {
                    value["http"] =
                        json!({"headers":{"x-id":{"kind":"identity","formats":["uuid"]}}})
                }
                _ => {}
            }
            assert_eq!(
                adds_only_json_times(&before, &parse(&value)),
                matches!(scenario, "calendar" | "timestamp"),
                "{scenario}"
            );
        }
        let empty = parse(&json!({"format":"traffic-policy/v3"}));
        let first = parse(&json!({"format":"traffic-policy/v3","json":{"fields":{
            "/day":{"kind":"time","formats":[{"format":"calendar_date","utc_offset":"+08:00"}]}
        }}}));
        assert!(allows_partial(&empty, &first));
    }

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
