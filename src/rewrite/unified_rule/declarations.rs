//! Global declarations add fields and ordered formats without replacing owners.
use crate::policy::{GlobalField, TrafficPolicy};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

mod formats;
#[cfg(test)]
mod incremental_tests;

#[cfg(test)]
pub(super) fn merge(document: &mut TrafficPolicy, proposed: &TrafficPolicy) -> Result<bool> {
    merge_with_replacements(document, proposed, &BTreeSet::new())
}

pub(super) fn merge_with_replacements(
    document: &mut TrafficPolicy,
    proposed: &TrafficPolicy,
    replace: &BTreeSet<String>,
) -> Result<bool> {
    let mut candidate = document.clone();
    if replace.contains("time") {
        candidate.time = proposed.time.clone();
    }
    if let Some(json) = &proposed.json {
        if replace.contains("json") {
            candidate.json = Some(json.clone());
        } else if !json.fields.is_empty() {
            fields(
                &mut candidate.json.get_or_insert_default().fields,
                &json.fields,
                "json.fields",
            )?;
        }
    }
    if let Some(mysql) = &proposed.mysql {
        if replace.contains("mysql") {
            candidate.mysql = Some(mysql.clone());
        } else {
            let tables = &mut candidate.mysql.get_or_insert_default().tables;
            for (name, table) in &mysql.tables {
                if let Some(current) = tables.get_mut(name) {
                    ensure!(
                        current.pattern == table.pattern,
                        "existing MySQL table pattern cannot be changed by an additive proposal"
                    );
                    for (column, field) in &table.fields {
                        let canonical = current
                            .fields
                            .keys()
                            .find(|name| name.eq_ignore_ascii_case(column))
                            .cloned()
                            .unwrap_or_else(|| column.clone());
                        field_entry(&mut current.fields, &canonical, field)
                            .with_context(|| format!("mysql.tables.{name}.fields.{column}"))?;
                    }
                } else {
                    let mut table = table.clone();
                    for field in table.fields.values_mut() {
                        let original = field.clone();
                        formats::merge(field, &original)?;
                    }
                    tables.insert(name.clone(), table);
                }
            }
        }
    }
    if let Some(redis) = &proposed.redis {
        if replace.contains("redis") {
            candidate.redis = Some(redis.clone());
        } else if !redis.keys.is_empty()
            || proposed
                .rules
                .iter()
                .any(|rule| rule.id().starts_with("redis.key."))
        {
            // Key-local behavior declarations compact back into redis.keys.
            // Preserve that container even when it has no scalar formats, so
            // rendering cannot introduce a previously absent format section.
            fields(
                &mut candidate.redis.get_or_insert_default().keys,
                &redis.keys,
                "redis.keys",
            )?;
        }
    }
    if let Some(http) = &proposed.http {
        if replace.contains("http") {
            candidate.http = Some(http.clone());
        } else if !http.headers.is_empty() {
            fields(
                &mut candidate.http.get_or_insert_default().headers,
                &http.headers,
                "http.headers",
            )?;
        }
    }
    if let Some(apis) = &proposed.async_api {
        if replace.contains("async_api") {
            candidate.async_api = Some(apis.clone());
        } else if !apis.is_empty() {
            let current = candidate.async_api.get_or_insert_default();
            for (api, rule) in apis {
                if let Some(existing) = current.get(api) {
                    ensure!(
                        existing == rule,
                        "existing async API contract cannot be changed by an additive proposal"
                    );
                } else {
                    current.insert(api.clone(), rule.clone());
                }
            }
        }
    }
    for (name, signature) in &proposed.signatures {
        if let Some(current) = candidate.signatures.get(name) {
            ensure!(
                current == signature,
                "existing signature definition changed; use a new signature name and explicitly replace the affected API positions"
            );
        } else {
            candidate.signatures.insert(name.clone(), signature.clone());
        }
    }
    for (name, resource) in &proposed.resources {
        if let Some(current) = candidate.resources.get(name) {
            ensure!(
                current == resource,
                "existing resource endpoint alias changed"
            );
        } else {
            candidate.resources.insert(name.clone(), resource.clone());
        }
    }
    crate::policy::compile_policy(&candidate)?;
    let changed = &candidate != document;
    *document = candidate;
    Ok(changed)
}

fn fields(
    current: &mut BTreeMap<String, GlobalField>,
    proposed: &BTreeMap<String, GlobalField>,
    location: &str,
) -> Result<()> {
    for (name, field) in proposed {
        field_entry(current, name, field).with_context(|| format!("{location}.{name}"))?;
    }
    Ok(())
}

fn field_entry(
    current: &mut BTreeMap<String, GlobalField>,
    name: &str,
    proposed: &GlobalField,
) -> Result<()> {
    if let Some(existing) = current.get_mut(name) {
        formats::merge(existing, proposed)?;
    } else {
        let mut field = proposed.clone();
        formats::merge(&mut field, proposed)?;
        current.insert(name.into(), field);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn named_signature_changes_cannot_silently_rebind_existing_api_permissions() {
        let parse = |name: &str, variable: &str| {
            crate::policy::parse_policy(&json!({
            "format":"traffic-policy/v3", "signatures":{
                name:{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":variable}}
            }
        }).to_string()).unwrap()
        };
        let mut policy = parse("default", "SESSION_SECRET");
        let before = policy.clone();
        assert!(merge(&mut policy, &parse("default", "OTHER_SECRET")).is_err());
        assert_eq!(policy, before);
        assert!(!merge(&mut policy, &before).unwrap());
        assert!(merge(&mut policy, &parse("oidc", "OIDC_SECRET")).unwrap());
        assert_eq!(policy.signatures.len(), 2);
    }

    #[test]
    fn global_sections_add_fields_and_empty_maps_do_not_clear_existing_strategies() {
        let parse = |fields: Value| {
            crate::policy::parse_policy(
                &json!({"format":"traffic-policy/v3","json":{"fields":fields}}).to_string(),
            )
            .unwrap()
        };
        let mut original = parse(json!({"/old":{"kind":"identity","formats":["uuid"]}}));
        let next = parse(json!({"/created_at":{"kind":"time","formats":["unix_seconds"]}}));
        assert!(merge(&mut original, &next).unwrap());
        assert!(original.json.as_ref().unwrap().fields.contains_key("/old"));
        assert!(
            original
                .json
                .as_ref()
                .unwrap()
                .fields
                .contains_key("/created_at")
        );
        assert!(!merge(&mut original, &next).unwrap());
        assert!(!merge(&mut original, &parse(json!({}))).unwrap());
        assert_eq!(original.json.unwrap().fields.len(), 2);
    }

    #[test]
    fn redis_section_adds_scalar_formats_and_explicit_replacement_can_clear_them() {
        let parse = |keys: Value| {
            crate::policy::parse_policy(
                &json!({"format":"traffic-policy/v3","redis":{"keys":keys}}).to_string(),
            )
            .unwrap()
        };
        let mut current = parse(json!({"old":{"kind":"identity","formats":["uuid"]}}));
        let next = parse(json!({"as-of":{"kind":"time","formats":["unix_seconds"]}}));
        assert!(merge(&mut current, &next).unwrap());
        assert_eq!(current.redis.as_ref().unwrap().keys.len(), 2);
        assert!(!merge(&mut current, &parse(json!({}))).unwrap());
        assert!(
            merge_with_replacements(
                &mut current,
                &parse(json!({})),
                &BTreeSet::from(["redis".into()])
            )
            .unwrap()
        );
        assert!(current.redis.unwrap().keys.is_empty());
    }

    #[test]
    fn endpoint_alias_changes_are_atomic_and_existing_aliases_stay_fixed() {
        let parse = |endpoint: &str| {
            crate::policy::parse_policy(
                &json!({
                    "format":"traffic-policy/v3", "resources":{"cache":{
                        "protocol":"redis", "endpoint":endpoint,"database":0}}
                })
                .to_string(),
            )
            .unwrap()
        };
        let mut original = parse("cache.test:6379");
        let before = original.clone();
        assert!(merge(&mut original, &parse("other.test:6379")).is_err());
        assert_eq!(original, before);
        assert!(!merge(&mut original, &before).unwrap());
    }

    #[test]
    fn empty_headers_and_async_maps_are_noop_unless_replacement_is_explicit() {
        let parse = |value: Value| crate::policy::parse_policy(&value.to_string()).unwrap();
        let mut document = parse(json!({"format":"traffic-policy/v3",
            "http":{"headers":{"x-amz-date":{"kind":"time","formats":["amz_date"]}}},
            "async_api":{"POST /jobs":{"when":{"/background":true},"end":[{"redis":{"operation":"DEL","key":"done:*","occurrence":2}}]}}
        }));
        let before = document.clone();
        assert!(!merge(&mut document, &parse(json!({"format":"traffic-policy/v3"}))).unwrap());
        assert_eq!(document, before);
        let next =
            parse(json!({"format":"traffic-policy/v3","http":{"headers":{}},"async_api":{}}));
        assert!(!merge(&mut document, &next).unwrap());
        assert_eq!(document, before);
        assert!(
            merge_with_replacements(
                &mut document,
                &next,
                &BTreeSet::from(["http".into(), "async_api".into()])
            )
            .unwrap()
        );
        assert!(document.http.unwrap().headers.is_empty());
        assert!(document.async_api.unwrap().is_empty());
    }
}
