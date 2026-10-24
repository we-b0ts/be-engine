//! Replace global format sections atomically and retain named endpoint aliases.
use crate::policy::TrafficPolicy;
use anyhow::{Result, ensure};

pub(super) fn merge(document: &mut TrafficPolicy, proposed: &TrafficPolicy) -> Result<bool> {
    let mut candidate = document.clone();
    if proposed.json.is_some() {
        candidate.json = proposed.json.clone();
    }
    if proposed.mysql.is_some() {
        candidate.mysql = proposed.mysql.clone();
    }
    if proposed.redis.is_some() {
        candidate.redis = proposed.redis.clone();
    }
    if proposed.http.is_some() {
        candidate.http = proposed.http.clone();
    }
    if proposed.async_api.is_some() {
        candidate.async_api = proposed.async_api.clone();
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
    let changed = &candidate != document;
    *document = candidate;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn global_sections_replace_instead_of_accumulating_old_field_strategies() {
        let parse = |fields: Value| {
            crate::policy::parse_policy(
                &json!({"format":"traffic-policy/v2","json":{"fields":fields}}).to_string(),
            )
            .unwrap()
        };
        let mut original = parse(json!({"/old":{"kind":"identity","formats":["uuid"]}}));
        let next = parse(json!({"/created_at":{"kind":"time","formats":["unix_seconds"]}}));
        assert!(merge(&mut original, &next).unwrap());
        assert_eq!(original.json, next.json);
        assert!(!merge(&mut original, &next).unwrap());
        assert!(merge(&mut original, &parse(json!({}))).unwrap());
        assert!(original.json.unwrap().fields.is_empty());
    }

    #[test]
    fn redis_section_replaces_atomically_and_can_clear_last_scalar_format() {
        let parse = |keys: Value| {
            crate::policy::parse_policy(
                &json!({"format":"traffic-policy/v2","redis":{"database":0,"keys":keys}})
                    .to_string(),
            )
            .unwrap()
        };
        let mut current = parse(json!({"old":{"kind":"identity","formats":["uuid"]}}));
        let next = parse(json!({"as-of":{"kind":"time","formats":["unix_seconds"]}}));
        assert!(merge(&mut current, &next).unwrap());
        assert_eq!(current.redis, next.redis);
        assert!(merge(&mut current, &parse(json!({}))).unwrap());
        assert!(current.redis.unwrap().keys.is_empty());
    }

    #[test]
    fn endpoint_alias_changes_are_atomic_and_existing_aliases_stay_fixed() {
        let parse = |endpoint: &str| {
            crate::policy::parse_policy(
                &json!({
                    "format":"traffic-policy/v2", "resources":{"cache":{
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
    fn headers_and_async_lifecycle_replace_atomically_and_absence_preserves_them() {
        let parse = |value: Value| crate::policy::parse_policy(&value.to_string()).unwrap();
        let mut document = parse(json!({"format":"traffic-policy/v2",
            "http":{"headers":{"x-amz-date":{"kind":"time","formats":["amz_date"]}}},
            "async_api":{"POST /jobs":{"when":{"/background":true},"end":[{"redis":{"operation":"DEL","key":"done:*","occurrence":2}}]}}
        }));
        let before = document.clone();
        assert!(!merge(&mut document, &parse(json!({"format":"traffic-policy/v2"}))).unwrap());
        assert_eq!(document, before);
        let next =
            parse(json!({"format":"traffic-policy/v2","http":{"headers":{}},"async_api":{}}));
        assert!(merge(&mut document, &next).unwrap());
        assert!(document.http.unwrap().headers.is_empty());
        assert!(document.async_api.unwrap().is_empty());
    }
}
