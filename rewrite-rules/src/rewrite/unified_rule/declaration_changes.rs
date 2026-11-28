//! Public update summaries expose declaration positions and format metadata only.
use std::collections::{BTreeMap, BTreeSet};

use crate::policy::{GlobalField, TrafficPolicy};
use serde_json::{Map, Value, json};

use super::declarations::http_request_selector;

pub fn summarize(
    before: &TrafficPolicy,
    after: &TrafficPolicy,
    replace: &BTreeSet<String>,
) -> Value {
    let mut changes = Map::new();
    if before.time != after.time {
        changes.insert(
            "time".into(),
            json!({
                "mode":"replace", "location":"time",
                "before":before.time, "after":after.time,
            }),
        );
    }
    section(
        &mut changes,
        "json",
        "json.fields",
        before.json.as_ref().map(|policy| &policy.fields),
        after.json.as_ref().map(|policy| &policy.fields),
        true,
        replace.contains("json"),
    );
    section(
        &mut changes,
        "mysql",
        "mysql.tables",
        before.mysql.as_ref().map(|policy| &policy.tables),
        after.mysql.as_ref().map(|policy| &policy.tables),
        false,
        replace.contains("mysql"),
    );
    section(
        &mut changes,
        "redis",
        "redis.keys",
        before.redis.as_ref().map(redis_entries).as_ref(),
        after.redis.as_ref().map(redis_entries).as_ref(),
        false,
        replace.contains("redis"),
    );
    section(
        &mut changes,
        "http",
        "http.headers",
        before.http.as_ref().map(|policy| &policy.headers),
        after.http.as_ref().map(|policy| &policy.headers),
        false,
        replace.contains("http"),
    );
    section(
        &mut changes,
        "http.requests",
        "http.requests",
        http_request_entries(before).as_ref(),
        http_request_entries(after).as_ref(),
        false,
        replace.contains("http"),
    );
    section(
        &mut changes,
        "async_api",
        "async_api",
        before.async_api.as_ref(),
        after.async_api.as_ref(),
        false,
        replace.contains("async_api"),
    );
    for (name, old, new) in [
        (
            "json",
            before.json.as_ref().map(|policy| &policy.fields),
            after.json.as_ref().map(|policy| &policy.fields),
        ),
        (
            "redis",
            before.redis.as_ref().map(|policy| &policy.keys),
            after.redis.as_ref().map(|policy| &policy.keys),
        ),
        (
            "http",
            before.http.as_ref().map(|policy| &policy.headers),
            after.http.as_ref().map(|policy| &policy.headers),
        ),
    ] {
        if let Some(change) = changes.get_mut(name) {
            change["added_formats"] = added_formats(
                old.into_iter()
                    .flat_map(BTreeMap::iter)
                    .map(|(name, field)| (name.clone(), field))
                    .collect(),
                new.into_iter()
                    .flat_map(BTreeMap::iter)
                    .map(|(name, field)| (name.clone(), field))
                    .collect(),
            );
        }
    }
    if let Some(change) = changes.get_mut("mysql") {
        change["added_formats"] = added_formats(
            mysql_fields(before.mysql.as_ref()),
            mysql_fields(after.mysql.as_ref()),
        );
    }
    if let Some(change) = changes.get_mut("redis") {
        let added = added_formats(redis_key_fields(before), redis_key_fields(after));
        if added.as_object().is_some_and(|formats| !formats.is_empty()) {
            change["added_key_formats"] = added;
        }
    }
    Value::Object(changes)
}

fn http_request_entries(policy: &TrafficPolicy) -> Option<BTreeMap<String, ()>> {
    let http = policy
        .http
        .as_ref()
        .filter(|http| !http.request_sigv4.is_empty())?;
    Some(
        http.request_sigv4
            .iter()
            .map(|rule| {
                (
                    http_request_selector(
                        &rule.host,
                        rule.method.as_deref(),
                        rule.path.as_deref(),
                        rule.query.as_deref(),
                    ),
                    (),
                )
            })
            .collect(),
    )
}

fn redis_key_fields(policy: &TrafficPolicy) -> BTreeMap<String, &GlobalField> {
    policy
        .redis
        .iter()
        .flat_map(|redis| &redis.key_identities)
        .map(|(pattern, field)| (pattern.clone(), field))
        .collect()
}

fn redis_entries(
    policy: &crate::policy::RedisPolicy,
) -> BTreeMap<String, (Option<&GlobalField>, Option<&GlobalField>)> {
    let mut entries = BTreeMap::new();
    for (pattern, field) in &policy.keys {
        entries.entry(pattern.clone()).or_insert((None, None)).0 = Some(field);
    }
    for (pattern, field) in &policy.key_identities {
        entries.entry(pattern.clone()).or_insert((None, None)).1 = Some(field);
    }
    entries
}

fn mysql_fields(policy: Option<&crate::policy::MysqlPolicy>) -> BTreeMap<String, &GlobalField> {
    policy
        .into_iter()
        .flat_map(|policy| &policy.tables)
        .flat_map(|(table, definition)| {
            definition
                .fields
                .iter()
                .map(move |(column, field)| (format!("{table}.{column}"), field))
        })
        .collect()
}

fn added_formats(
    before: BTreeMap<String, &GlobalField>,
    after: BTreeMap<String, &GlobalField>,
) -> Value {
    let mut added = Map::new();
    for (name, field) in after {
        let Some(previous) = before.get(&name) else {
            continue;
        };
        let (Ok(previous), Ok(current)) =
            (serde_json::to_value(previous), serde_json::to_value(field))
        else {
            continue;
        };
        if previous["kind"] != current["kind"] {
            continue;
        }
        if let (Some(old), Some(new)) = (
            previous["formats"].as_array(),
            current["formats"].as_array(),
        ) {
            let mut formats = vec![];
            for format in new {
                if !old.contains(format) && !formats.contains(format) {
                    formats.push(format.clone());
                }
            }
            if !formats.is_empty() {
                added.insert(name, json!(formats));
            }
        }
    }
    Value::Object(added)
}

fn section<T: PartialEq>(
    changes: &mut Map<String, Value>,
    name: &str,
    location: &str,
    before: Option<&BTreeMap<String, T>>,
    after: Option<&BTreeMap<String, T>>,
    fields: bool,
    replace: bool,
) {
    if before == after {
        return;
    }
    let added = after
        .into_iter()
        .flat_map(BTreeMap::keys)
        .filter(|key| !before.is_some_and(|entries| entries.contains_key(*key)))
        .collect::<Vec<_>>();
    let changed = after
        .into_iter()
        .flat_map(BTreeMap::iter)
        .filter(|(key, value)| {
            before
                .and_then(|entries| entries.get(*key))
                .is_some_and(|previous| previous != *value)
        })
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    let removed = before
        .into_iter()
        .flat_map(BTreeMap::keys)
        .filter(|key| !after.is_some_and(|entries| entries.contains_key(*key)))
        .collect::<Vec<_>>();
    let mut change = json!({"mode":if replace { "replace" } else { "add" }, "location":location,
        "present_before":before.is_some(), "present_after":after.is_some()});
    let (added_key, changed_key, removed_key) = if fields {
        ("added_fields", "changed_fields", "removed_fields")
    } else {
        ("added_entries", "changed_entries", "removed_entries")
    };
    change[added_key] = json!(added);
    change[changed_key] = json!(changed);
    change[removed_key] = json!(removed);
    changes.insert(name.into(), change);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(value: Value) -> TrafficPolicy {
        crate::policy::parse_policy(&value.to_string()).unwrap()
    }

    #[test]
    fn reports_sigv4_route_selectors_with_the_exact_query() {
        let before = policy(json!({"format":"traffic-policy/v3"}));
        let after = policy(json!({"format":"traffic-policy/v3","http":{"requests":[{
            "host":"s3.example.test:9100","method":"GET","path":"/wegent-archives",
            "query":"location=","authorization":{"kind":"aws_sigv4"}
        }]}}));
        let changes = summarize(&before, &after, &BTreeSet::new());
        assert_eq!(
            changes["http.requests"]["added_entries"],
            json!(["GET s3.example.test:9100/wegent-archives?location="])
        );
    }

    #[test]
    fn reports_sigv4_host_selection_when_replacing_an_exact_route() {
        let before = policy(json!({"format":"traffic-policy/v3","http":{"requests":[{
            "host":"s3.example.test:9100","method":"HEAD","path":"/wegent-archives",
            "authorization":{"kind":"aws_sigv4"}
        }]}}));
        let after = policy(json!({"format":"traffic-policy/v3","http":{"requests":[{
            "host":"s3.example.test:9100","authorization":{"kind":"aws_sigv4"}
        }]}}));
        let changes = summarize(&before, &after, &BTreeSet::from(["http".into()]));
        assert_eq!(
            changes["http.requests"]["added_entries"],
            json!(["s3.example.test:9100"])
        );
        assert_eq!(
            changes["http.requests"]["removed_entries"],
            json!(["HEAD s3.example.test:9100/wegent-archives"])
        );
    }

    #[test]
    fn all_replaced_sections_report_only_changed_declaration_positions() {
        let before = policy(json!({"format":"traffic-policy/v3",
            "json":{"fields":{"/same":{"kind":"identity","formats":["uuid"]},"/old":{"kind":"unordered"},"/changed":{"kind":"time","formats":["unix_seconds"]}}},
            "mysql":{"tables":{"old":{"pattern":"old","fields":{"id":{"kind":"identity","formats":["decimal"]}}}}},
            "redis":{"keys":{"changed":{"kind":"identity","formats":["uuid"]},"old":{"kind":"identity","formats":["uuid"]}}},
            "http":{"headers":{"x-old":{"kind":"identity","formats":["uuid"]},"x-changed":{"kind":"time","formats":["unix_seconds"]}}}
        }));
        let after = policy(json!({"format":"traffic-policy/v3",
            "json":{"fields":{"/same":{"kind":"identity","formats":["uuid"]},"/new":{"kind":"unordered"},"/changed":{"kind":"time","formats":["unix_milliseconds"]}}},
            "mysql":{"tables":{"new":{"pattern":"new","fields":{"id":{"kind":"identity","formats":["decimal"]}}}}},
            "redis":{"keys":{"changed":{"kind":"identity","formats":["decimal"]},"new":{"kind":"identity","formats":["uuid"]}}},
            "http":{"headers":{"x-new":{"kind":"identity","formats":["uuid"]},"x-changed":{"kind":"time","formats":["unix_milliseconds"]}}}
        }));
        let replace =
            BTreeSet::from(["json".into(), "mysql".into(), "redis".into(), "http".into()]);
        let changes = summarize(&before, &after, &replace);
        assert_eq!(changes["json"]["added_fields"], json!(["/new"]));
        assert_eq!(changes["json"]["changed_fields"], json!(["/changed"]));
        assert_eq!(changes["json"]["removed_fields"], json!(["/old"]));
        for (section, added, changed, removed) in [
            ("mysql", json!(["new"]), json!([]), json!(["old"])),
            ("redis", json!(["new"]), json!(["changed"]), json!(["old"])),
            (
                "http",
                json!(["x-new"]),
                json!(["x-changed"]),
                json!(["x-old"]),
            ),
        ] {
            assert_eq!(changes[section]["mode"], "replace");
            assert_eq!(changes[section]["added_entries"], added);
            assert_eq!(changes[section]["changed_entries"], changed);
            assert_eq!(changes[section]["removed_entries"], removed);
        }
        assert_eq!(
            changes["json"]["added_formats"]["/changed"],
            json!(["unix_milliseconds"])
        );
        assert!(!changes.to_string().contains("\"fields\":"));
        assert_eq!(summarize(&before, &before, &replace), json!({}));
    }
}
