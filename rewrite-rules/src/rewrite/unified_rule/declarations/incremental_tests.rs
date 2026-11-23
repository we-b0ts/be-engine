use super::*;
use serde_json::{Value, json};

fn policy(value: Value) -> TrafficPolicy {
    crate::policy::parse_policy(&value.to_string()).unwrap()
}

#[test]
fn field_addition_and_json_replacement_preserve_project_time_settings() {
    let original = policy(json!({"format":"traffic-policy/v3",
        "time":{"default_utc_offset":"+05:30"},
        "json":{"fields":{"/created":{"kind":"time","formats":["rfc3339"]}}}}));
    let mut current = original.clone();
    let addition = policy(
        json!({"format":"traffic-policy/v3","json":{"fields":{"/items":{"kind":"unordered"}}}}),
    );
    merge(&mut current, &addition).unwrap();
    assert_eq!(current.time, original.time);
    let replacement = policy(json!({"format":"traffic-policy/v3","json":{"fields":{}}}));
    merge_with_replacements(&mut current, &replacement, &BTreeSet::from(["json".into()])).unwrap();
    assert_eq!(current.time, original.time);
    let rendered = crate::policy::render_policy(&current).unwrap();
    let reparsed = crate::policy::parse_policy(&rendered).unwrap();
    assert_eq!(reparsed.time, original.time);
    assert!(
        super::super::impact::affects_api(
            &crate::policy::render_policy(&original).unwrap(),
            &rendered,
            "GET /api"
        )
        .unwrap(),
        "removing a redundant declaration must retain the runtime revalidation obligation"
    );
}

#[test]
fn time_settings_change_only_through_explicit_replacement_and_are_not_source_permissions() {
    let mut current =
        policy(json!({"format":"traffic-policy/v3","time":{"default_utc_offset":"+05:30"}}));
    let replacement =
        policy(json!({"format":"traffic-policy/v3","time":{"default_utc_offset":"+09:00"}}));
    assert!(!merge(&mut current, &replacement).unwrap());
    assert_eq!(current.time.default_utc_offset, "+05:30");
    assert!(
        merge_with_replacements(&mut current, &replacement, &BTreeSet::from(["time".into()]))
            .unwrap()
    );
    assert_eq!(current.time.default_utc_offset, "+09:00");
    super::super::source_proof::SourceProofSnapshot::capture(&current).unwrap();
    assert!(current.rules.is_empty());
}

#[test]
fn formats_append_in_original_order_and_reapplication_is_a_noop() {
    for (first, addition, expected) in [
        (
            json!({"kind":"time","formats":["rfc3339"]}),
            json!({"kind":"time","formats":["unix_seconds","rfc3339","unix_seconds"]}),
            json!(["rfc3339", "unix_seconds"]),
        ),
        (
            json!({"kind":"identity","formats":["uuid"]}),
            json!({"kind":"identity","formats":["decimal","uuid","decimal"]}),
            json!(["uuid", "decimal"]),
        ),
        (
            json!({"kind":"template","formats":[{"template":"a-{id}","fields":{"id":"uuid"}}]}),
            json!({"kind":"template","formats":[{"template":"b-{id}","fields":{"id":"uuid"}}]}),
            json!([{"template":"a-{id}","fields":{"id":"uuid"}},{"template":"b-{id}","fields":{"id":"uuid"}}]),
        ),
    ] {
        let mut current = policy(
            json!({"format":"traffic-policy/v3","json":{"fields":{"/value":first,"/retained":{"kind":"unordered"}}}}),
        );
        let proposed =
            policy(json!({"format":"traffic-policy/v3","json":{"fields":{"/value":addition}}}));
        assert!(merge(&mut current, &proposed).unwrap());
        assert_eq!(
            serde_json::to_value(&current.json.as_ref().unwrap().fields["/value"]).unwrap()["formats"],
            expected
        );
        assert!(
            current
                .json
                .as_ref()
                .unwrap()
                .fields
                .contains_key("/retained")
        );
        assert!(!merge(&mut current, &proposed).unwrap());
    }
}

#[test]
fn additions_reuse_existing_single_protocol_format_limits() {
    for (kind, original, addition) in [
        ("url", "url", "aws_sigv4"),
        ("duration", "seconds", "milliseconds"),
    ] {
        let mut current = policy(json!({"format":"traffic-policy/v3","json":{"fields":{
            "/value":{"kind":kind,"formats":[original]}
        }}}));
        let same = current.clone();
        assert!(!merge(&mut current, &same).unwrap());
        let different = policy(json!({"format":"traffic-policy/v3","json":{"fields":{
            "/value":{"kind":kind,"formats":[addition]}
        }}}));
        assert!(merge(&mut current, &different).is_err());
        assert_eq!(current, same);
    }
}

#[test]
fn physical_carriers_add_formats_without_replacing_other_fields_or_native_permissions() {
    let mut current = policy(json!({"format":"traffic-policy/v3",
        "mysql":{"tables":{"tasks":{"pattern":"tasks_*","fields":{"ID":{"kind":"identity","formats":["decimal"]},"retained":{"kind":"time","formats":["unix_seconds"]}}}}},
        "redis":{
            "keys":{"id":{"kind":"identity","formats":["uuid"]}},
            "rules":[{"id":"background-scan","match":{},"effect":{"kind":"process_owned",
                "selector":{"protocol":"redis","ports":[6379],"operation":"HSCAN",
                    "keys":[{"kind":"exact","value":"inbox"}]}}}]
        },
        "http":{"headers":{"x-id":{"kind":"identity","formats":["uuid"]},"x-retained":{"kind":"time","formats":["unix_seconds"]}}}
    }));
    let original_rules = current.rules.clone();
    let proposed = policy(json!({"format":"traffic-policy/v3",
        "mysql":{"tables":{"tasks":{"pattern":"tasks_*","fields":{"id":{"kind":"identity","formats":["uuid"]}}}}},
        "redis":{"keys":{"id":{"kind":"identity","formats":["decimal"]}}},
        "http":{"headers":{"X-ID":{"kind":"identity","formats":["decimal"]}}}
    }));
    assert!(merge(&mut current, &proposed).unwrap());
    assert_eq!(
        current.rules, original_rules,
        "format additions must preserve native process ownership"
    );
    assert_eq!(
        current.mysql.as_ref().unwrap().tables["tasks"].fields.len(),
        2
    );
    assert!(
        current.mysql.as_ref().unwrap().tables["tasks"]
            .fields
            .contains_key("ID")
    );
    assert_eq!(
        serde_json::to_value(&current.mysql.as_ref().unwrap().tables["tasks"].fields["ID"])
            .unwrap()["formats"],
        json!(["decimal", "uuid"])
    );
    assert_eq!(
        serde_json::to_value(&current.redis.as_ref().unwrap().keys["id"]).unwrap()["formats"],
        json!(["uuid", "decimal"])
    );
    assert_eq!(
        serde_json::to_value(&current.http.as_ref().unwrap().headers["x-id"]).unwrap()["formats"],
        json!(["uuid", "decimal"])
    );
    assert!(
        current
            .http
            .as_ref()
            .unwrap()
            .headers
            .contains_key("x-retained")
    );
    assert!(!merge(&mut current, &proposed).unwrap());
}

#[test]
fn additive_conflicts_are_atomic_and_mysql_empty_presence_still_enables_native_inference() {
    let original = policy(json!({"format":"traffic-policy/v3",
        "json":{"fields":{"/id":{"kind":"identity","formats":["uuid"]}}},
        "mysql":{"tables":{"t":{"pattern":"tasks_*","fields":{"id":{"kind":"identity","formats":["decimal"]}}}}}
    }));
    for proposed in [
        policy(
            json!({"format":"traffic-policy/v3","json":{"fields":{"/id":{"kind":"time","formats":["unix_seconds"]}}}}),
        ),
        policy(
            json!({"format":"traffic-policy/v3","mysql":{"tables":{"t":{"pattern":"other_*","fields":{"id":{"kind":"identity","formats":["decimal"]}}}}}}),
        ),
    ] {
        let mut current = original.clone();
        assert!(merge(&mut current, &proposed).is_err());
        assert_eq!(current, original);
    }
    let mut current = TrafficPolicy::default();
    let empty = policy(json!({"format":"traffic-policy/v3","mysql":{}}));
    assert!(merge(&mut current, &empty).unwrap());
    assert!(
        crate::policy::compile_policy(&current)
            .unwrap()
            .mysql
            .is_some()
    );
    assert!(!merge(&mut current, &empty).unwrap());
    let mut current = original.clone();
    assert!(!merge(&mut current, &empty).unwrap());
    assert_eq!(current, original);
}

#[test]
fn async_api_additions_keep_existing_completion_contracts() {
    let declaration = |api: &str, key: &str| {
        policy(
            json!({"format":"traffic-policy/v3","recording":{"async_api":{
                api:{"when":{"/background":true},"end":[{"redis":{"operation":"DEL","key":key}}]}
            }}}),
        )
    };
    let mut current = declaration("POST /one", "one");
    assert!(merge(&mut current, &declaration("POST /two", "two")).unwrap());
    assert_eq!(current.async_api.as_ref().unwrap().len(), 2);
    assert!(!merge(&mut current, &declaration("POST /one", "one")).unwrap());
    let before = current.clone();
    assert!(merge(&mut current, &declaration("POST /one", "changed")).is_err());
    assert_eq!(current, before);
}
