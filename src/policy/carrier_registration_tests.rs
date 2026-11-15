//! One registered value implementation reaches each existing native scalar carrier.
use super::*;
use crate::value_contract::{http_headers, redis_scalar};
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn the_same_registered_policy_compares_http_redis_and_mysql_values() {
    let field = json!({
        "kind":"policy", "id":"unordered-joined-string", "version":1,
        "options":{"separator":","}
    });
    let policy = parse_and_compile_policy(
        &json!({
            "format":"traffic-policy/v3",
            "http":{"headers":{"x-values":field}},
            "redis":{"keys":{"values":field}},
            "mysql":{"tables":{"items":{"pattern":"items","fields":{"value":field}}}}
        })
        .to_string(),
    )
    .unwrap();
    let source = "red,blue,red";
    for (target, passes) in [("red,red,blue", true), ("red,blue", false)] {
        let headers = |value: &str| BTreeMap::from([("x-values".into(), vec![value.to_owned()])]);
        let http = http_headers::compare(
            &headers(source),
            &headers(target),
            policy.http.as_ref().unwrap(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(http.passed(), passes, "HTTP {http:?}");
        let redis = redis_scalar::compare(
            source.as_bytes(),
            target.as_bytes(),
            policy
                .redis
                .as_ref()
                .unwrap()
                .field(b"values")
                .unwrap()
                .unwrap(),
            &policy.global_json.as_ref().unwrap().time,
            Default::default(),
            &[],
        )
        .unwrap();
        assert_eq!(redis.passed(), passes, "Redis {redis:?}");
        let response = |value: &str| {
            serde_json::from_value(json!({
                "status":"resultset", "columns":[{
                    "name":"value", "database":"app", "table":"items", "column":"value",
                    "family":"string", "sql_type":"VARCHAR"
                }], "rows":[[{"kind":"string", "value":value}]], "rows_truncated":false
            }))
            .unwrap()
        };
        let mysql = crate::protocols::replay::mysql::contracts::automatic::compare_response(
            &policy,
            &response(source),
            &response(target),
            Some("SELECT value FROM items"),
            Some("app"),
            Default::default(),
        )
        .unwrap();
        assert_eq!(mysql.passed(), passes, "MySQL {mysql:?}");
    }
}
