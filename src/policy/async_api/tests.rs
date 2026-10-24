use super::*;
use crate::policy::{compile_policy, parse_policy, render_policy};

const POLICY: &str = "format: traffic-policy/v2\nmysql: {database: task_manager}\nredis: {database: 3}\nasync_api:\n  'POST /api/v1/responses':\n    when: {'/background': true}\n    end:\n      - redis: {operation: del, key: 'chat:cancel:*', occurrence: 2}\n      - mysql: {sql: 'UPDATE tasks SET status = ? WHERE id = ?'}\n";

#[test]
fn completion_formats_roundtrip_inherit_databases_and_refresh_capture_and_replay_identity() {
    let document = parse_policy(POLICY).unwrap();
    let compiled = compile_policy(&document).unwrap();
    let rule = &compiled.async_api["POST /api/v1/responses"];
    let AsyncEnd::Redis(redis) = &rule.end[0] else {
        panic!("Redis end")
    };
    assert_eq!(
        (redis.operation.as_str(), redis.database, redis.occurrence),
        ("DEL", Some(3), 2)
    );
    let AsyncEnd::Mysql(mysql) = &rule.end[1] else {
        panic!("MySQL end")
    };
    assert_eq!(mysql.database.as_deref(), Some("task_manager"));
    let rendered = render_policy(&document).unwrap();
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap()).unwrap(),
        compiled
    );
    // Authoring retains omitted databases: subsequent root scope edits inherit.
    assert!(
        document.async_api.as_ref().unwrap()["POST /api/v1/responses"]
            .end
            .iter()
            .all(|end| match end {
                AsyncEnd::Mysql(end) => end.database.is_none(),
                AsyncEnd::Redis(end) => end.database.is_none(),
            })
    );
    let changed =
        compile_policy(&parse_policy(&POLICY.replace("occurrence: 2", "occurrence: 3")).unwrap())
            .unwrap();
    assert_ne!(compiled.fingerprints.full, changed.fingerprints.full);
    assert_ne!(compiled.fingerprints.capture, changed.fingerprints.capture);
    assert_ne!(compiled.fingerprints.runtime, changed.fingerprints.runtime);
    let source = crate::config::SourceTrafficPolicyConfig::parse(
        POLICY,
        std::path::Path::new("policy.yaml"),
    )
    .unwrap();
    assert_eq!(source.async_api, compiled.async_api);
    let mut config = crate::AppConfig::default();
    source.apply_to(&mut config).unwrap();
    assert_eq!(config.async_api, compiled.async_api);
}

#[test]
fn redis_default_occurrence_is_one_and_empty_async_map_clears_without_capture_permission() {
    let raw = POLICY.replace(", occurrence: 2", "");
    let document = parse_policy(&raw).unwrap();
    let AsyncEnd::Redis(end) =
        &document.async_api.as_ref().unwrap()["POST /api/v1/responses"].end[0]
    else {
        panic!("Redis end")
    };
    assert_eq!(end.occurrence, 1);
    assert!(!render_policy(&document).unwrap().contains("occurrence:"));
    let empty =
        compile_policy(&parse_policy("format: traffic-policy/v2\nasync_api: {}\n").unwrap())
            .unwrap();
    let absent = compile_policy(&parse_policy("format: traffic-policy/v2\n").unwrap()).unwrap();
    assert!(empty.async_api.is_empty());
    assert_eq!(empty.fingerprints.capture, absent.fingerprints.capture);
}

#[test]
fn body_conditions_are_exact_literals_and_missing_is_distinct_from_null() {
    let document = parse_policy(POLICY).unwrap();
    let rule = &document.async_api.as_ref().unwrap()["POST /api/v1/responses"];
    let matches = |body: Value| {
        async_api_matches(
            "POST /api/v1/responses",
            rule,
            "POST",
            "/api/v1/responses?x=1",
            Some(&body),
        )
    };
    assert!(matches(serde_json::json!({"background":true})));
    for body in [
        serde_json::json!({}),
        serde_json::json!({"background":false}),
        serde_json::json!({"background":"true"}),
        serde_json::json!({"background":null}),
    ] {
        assert!(!matches(body));
    }
}

#[test]
fn invalid_or_ambiguous_lifecycle_descriptions_are_rejected() {
    for invalid in [
        POLICY.replace("occurrence: 2", "occurrence: 0"),
        POLICY.replace("occurrence: 2", "occurrence: 1025"),
        POLICY.replace("chat:cancel:*", "chat:*:*"),
        POLICY.replace("'/background': true", "'/*': true"),
        POLICY.replace("'/background': true", "'/background': [true]"),
        POLICY.replace(
            "'/background': true",
            "'/background': true, '/background': false",
        ),
        POLICY.replace(
            "sql: 'UPDATE tasks SET status = ? WHERE id = ?'",
            "sql: 'UPDATE ? SET status = ?'",
        ),
        POLICY.replace("when:", "timeout: 200\n    when:"),
        POLICY.replace("when:", "failure: false\n    when:"),
        POLICY.replace(
            "redis: {operation: del, key: 'chat:cancel:*', occurrence: 2}",
            "redis: {operation: del, key: 'chat:cancel:*'}, mysql: {sql: 'SELECT 1'}",
        ),
        POLICY.replace("redis: {operation:", "unknown: {operation:"),
    ] {
        assert!(
            parse_policy(&invalid)
                .and_then(|document| compile_policy(&document))
                .is_err(),
            "accepted {invalid}"
        );
    }
}
