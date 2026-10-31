use super::*;
use crate::policy::{compile_policy, parse_policy, render_policy};

const POLICY: &str = "format: traffic-policy/v3\nasync_api:\n  'POST /api/v1/responses':\n    when: {'/background': true}\n    end:\n      - redis: {operation: del, key: 'chat:cancel:*', occurrence: 2, database: 3}\n      - mysql: {sql: 'UPDATE tasks SET status = ? WHERE id = ?', database: task_manager}\n";

#[test]
fn completion_formats_preserve_explicit_databases_and_refresh_capture_and_replay_identity() {
    let document = parse_policy(POLICY).unwrap();
    let compiled = compile_policy(&document).unwrap();
    let rule = &compiled.async_api["POST /api/v1/responses"][0];
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
    let without_databases = POLICY
        .replace(", database: 3", "")
        .replace(", database: task_manager", "");
    let unscoped = compile_policy(&parse_policy(&without_databases).unwrap()).unwrap();
    assert!(
        unscoped.async_api["POST /api/v1/responses"][0]
            .end
            .iter()
            .all(|end| match end {
                AsyncEnd::Mysql(end) => end.database.is_none(),
                AsyncEnd::Redis(end) => end.database.is_none(),
                AsyncEnd::Http(_) => false,
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
        &document.async_api.as_ref().unwrap()["POST /api/v1/responses"][0].end[0]
    else {
        panic!("Redis end")
    };
    assert_eq!(end.occurrence, 1);
    assert!(!render_policy(&document).unwrap().contains("occurrence:"));
    let empty =
        compile_policy(&parse_policy("format: traffic-policy/v3\nasync_api: {}\n").unwrap())
            .unwrap();
    let absent = compile_policy(&parse_policy("format: traffic-policy/v3\n").unwrap()).unwrap();
    assert!(empty.async_api.is_empty());
    assert_eq!(empty.fingerprints.capture, absent.fingerprints.capture);
}

#[test]
fn body_conditions_are_exact_literals_and_missing_is_distinct_from_null() {
    let document = parse_policy(POLICY).unwrap();
    let rule = &document.async_api.as_ref().unwrap()["POST /api/v1/responses"][0];
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
            "redis: {operation: del, key: 'chat:cancel:*', occurrence: 2, database: 3}",
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

#[test]
fn ordered_response_scenarios_roundtrip_and_preserve_legacy_identity() {
    let legacy = compile_policy(&parse_policy(POLICY).unwrap()).unwrap();
    let mut array = parse_policy(POLICY).unwrap();
    let rendered = render_policy(&array).unwrap();
    assert!(rendered.contains("- when:"));
    assert_eq!(
        legacy,
        compile_policy(&parse_policy(&rendered).unwrap()).unwrap()
    );
    let rules = &mut array
        .async_api
        .as_mut()
        .unwrap()
        .get_mut("POST /api/v1/responses")
        .unwrap()
        .0;
    rules.insert(0, serde_json::from_value(serde_json::json!({
        "when_response":{"/status":"queued"},"unless_response":{"/is_latest":true},
        "end":[{"http":{"method":"post","endpoint":"executor.test:80","path":"/submit","status_codes":[202,200,202]}}]
    })).unwrap());
    let compiled = compile_policy(&array).unwrap();
    let rules = &compiled.async_api["POST /api/v1/responses"];
    let AsyncEnd::Http(end) = &rules[0].end[0] else {
        panic!("HTTP end")
    };
    assert_eq!(end.method, "POST");
    assert_eq!(end.status_codes, [200, 202]);
    assert_eq!(
        compile_policy(&parse_policy(&render_policy(&array).unwrap()).unwrap()).unwrap(),
        compiled
    );
    assert_ne!(compiled.fingerprints.capture, legacy.fingerprints.capture);
    array
        .async_api
        .as_mut()
        .unwrap()
        .get_mut("POST /api/v1/responses")
        .unwrap()
        .0
        .reverse();
    assert_ne!(
        compile_policy(&array).unwrap().fingerprints.capture,
        compiled.fingerprints.capture
    );
}

#[test]
fn response_conditions_and_exclusions_use_exact_observed_literals() {
    let rule: AsyncApiRule = serde_json::from_value(serde_json::json!({
        "when_response":{"/status":"queued"},"unless_response":{"/is_latest":true},"end":[]
    }))
    .unwrap();
    for (body, expected) in [
        (serde_json::json!({"status":"queued"}), true),
        (
            serde_json::json!({"status":"queued","is_latest":false}),
            true,
        ),
        (
            serde_json::json!({"status":"queued","is_latest":true}),
            false,
        ),
        (serde_json::json!({"status":"in_progress"}), false),
        (serde_json::json!({}), false),
    ] {
        assert_eq!(async_response_matches(&rule, Some(&body)), expected);
    }
    assert!(!async_response_matches(&rule, None));
    let null_rule = AsyncApiRule {
        when_response: BTreeMap::from([("/status".into(), Value::Null)]),
        ..Default::default()
    };
    assert!(async_response_matches(
        &null_rule,
        Some(&serde_json::json!({"status":null}))
    ));
    assert!(!async_response_matches(
        &null_rule,
        Some(&serde_json::json!({}))
    ));
}

#[test]
fn invalid_scenario_arrays_and_http_terminals_are_rejected() {
    let valid = serde_json::json!({"when_response":{"/status":"queued"},"end":[{
        "http":{"method":"POST","endpoint":"executor.test:80","path":"/submit"}
    }]});
    let mut invalid = Vec::new();
    for (pointer, value) in [
        ("/end/0/http/method", serde_json::json!("bad method")),
        ("/end/0/http/endpoint", serde_json::json!("executor.test:0")),
        (
            "/end/0/http/path",
            serde_json::json!("http://executor.test/submit"),
        ),
        ("/end/0/http/path", serde_json::json!("/submit?x=1")),
        ("/end/0/http/status_codes", serde_json::json!([500])),
        ("/when_response", serde_json::json!({"/status": ["queued"]})),
    ] {
        let mut rule = valid.clone();
        if pointer.ends_with("status_codes") {
            rule["end"][0]["http"]["status_codes"] = value;
        } else {
            *rule.pointer_mut(pointer).unwrap() = value;
        }
        invalid.push(serde_json::json!([rule]));
    }
    invalid.extend([serde_json::json!([]), Value::Array(vec![valid; 33])]);
    for value in invalid {
        let result = serde_json::from_value::<AsyncApiRules>(value)
            .map_err(anyhow::Error::from)
            .and_then(|rules| compile_async_api(&BTreeMap::from([("POST /jobs".into(), rules)])));
        assert!(result.is_err());
    }
}
