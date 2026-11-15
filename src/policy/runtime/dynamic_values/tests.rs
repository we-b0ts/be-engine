use super::*;
use crate::policy::runtime::matcher::MysqlPolicyContext;
use crate::protocols::replay::mysql::ReplaySessionIdentity;
use serde_json::json;

fn endpoint(port: u16) -> TargetKey {
    TargetKey {
        host: "service.test".into(),
        port,
    }
}
fn rule() -> DynamicValueRule {
    serde_json::from_value(json!({"id":"generated-name", "api":"/items", "targets":[{"host":"service.test","port":3306},{"host":"service.test","port":6379},{"host":"service.test","port":80}],
        "capture":{"protocol":"mysql","target":{"host":"service.test","port":3306},"database":"app", "sql":"SELECT id FROM kinds WHERE name=? AND user_id=?", "value_index":0},
        "source_evidence":"NameFactory:create generates a fresh random identity"})).unwrap()
}
fn runtime() -> DynamicValues {
    DynamicValues::new(
        vec![rule()],
        BTreeMap::from([
            ("case".into(), "/items".into()),
            ("other".into(), "/items".into()),
        ]),
    )
}
fn capture(runtime: &DynamicValues, source: &str, target: &str) -> Result<DynamicDecision> {
    let identity = ReplaySessionIdentity {
        target: Some(endpoint(3306)),
        database: Some("app".into()),
        username: Some("user".into()),
    };
    let source_sql = format!("SELECT id FROM kinds WHERE name='{source}' AND user_id=1");
    let target_sql = format!("SELECT id FROM kinds WHERE name='{target}' AND user_id=1");
    Ok(runtime
        .mysql(&MysqlPolicyContext {
            request_times: Default::default(),
            case_id: Some("case"),
            identity: &identity,
            command: "COM_QUERY",
            recorded_sql: Some(&source_sql),
            sql: Some(&target_sql),
            recorded: None,
            actual: None,
        })
        .unwrap()?
        .decision)
}

#[test]
fn a_single_capture_authorizes_sql_json_and_redis_references_without_a_format() {
    let runtime = runtime();
    let decision = capture(&runtime, "old-name", "new-name").unwrap();
    let source = vec![
        b"prefix:old-name".to_vec(),
        br#"{"metadata":{"name":"old-name"},"count":1}"#.to_vec(),
    ];
    let actual = vec![
        b"prefix:new-name".to_vec(),
        br#"{"count":1,"metadata":{"name":"new-name"}}"#.to_vec(),
    ];
    assert!(
        runtime
            .normalize_arguments(Some("case"), &endpoint(6379), &source, &actual)
            .is_none()
    );
    runtime.commit("case", decision).unwrap();
    let (source, actual) = runtime
        .normalize_arguments(Some("case"), &endpoint(6379), &source, &actual)
        .unwrap()
        .unwrap();
    assert_eq!(source, actual);
    let identity = ReplaySessionIdentity {
        target: Some(endpoint(3306)),
        database: Some("app".into()),
        username: None,
    };
    let source_sql = "INSERT INTO kinds(name,json) VALUES('old-name','{\"名称\":\"中文\",\"name\":\"old-name\"}')";
    let actual_sql = "INSERT INTO kinds(name,json) VALUES(?,?)";
    let params = vec![
        crate::protocols::replay::mysql::RecordedMysqlValue {
            kind: "string".into(),
            value: Some(json!("new-name")),
            raw: None,
        },
        crate::protocols::replay::mysql::RecordedMysqlValue {
            kind: "string".into(),
            value: Some(json!(r#"{"name":"new-name","名称":"中文"}"#)),
            raw: None,
        },
    ];
    let normalized = runtime
        .mysql(&MysqlPolicyContext {
            request_times: Default::default(),
            case_id: Some("case"),
            identity: &identity,
            command: "COM_STMT_EXECUTE",
            recorded_sql: Some(source_sql),
            sql: Some(actual_sql),
            recorded: None,
            actual: Some(&params),
        })
        .unwrap()
        .unwrap();
    let source_tokens = crate::protocols::replay::mysql::sql_match::materialize(
        normalized.source_sql.as_deref().unwrap(),
        &[],
    )
    .unwrap();
    let target_tokens = crate::protocols::replay::mysql::sql_match::materialize(
        normalized.actual_sql.as_deref().unwrap(),
        normalized.actual_params.as_deref().unwrap(),
    )
    .unwrap();
    assert_eq!(source_tokens, target_tokens);
}

#[test]
fn mappings_do_not_leak_to_other_cases_ports_or_global_dependencies() {
    let runtime = runtime();
    runtime
        .commit("case", capture(&runtime, "old-name", "new-name").unwrap())
        .unwrap();
    let source = vec![b"old-name".to_vec()];
    let actual = vec![b"new-name".to_vec()];
    assert!(
        runtime
            .normalize_arguments(Some("other"), &endpoint(6379), &source, &actual)
            .is_none()
    );
    assert!(
        runtime
            .normalize_arguments(Some("case"), &endpoint(6380), &source, &actual)
            .is_none()
    );
    assert!(
        runtime
            .normalize_arguments(None, &endpoint(6379), &source, &actual)
            .is_none()
    );
    runtime.begin_case("case");
    assert!(
        runtime
            .normalize_arguments(Some("case"), &endpoint(6379), &source, &actual)
            .is_none()
    );
}

#[test]
fn identity_changes_collapses_and_stable_key_changes_remain_failures() {
    let runtime = runtime();
    runtime
        .commit("case", capture(&runtime, "old-name", "new-name").unwrap())
        .unwrap();
    assert!(capture(&runtime, "old-name", "third-name").is_err());
    assert!(capture(&runtime, "different-name", "new-name").is_err());
    assert!(
        runtime
            .normalize_arguments(
                Some("case"),
                &endpoint(6379),
                &[b"prefix:old-name".to_vec()],
                &[b"prefix:old-name".to_vec()]
            )
            .unwrap()
            .is_err()
    );
    let (source, actual) = runtime
        .normalize_arguments(
            Some("case"),
            &endpoint(6379),
            &[b"prefix:old-name".to_vec()],
            &[b"wrong:new-name".to_vec()],
        )
        .unwrap()
        .unwrap();
    assert_ne!(source, actual);
    assert!(
        runtime
            .normalize_arguments(
                Some("case"),
                &endpoint(6379),
                &[br#"{"name":"old-name"}"#.to_vec()],
                &[br#"{"name":"wrong","name":"new-name"}"#.to_vec()]
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn http_paths_queries_and_json_share_the_case_binding() {
    let runtime = runtime();
    runtime
        .commit("case", capture(&runtime, "old-name", "new-name").unwrap())
        .unwrap();
    let actual_uri: hyper::Uri = "/items/new-name?name=new%2Dname&stable=1".parse().unwrap();
    let normalized = runtime
        .http(
            Some("case"),
            &endpoint(80),
            "POST",
            HttpInput {
                request_started_at: None,
                uri: "/items/old-name?name=old-name&stable=1",
                body: br#"{"name":"old-name"}"#,
            },
            HttpInput {
                request_started_at: None,
                uri: &actual_uri.to_string(),
                body: br#"{"name":"new-name"}"#,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(normalized.source_uri, normalized.actual_uri.to_string());
    assert_eq!(normalized.source_body, normalized.actual_body);
}

#[test]
fn rule_scope_and_optional_uuid_shape_are_validated() {
    rule().validate().unwrap();
    let mut invalid = rule();
    invalid.targets[0].port = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = rule();
    invalid.source_evidence.clear();
    assert!(invalid.validate().is_ok());
    let mut invalid = rule();
    invalid.format = Some(DynamicValueFormat::Uuid);
    assert!(invalid.validate_value("opaque-name").is_err());
}

#[test]
fn redis_hset_json_capture_preserves_other_fields_and_database() {
    let mut rule = rule();
    rule.capture = serde_json::from_value(json!({"protocol":"redis","target":{"host":"service.test","port":6379},"database":2,"command":"HSET","key":"anchor","argument_index":2,"json_pointer":"/name"})).unwrap();
    rule.validate().unwrap();
    let runtime = DynamicValues::new(
        vec![rule],
        BTreeMap::from([("case".into(), "/items".into())]),
    );
    let left = vec![
        b"anchor".to_vec(),
        b"field".to_vec(),
        br#"{"name":"old-name","stable":1}"#.to_vec(),
    ];
    let right = vec![
        b"anchor".to_vec(),
        b"field".to_vec(),
        br#"{"stable":1,"name":"new-name"}"#.to_vec(),
    ];
    assert!(
        runtime
            .redis(Some("case"), &endpoint(6379), 0, "HSET", &left, &right)
            .is_none()
    );
    let normalized = runtime
        .redis(Some("case"), &endpoint(6379), 2, "HSET", &left, &right)
        .unwrap()
        .unwrap();
    assert_eq!(normalized.source, normalized.actual);
    runtime.commit("case", normalized.decision).unwrap();
    let wrong = vec![
        b"anchor".to_vec(),
        b"field".to_vec(),
        br#"{"stable":2,"name":"new-name"}"#.to_vec(),
    ];
    let normalized = runtime
        .redis(Some("case"), &endpoint(6379), 2, "HSET", &left, &wrong)
        .unwrap()
        .unwrap();
    assert_ne!(normalized.source, normalized.actual);
}

#[test]
fn redis_and_http_audits_restore_only_proven_same_case_sql_references() {
    use crate::mysql::sql::Token;
    use crate::policy::runtime::config::fingerprint;
    for protocol in ["redis", "http"] {
        let mut rule = rule();
        let event = if protocol == "redis" {
            rule.capture = serde_json::from_value(json!({"protocol":"redis","target":{"host":"service.test","port":6379},"database":0,"command":"SET","key":"anchor","argument_index":1})).unwrap();
            json!({"event_type":"redis_exchange","target_host":"service.test","target_port":6379,"database":0,"command":"SET","replay_safe":true,"args":[{"encoding":"utf8","data":"anchor"},{"encoding":"utf8","data":"old-name"}],"response":{"encoding":"utf8","data":"+OK\r\n"}})
        } else {
            rule.capture = serde_json::from_value(json!({"protocol":"http","target":{"host":"service.test","port":80},"method":"POST","path":"/create","json_pointer":"/name"})).unwrap();
            json!({"event_type":"http_exchange","scheme":"http","uri":"http://service.test/create","method":"POST","response_status":200,"request_body":{"encoding":"utf8","data":"{\"name\":\"old-name\"}"},"response_body":{"encoding":"utf8","data":"{}"}})
        };
        rule.validate().unwrap();
        let bytes = serde_json::to_vec(&event).unwrap();
        let runtime = DynamicValues::new(
            vec![rule.clone()],
            BTreeMap::from([("case".into(), "/items".into())]),
        );
        runtime.observe_source("case", &bytes).unwrap();
        assert!(runtime.rule_reports()[0].applicable);
        assert_eq!(runtime.rule_reports()[0].matches, 0);
        let mut report = json!({"replay_policy":{"dynamic_bindings":[{"case_id":"case","rule_id":rule.id,"source_fingerprint":fingerprint(b"old-name"),"target_fingerprint":fingerprint(b"new-name")}]}});
        let left = vec![Token::Bytes(b"prefix:old-name".to_vec())];
        let right = vec![Token::Bytes(b"prefix:new-name".to_vec())];
        let restored = from_report(
            &[rule.clone()],
            &report,
            "case",
            &json!({"uri":"/items"}),
            &bytes,
            &left,
            &right,
        )
        .unwrap();
        let (source, actual) = restored
            .normalize_arguments(
                Some("case"),
                &endpoint(3306),
                &[b"old-name".to_vec()],
                &[b"new-name".to_vec()],
            )
            .unwrap()
            .unwrap();
        assert_eq!(source, actual);
        assert!(
            from_report(
                &[rule.clone()],
                &report,
                "case",
                &json!({"uri":"/other"}),
                &bytes,
                &left,
                &right
            )
            .is_err()
        );
        report["replay_policy"]["dynamic_bindings"][0]["target_fingerprint"] = json!("forged");
        assert!(
            from_report(
                &[rule],
                &report,
                "case",
                &json!({"uri":"/items"}),
                &bytes,
                &left,
                &right
            )
            .is_err()
        );
    }
}

#[test]
fn integer_http_identity_preserves_type_and_only_normalizes_the_declared_pointer() {
    let rule: DynamicValueRule = serde_json::from_value(json!({"id":"rpc-id","api":"/items","value_type":"integer","targets":[{"host":"service.test","port":80}],"capture":{"protocol":"http","target":{"host":"service.test","port":80},"method":"POST","path":"/rpc","json_pointer":"/id"},"source_evidence":"RpcClient:counter generates an integer correlation id"})).unwrap();
    rule.validate().unwrap();
    let runtime = DynamicValues::new(
        vec![rule],
        BTreeMap::from([("case".into(), "/items".into())]),
    );
    let source = br#"{"id":10,"business_id":10,"text":"10","method":"list"}"#;
    let actual = br#"{"id":20,"business_id":10,"text":"10","method":"list"}"#;
    let compare = |actual: &[u8]| {
        runtime
            .http(
                Some("case"),
                &endpoint(80),
                "POST",
                HttpInput {
                    request_started_at: None,
                    uri: "/rpc",
                    body: source,
                },
                HttpInput {
                    request_started_at: None,
                    uri: "/rpc",
                    body: actual,
                },
            )
            .unwrap()
    };
    let normalized = compare(actual).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&normalized.source_body).unwrap(),
        serde_json::from_slice::<serde_json::Value>(&normalized.actual_body).unwrap()
    );
    runtime.commit("case", normalized.decision).unwrap();
    let normalized = compare(br#"{"id":20,"business_id":20,"text":"20","method":"list"}"#).unwrap();
    assert_ne!(
        serde_json::from_slice::<serde_json::Value>(&normalized.source_body).unwrap(),
        serde_json::from_slice::<serde_json::Value>(&normalized.actual_body).unwrap()
    );
    assert!(compare(br#"{"id":"20","business_id":10,"text":"10","method":"list"}"#).is_err());
    assert!(compare(br#"{"id":20.0,"business_id":10,"text":"10","method":"list"}"#).is_err());
    assert!(compare(br#"{"id":21,"business_id":10,"text":"10","method":"list"}"#).is_err());
    runtime.observe_http("case", &endpoint(80), "POST", "/rpc", source, actual);
    assert_eq!(
        runtime.capture_candidates()[0].value_type,
        DynamicValueType::Integer
    );
}
