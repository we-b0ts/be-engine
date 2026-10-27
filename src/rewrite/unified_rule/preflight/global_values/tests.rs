use super::*;
use serde_json::json;
mod multipart;
mod provenance;
mod script_times;

#[test]
fn global_format_trace_failure_identifies_original_record_without_payloads() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("dependencies.jsonl");
    let event = json!({"event_type":"mysql_exchange","connection_id":"source-connection","query_sequence":7,"payload":"private-payload"});
    fs::write(&path, format!("\n{event}\n")).unwrap();
    let error = visit(&path, |_| anyhow::bail!("global format contract failed")).unwrap_err();
    let error = format!("{error:#}");
    for expected in [
        "record=2",
        "event_type=mysql_exchange",
        "connection_id=source-connection",
        "sequence=7",
        "global format contract failed",
    ] {
        assert!(error.contains(expected), "{error}");
    }
    assert!(!error.contains("private-payload"), "{error}");
}

fn policy() -> CompiledPolicy {
    crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v2
json:
  fields:
    /id: {kind: identity, formats: [decimal]}
    /created_at: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap()
}

fn redis(command: &str) -> Value {
    json!({"event_type":"redis_exchange","command":command})
}

fn args(values: &[&str]) -> Vec<u8> {
    serde_json::to_vec(
        &values
            .iter()
            .map(|text| text.as_bytes().to_vec())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn global_scope_selects_every_api_and_mysql_without_api_rules() {
    let policy = policy();
    let ids = BTreeSet::from([GLOBAL_JSON_ID.into()]);
    assert_eq!(resource::selected(&policy, &ids), ids);
    assert!(policy.rules.is_empty());
}

#[test]
fn mysql_control_requests_are_exact_noncarriers_and_missing_business_sql_is_rejected() {
    let policy = policy();
    let event = json!({
        "event_type":"mysql_exchange", "command":"COM_PING",
        "target_host":"db.test", "target_port":3306, "database":"app",
        "response":{"status":"ok"}
    });
    let directory = tempfile::tempdir().unwrap();
    let selected = BTreeSet::from([GLOBAL_JSON_ID.into()]);
    for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
        let raw = dependency::source_witness(surface, &event, directory.path()).unwrap();
        let checked = compare(&event, surface, &raw, &raw, &policy, Default::default()).unwrap();
        assert!(checked.passed());
        assert!(!record_source(&checked, &selected, &mut Preflight::default()).unwrap());
    }
    let raw =
        dependency::source_witness(Surface::DependencyRequest, &event, directory.path()).unwrap();
    for command in ["COM_QUIT", "COM_QUERY"] {
        let mut target: Value = serde_json::from_slice(&raw).unwrap();
        target["command"] = command.into();
        assert!(
            compare(
                &event,
                Surface::DependencyRequest,
                &raw,
                &serde_json::to_vec(&target).unwrap(),
                &policy,
                Default::default()
            )
            .is_err()
        );
    }
    for command in ["COM_QUERY", "COM_STMT_EXECUTE", "COM_STMT_PREPARE"] {
        let mut query = event.clone();
        query["command"] = command.into();
        let raw = dependency::source_witness(Surface::DependencyRequest, &query, directory.path())
            .unwrap();
        assert!(
            compare(
                &query,
                Surface::DependencyRequest,
                &raw,
                &raw,
                &policy,
                Default::default()
            )
            .is_err()
        );
    }
}

#[test]
fn redis_global_comparison_sees_every_value_and_enforces_one_automatic_id_relation() {
    let policy = policy();
    let source = args(&["one", r#"{"id":"11"}"#, "two", r#"{"id":"11"}"#]);
    let good = args(&["one", r#"{"id":"22"}"#, "two", r#"{"id":"22"}"#]);
    let bad = args(&["one", r#"{"id":"22"}"#, "two", r#"{"id":"33"}"#]);
    assert!(
        compare(
            &redis("MSET"),
            Surface::DependencyRequest,
            &source,
            &good,
            &policy,
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            &redis("MSET"),
            Surface::DependencyRequest,
            &source,
            &bad,
            &policy,
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    let changed_key = args(&["wrong", r#"{"id":"22"}"#, "two", r#"{"id":"22"}"#]);
    assert!(
        compare(
            &redis("MSET"),
            Surface::DependencyRequest,
            &source,
            &changed_key,
            &policy,
            AnchorClocks::default()
        )
        .is_err()
    );
}

#[test]
fn missing_fields_and_opaque_values_are_unavailable_but_paired_null_is_exact() {
    let policy = policy();
    let selected = BTreeSet::from([GLOBAL_JSON_ID.into()]);
    let mut result = Preflight::default();
    for payload in ["opaque", "{}"] {
        let raw = args(&["key", payload]);
        let checked = compare(
            &redis("SET"),
            Surface::DependencyRequest,
            &raw,
            &raw,
            &policy,
            AnchorClocks::default(),
        )
        .unwrap();
        assert!(!record_source(&checked, &selected, &mut result).unwrap());
    }
    assert_eq!(result.unavailable_source_values, 2);
    assert_eq!(result.source_validations, 0);
    let null = args(&["key", r#"{"created_at":null}"#]);
    assert!(
        compare(
            &redis("SET"),
            Surface::DependencyRequest,
            &null,
            &null,
            &policy,
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    let raw = args(&["key", r#"{"id":"11"}"#]);
    let checked = compare(
        &redis("SET"),
        Surface::DependencyRequest,
        &raw,
        &raw,
        &policy,
        AnchorClocks::default(),
    )
    .unwrap();
    assert!(record_source(&checked, &selected, &mut result).unwrap());
    assert_eq!(result.rules[GLOBAL_JSON_ID], 1);
    assert_eq!(result.independent_target_validations, 0);
}

#[test]
fn native_key_shapes_keep_global_content_checks_and_require_native_replay() {
    let policy=crate::policy::parse_and_compile_policy(r#"format: traffic-policy/v2
json:
  fields:
    /id: {kind: identity, formats: [decimal]}
resources:
  cache: {protocol: redis, endpoint: 'cache.test:6379', database: 0}
rules:
- id: session-key
  match:
    api: POST /sessions
    resource: cache
    key: {kind: affix, prefix: 'session:', suffix: ''}
  effect:
    kind: redis_sequence
    key: {kind: capture, template: 'session:{value}', format: {kind: hex, bytes: 4}}
    commands: [{operation: SET, arguments: {}}]
  proof: {source: 'sessions.py:1-20', fact: 'Session creation draws a fresh key nonce and stores its document'}
"#).unwrap();
    let event = json!({"event_type":"redis_exchange","command":"SET","target_host":"cache.test","target_port":6379,"database":0});
    let source = args(&["session:aaaaaaaa", r#"{"id":"11","stable":1}"#]);
    let target = args(&["session:bbbbbbbb", r#"{"id":"22","stable":1}"#]);
    let request = json!({"method":"POST","uri":"/sessions"});
    let metadata = crate::replay::MysqlInferenceMetadata::default();
    let mut obligations = BTreeSet::new();
    let mut context = CompareContext {
        policy: &policy,
        clocks: Default::default(),
        metadata: &metadata,
        copies: None,
        request: Some(&request),
        native_obligations: &mut obligations,
    };
    assert!(
        compare_prepared(
            &event,
            Surface::DependencyRequest,
            &source,
            &target,
            &mut context
        )
        .unwrap()
        .passed()
    );
    let changed = args(&["session:bbbbbbbb", r#"{"id":"22","stable":2}"#]);
    assert!(
        !compare_prepared(
            &event,
            Surface::DependencyRequest,
            &source,
            &changed,
            &mut context
        )
        .unwrap()
        .passed()
    );
    let outside = args(&["outside:bbbbbbbb", r#"{"id":"22","stable":1}"#]);
    assert!(
        compare_prepared(
            &event,
            Surface::DependencyRequest,
            &source,
            &outside,
            &mut context
        )
        .is_err()
    );
    let wrong_api = json!({"method":"GET","uri":"/sessions"});
    context.request = Some(&wrong_api);
    assert!(
        compare_prepared(
            &event,
            Surface::DependencyRequest,
            &source,
            &target,
            &mut context
        )
        .is_err()
    );
    assert!(obligations.contains("session-key"));
}

#[test]
fn redis_scalar_formats_compose_with_json_and_protocol_expiration_without_old_rule_scopes() {
    let policy = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v2
redis:
  keys:
    as-of: {kind: time, formats: [unix_seconds]}
json:
  fields:
    /id: {kind: identity, formats: [decimal]}
"#,
    )
    .unwrap();
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: DateTime::from_timestamp(1000, 0),
            target: DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    };
    let event = json!({"event_type":"redis_exchange","command":"MSET","database":0});
    let source = args(&["as-of", "1000", "document", r#"{"id":"11"}"#]);
    let target = args(&["as-of", "2000", "document", r#"{"id":"22"}"#]);
    let checked = compare(
        &event,
        Surface::DependencyRequest,
        &source,
        &target,
        &policy,
        clocks,
    )
    .unwrap();
    assert!(checked.passed(), "{:?}", checked.differences);
    assert!(checked.evaluated.contains("global.redis"));
    assert!(checked.evaluated.contains(GLOBAL_JSON_ID));
    let source = args(&["as-of", "1000", "EXAT", "1060"]);
    let target = args(&["as-of", "2000", "EXAT", "2060"]);
    let event = json!({"event_type":"redis_exchange","command":"SET","database":0});
    assert!(
        compare(
            &event,
            Surface::DependencyRequest,
            &source,
            &target,
            &policy,
            clocks
        )
        .unwrap()
        .passed()
    );
    let selected = BTreeSet::from(["global.redis".into()]);
    let same = compare(
        &event,
        Surface::DependencyRequest,
        &source,
        &source,
        &policy,
        Default::default(),
    )
    .unwrap();
    assert!(record_source(&same, &selected, &mut Preflight::default()).unwrap());
    let other_database = json!({"event_type":"redis_exchange","command":"SET","database":1});
    assert!(
        compare(
            &other_database,
            Surface::DependencyRequest,
            &source,
            &target,
            &policy,
            clocks
        )
        .unwrap()
        .passed(),
        "key formats apply across independently paired Redis databases"
    );
    let changed_key = args(&["other-key", "2000", "EXAT", "2060"]);
    assert!(
        compare(
            &other_database,
            Surface::DependencyRequest,
            &source,
            &changed_key,
            &policy,
            clocks
        )
        .is_err(),
        "a shared value format cannot waive the native physical key"
    );
}

#[test]
fn scalar_key_identity_cannot_bypass_json_scalar_protocol_checks() {
    let policy = crate::policy::parse_and_compile_policy("format: traffic-policy/v2\njson:\n  fields:\n    '': {kind: url, formats: [aws_sigv4]}\nredis:\n  keys:\n    key: {kind: identity, formats: [string]}\n").unwrap();
    let payload = r#""https://source.test/download?X-Amz-Date=20200101T000000Z&X-Amz-Credential=ak%2F20200101%2Fr%2Fs3%2Faws4_request&X-Amz-Signature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#;
    let source = args(&["key", payload]);
    let target = args(&["key", &payload.replace("source.test", "wrong.test")]);
    let event = json!({"event_type":"redis_exchange","database":0,"command":"SET"});
    assert!(
        !compare(
            &event,
            Surface::DependencyRequest,
            &source,
            &target,
            &policy,
            Default::default()
        )
        .unwrap()
        .passed()
    );
}
