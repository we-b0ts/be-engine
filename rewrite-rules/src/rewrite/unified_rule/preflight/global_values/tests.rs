use super::*;
use serde_json::json;

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
        r#"format: traffic-policy/v3
json:
  fields:
    /id: {kind: identity, formats: [decimal]}
    /created_at: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap()
}

#[test]
fn automatic_redis_text_preflight_keeps_builtin_coverage_separate_and_checks_request_clocks() {
    let policy = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap();
    let event = json!({"event_type":"redis_exchange","command":"SET",
        "target_host":"cache.test","target_port":6379,"database":0});
    let source = args(&["key", "2026-10-16T00:00:30Z"]);
    let clocks = AnchorClocks::for_request(
        ClockPair {
            source: Some("2026-10-16T00:00:00Z".parse().unwrap()),
            target: Some("2026-10-16T00:01:00Z".parse().unwrap()),
        },
        ClockPair {
            source: Some("2026-10-16T00:00:30Z".parse().unwrap()),
            target: Some("2026-10-16T00:02:30Z".parse().unwrap()),
        },
        Default::default(),
    );
    let coverage = compare(
        &event,
        Surface::DependencyRequest,
        &source,
        &source,
        &policy,
        clocks,
    )
    .unwrap();
    assert!(coverage.passed(), "{:?}", coverage.differences);
    assert!(
        coverage
            .evaluated
            .contains(crate::value_contract::time::automatic::RULE_ID)
    );
    assert!(!coverage.evaluated.contains(GLOBAL_JSON_ID));
    for target in ["2026-10-16T00:02:30Z", "2026-10-16T00:04:03Z"] {
        let checked = compare(
            &event,
            Surface::DependencyRequest,
            &source,
            &args(&["key", target]),
            &policy,
            clocks,
        );
        if target.ends_with("02:30Z") {
            assert!(checked.unwrap().passed());
        } else {
            assert!(checked.is_err() || !checked.unwrap().passed());
        }
    }
}

fn redis(command: &str) -> Value {
    json!({"event_type":"redis_exchange","command":command,"database":0,"resp_version":2})
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
            .map(|comparison| !comparison.passed())
            .unwrap_or(true)
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
        .map(|comparison| !comparison.passed())
        .unwrap_or(true)
    );
}

#[test]
fn redis_key_identity_preflight_counts_source_coverage_and_checks_json_consistency() {
    let policy = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /session_id: {kind: identity, formats: [{prefix: vnc-, hex: 4}]}
redis:
  keys:
    'vnc_session:*':
      key_format: {kind: identity, formats: [{prefix: vnc-, hex: 4}]}
"#,
    )
    .unwrap();
    let source = args(&["vnc_session:vnc-1234", r#"{"session_id":"vnc-1234"}"#]);
    let checked = |target: &[u8]| {
        compare(
            &redis("SET"),
            Surface::DependencyRequest,
            &source,
            target,
            &policy,
            Default::default(),
        )
        .unwrap()
    };
    let mut proof = Preflight::default();
    let selected = BTreeSet::from(["global.redis".into()]);
    assert!(record_source(&checked(&source), &selected, &mut proof).unwrap());
    assert_eq!(proof.rules["global.redis"], 1);
    for (json_id, passed) in [("vnc-5678", true), ("vnc-9abc", false)] {
        let value = json!({"session_id": json_id}).to_string();
        let comparison = checked(&args(&["vnc_session:vnc-5678", &value]));
        assert_eq!(comparison.passed(), passed, "{:?}", comparison.differences);
    }
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
