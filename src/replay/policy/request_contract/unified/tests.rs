use super::*;
use serde_json::json;

fn runtime(operation: &str) -> RequestContracts {
    let policy = crate::policy::parse_policy(&format!(
        r#"
format: traffic-policy/v1
rules:
- id: session-value
  surface: dependency.request
  match:
    api: POST /sessions
    resource: {{protocol: redis, endpoint: 'cache.test:6379', database: 0}}
    operation: {operation}
    key: {{prefix: 'session:'}}
  slot: value
  codec: json
  contract:
    /members: {{kind: unordered}}
    /expires_at: {{kind: time, format: unix_seconds, relation: preserve_offset}}
  proof: {{source: 'src/session.rs:12-20', fact: 'Members are a set; expiry is request-relative'}}
"#
    ))
    .unwrap();
    let mut runtime = RequestContracts::default();
    runtime
        .configure_compiled(Some(Arc::new(
            crate::policy::compile_policy(&policy).unwrap(),
        )))
        .unwrap();
    runtime.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            method: "POST".into(),
            path: "/sessions".into(),
            recorded: DateTime::from_timestamp(1000, 0),
            actual: DateTime::from_timestamp(2000, 0),
            dir: PathBuf::new(),
            conditions: Default::default(),
            source_body: Some(json!({"enabled":true})),
        },
    );
    runtime
}

fn source() -> String {
    json!({"members":["a","b","a"],"expires_at":1010,"stable":"checked"}).to_string()
}
fn target() -> String {
    json!({"members":["a","a","b"],"expires_at":2010,"stable":"checked"}).to_string()
}

fn preview(
    runtime: &RequestContracts,
    command: &str,
    source: &[&str],
    target: &[&str],
) -> Result<Decision> {
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    runtime
        .preview_redis(
            "case",
            &host,
            0,
            command,
            &source
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>(),
            &target
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>(),
        )
        .expect("compiled value rule selected")
}

#[test]
fn redis_set_composes_collection_and_time_without_relaxing_other_arguments() {
    let runtime = runtime("SET");
    let a = source();
    let b = target();
    let decision = preview(
        &runtime,
        "SET",
        &["session:1", &a, "EX", "90"],
        &["session:1", &b, "EX", "90"],
    )
    .unwrap();
    assert_eq!(decision.ids, ["session-value"]);
    assert_eq!(decision.unified_time_validations["session-value"], 1);
    for changed in [
        b.replace("checked", "changed"),
        b.replace("[\"a\",\"a\",\"b\"]", "[\"a\",\"b\",\"b\"]"),
    ] {
        assert!(
            preview(
                &runtime,
                "SET",
                &["session:1", &a],
                &["session:1", &changed]
            )
            .is_err()
        );
    }
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", &a, "EX", "90"],
            &["session:1", &b, "EX", "91"]
        )
        .is_err()
    );
    assert!(preview(&runtime, "SET", &["session:1", &a], &["session:2", &b]).is_err());
    assert!(runtime.reports().iter().all(|report| report.matches == 0));
    runtime.commit(decision);
    assert_eq!(runtime.reports()[0].matches, 1);
    assert_eq!(runtime.reports()[0].time_validations, 1);
}

#[test]
fn redis_value_slots_are_explicit_for_setex_psetex_and_publish() {
    let a = source();
    let b = target();
    for command in ["SETEX", "PSETEX"] {
        let runtime = runtime(command);
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", "90", &a],
                &["session:1", "90", &b]
            )
            .is_ok()
        );
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", "90", &a],
                &["session:1", "91", &b]
            )
            .is_err()
        );
    }
    let runtime = runtime("PUBLISH");
    assert!(preview(&runtime, "PUBLISH", &["session:1", &a], &["session:1", &b]).is_ok());
    assert!(
        preview(
            &runtime,
            "PUBLISH",
            &["session:1", &a, "extra"],
            &["session:1", &b, "extra"]
        )
        .is_err()
    );
}

#[test]
fn missing_clocks_and_duplicate_members_fail_without_usage_commit() {
    let runtime = runtime("SET");
    runtime
        .state
        .lock()
        .unwrap()
        .cases
        .get_mut("case")
        .unwrap()
        .actual = None;
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", &source()],
            &["session:1", &target()]
        )
        .is_err()
    );
    let runtime = self::runtime("SET");
    assert!(
        preview(
            &runtime,
            "SET",
            &[
                "session:1",
                "{\"expires_at\":1010,\"expires_at\":1010,\"members\":[]}"
            ],
            &["session:1", &target()]
        )
        .is_err()
    );
    assert_eq!(runtime.reports()[0].matches, 0);
}

#[test]
fn source_predicates_and_auth_identity_cannot_be_chosen_by_target() {
    let mut runtime = runtime("SET");
    let mut policy = runtime.compiled.as_ref().unwrap().as_ref().clone();
    policy.rules[0].rule.when = Some(crate::policy::SourceCondition {
        request_body_json: BTreeMap::from([(
            "/enabled".into(),
            crate::policy::SourcePredicate::Equals(crate::policy::EqualsPredicate {
                equals: crate::policy::SourceScalar::Bool(false),
            }),
        )]),
    });
    runtime.configure_compiled(Some(Arc::new(policy))).unwrap();
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let args = |value: String| vec![b"session:1".to_vec(), value.into_bytes()];
    assert!(
        runtime
            .preview_redis("case", &host, 0, "SET", &args(source()), &args(target()))
            .is_none()
    );
    let mut policy = runtime.compiled.as_ref().unwrap().as_ref().clone();
    policy.rules[0].rule.when = None;
    policy.rules[0]
        .rule
        .selector
        .resource
        .as_mut()
        .unwrap()
        .username = Some("alice".into());
    runtime.configure_compiled(Some(Arc::new(policy))).unwrap();
    let mut context = RedisRequestContext::without_exchange("case", &host, 0, "SET");
    assert!(
        runtime
            .preview_redis_context(&context, &args(source()), &args(target()))
            .is_none()
    );
    context.username = Some("alice");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    assert!(
        runtime
            .preview_redis_context(&context, &args(source()), &args(target()))
            .unwrap()
            .is_ok()
    );
}

#[test]
fn redis_value_rule_applicability_retains_only_selected_source_identities() {
    let runtime = runtime("SET");
    let event = json!({"event_type":"redis_exchange","connection_id":"value-lane","sequence":4,
        "target_host":"cache.test","target_port":6379,"database":0,"command":"SET","replay_safe":true,
        "request_started_at":"1970-01-01T00:16:40Z","timestamp":"1970-01-01T00:16:40Z",
        "args":[{"encoding":"utf8","data":"session:1","truncated":false},{"encoding":"utf8","data":source(),"truncated":false}]});
    for (field, value) in [
        ("database", json!(1)),
        ("target_port", json!(6380)),
        ("global_dependency_reason", json!("process-owned")),
    ] {
        let mut unrelated = event.clone();
        unrelated[field] = value;
        runtime
            .observe_source("case", unrelated.to_string().as_bytes())
            .unwrap();
        assert!(runtime.recorded_redis_rule_applicability().is_empty());
    }
    runtime
        .observe_source("case", event.to_string().as_bytes())
        .unwrap();
    assert_eq!(
        serde_json::to_value(runtime.recorded_redis_rule_applicability()).unwrap(),
        json!({"session-value":[{"case_id":"case","connection_id":"value-lane","sequence":4}]})
    );
}
