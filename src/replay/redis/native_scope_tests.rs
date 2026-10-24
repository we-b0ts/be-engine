use super::*;
use serde_json::json;

#[test]
fn native_lock_and_publish_scope_comes_from_source_api_body_database_and_auth() {
    assert_scopes(true);
}

#[test]
fn native_resource_rules_apply_across_apis_but_keep_database_and_auth_isolated() {
    assert_scopes(false);
}

fn assert_scopes(api_scoped: bool) {
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("policy.yaml");
    let policy = r#"
format: traffic-policy/v2
rules:
- id: scoped-lock
  match:
    api: POST /sessions
    resource: {protocol: redis, endpoint: 'cache.test:6379', database: 2, username: alice}
    key: {kind: affix, prefix: 'lock:'}
  when: {request_body_json: {/enabled: {equals: true}}}
  effect: {kind: redis_lock}
  proof: {source: 'source.py:lock', fact: 'This Source path acquires and releases a case-owned lock under the same authenticated Redis identity'}
- id: scoped-publisher
  match:
    api: POST /sessions
    resource: {protocol: redis, endpoint: 'cache.test:6379', database: 2, username: alice}
    operation: PUBLISH
    key: {kind: exact, value: events}
  when: {request_body_json: {/enabled: {equals: true}}}
  effect: {kind: redis_publish_identity, uuid_field: host_id}
  proof: {source: 'source.py:publish', fact: 'This Source path publishes a process UUID while keeping the event business fields exact'}
"#;
    let policy = if api_scoped {
        policy.to_owned()
    } else {
        policy.replace("    api: POST /sessions\n", "").replace(
            "  when: {request_body_json: {/enabled: {equals: true}}}\n",
            "",
        )
    };
    std::fs::write(&policy_path, policy).unwrap();
    let mut cases = BTreeMap::new();
    for (id, method, enabled) in [
        ("ok", "POST", true),
        ("method", "GET", true),
        ("condition", "POST", false),
    ] {
        let dir = temp.path().join(id);
        std::fs::create_dir(&dir).unwrap();
        let uri = if id == "method" {
            "/other"
        } else {
            "/sessions"
        };
        std::fs::write(dir.join("request.json"),json!({"method":method,"uri":uri,"body":{"encoding":"utf8","truncated":false,"data":json!({"enabled":enabled}).to_string()}}).to_string()).unwrap();
        std::fs::write(dir.join("expected-response.json"), "{}").unwrap();
        std::fs::write(dir.join("dependencies.jsonl"), "").unwrap();
        cases.insert(
            id.into(),
            crate::replay::ReplayCase {
                id: id.into(),
                dependencies_path: dir.join("dependencies.jsonl"),
                dir,
                status: crate::replay::ReplayCaseStatus::Pending,
            },
        );
    }
    let runtime = crate::replay::ReplayPolicyRuntime::load(&policy_path, &cases).unwrap();
    let mut state = RedisReplayState {
        request_contracts: runtime.request_contracts.clone(),
        ..Default::default()
    };
    let mut targets = BTreeMap::new();
    for (index, (case, db, user)) in [
        ("ok", 2, "alice"),
        ("method", 2, "alice"),
        ("condition", 2, "alice"),
        ("ok", 3, "alice"),
        ("ok", 2, "bob"),
    ]
    .into_iter()
    .enumerate()
    {
        let record = serde_json::from_value(json!({"connection_id":Uuid::new_v4(),"sequence":index+1,"target_host":"cache.test","target_port":6379,"database":db,"username":user,"resp_version":2,
            "command":"SET","args":(["lock:one","source-token","NX","PX","30000"].map(|data|json!({"encoding":"utf8","data":data}))),
            "response_kind":"simple_string","response":{"encoding":"utf8","data":"+OK\r\n"},"replay_safe":true})).unwrap();
        state
            .register_exchange(record, ReplaySource::Case, Some(case), &mut targets, &[])
            .unwrap();
    }
    state.configure_lock_tokens(&runtime.redis_lock_token_rules());
    for (index, exchange) in state.exchanges.iter().enumerate() {
        let mut actual = exchange.args.clone();
        actual[1] = b"target-token".to_vec();
        assert_eq!(
            state
                .lock_tokens
                .arguments_match(exchange, &state.exchanges, &actual),
            if index == 0 || (!api_scoped && index < 3) {
                Some(true)
            } else {
                None
            }
        );
    }
    state.configure_publish(runtime.redis_publish_rules());
    let source = vec![
        b"events".to_vec(),
        br#"{"host_id":"0123456789ab4def8123456789abcdef","body":"checked"}"#.to_vec(),
    ];
    let actual = vec![
        b"events".to_vec(),
        br#"{"host_id":"fedcba98765443218123456789abcdef","body":"checked"}"#.to_vec(),
    ];
    for (index, (case, db, user)) in [
        ("ok", 2, "alice"),
        ("method", 2, "alice"),
        ("condition", 2, "alice"),
        ("ok", 3, "alice"),
        ("ok", 2, "bob"),
    ]
    .into_iter()
    .enumerate()
    {
        let result = state.publish_rules.preview_json(
            publish::json::JsonContext {
                case_id: Some(case),
                host: "cache.test",
                port: 6379,
                database: db,
                username: Some(user),
            },
            &source,
            &actual,
        );
        if index == 0 || (!api_scoped && index < 3) {
            assert!(result.unwrap().is_ok());
        } else {
            assert!(result.is_none());
        }
    }
}
