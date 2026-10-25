use super::*;

fn native(values: Vec<Value>) -> Vec<PolicyRule> {
    values
        .into_iter()
        .map(|value| PolicyRule::Native(Box::new(serde_yaml::from_value(value).unwrap())))
        .collect()
}

fn localcache(raw: &str) -> Declaration {
    serde_yaml::from_str(raw).unwrap()
}

fn processes(raw: &str) -> ProcessDeclaration {
    serde_yaml::from_str(raw).unwrap()
}

fn root() -> Mapping {
    serde_yaml::from_str("source_revision: source-v1").unwrap()
}

fn named() -> BTreeMap<String, ResourceDeclaration> {
    serde_yaml::from_str(
        "task_mysql: {protocol: mysql, endpoint: 'db.test:3306', database: tasks, username: worker}",
    )
    .unwrap()
}

fn compacted(rules: &[PolicyRule], names: &BTreeMap<String, ResourceDeclaration>) -> Value {
    let mut root = root();
    for rule in rules {
        assert!(compact(rule, names, &mut root).unwrap());
    }
    root.into()
}

#[test]
fn localcache_declares_requests_with_explicit_http_host_and_exact_redis_field() {
    let declaration = localcache(
        r#"requests:
- redis: {operation: HGET, key: token_v2, field: '3061639762'}
- http: {host: AUTH.example.com, method: get, path: /.well-known/jwks.json}
"#,
    );
    let rules = native(expand(Some(declaration), None, None, &BTreeMap::new()).unwrap());
    let redis = rules[0].as_native().unwrap();
    assert!(redis.selector.resource.is_none());
    assert!(
        matches!(&redis.effect, NativeEffect::FiniteSharing(FiniteSharingEffect::Redis { hash_field: Some(field) }) if field == "3061639762")
    );
    let http = rules[1].as_native().unwrap();
    assert_eq!(http.selector.http_host.as_deref(), Some("auth.example.com"));
    assert_eq!(http.selector.operation.as_deref(), Some("GET"));
    assert!(http.selector.resource.is_none());
    let rendered = compacted(&rules, &BTreeMap::new());
    let local: Declaration = serde_yaml::from_value(rendered["localcache"].clone()).unwrap();
    assert_eq!(
        native(expand(Some(local), None, None, &BTreeMap::new()).unwrap()),
        rules
    );
    let text = serde_yaml::to_string(&rendered).unwrap();
    for forbidden in ["effect:", "match:", "proof:", "resource:", "database:"] {
        assert!(!text.contains(forbidden), "{text}");
    }
}

#[test]
fn one_named_source_task_preserves_multiple_protocol_dependencies_and_mysql_aliases() {
    let declaration = processes(
        r#"tasks:
  refresh_background:
    requests:
    - http: {host: api.example.com, methods: [GET, HEAD], path_prefixes: [/status/, /keys/]}
    - redis:
        ports: [6379, 6380]
        operation: GET
        keys: [{kind: exact, value: heartbeat}]
        arguments: [task_mysql, proof]
    - mysql:
        selector:
          resource: task_mysql
          sql: "SELECT 'task_mysql' AS resource, 'proof' AS literal FROM tasks WHERE id = ?"
          tables: [tasks]
        include_transaction_boundaries: true
        transaction_members:
        - resource: task_mysql
          sql: UPDATE tasks SET state = ? WHERE id = ?
          tables: [tasks]
"#,
    );
    let names = named();
    let rules = native(expand(None, Some(declaration), Some("source-v1"), &names).unwrap());
    assert_eq!(rules.len(), 3);
    for rule in &rules {
        let NativeEffect::ProcessOwned(effect) = &rule.as_native().unwrap().effect else {
            panic!("process owner");
        };
        assert_eq!(effect.task_name.as_deref(), Some("refresh_background"));
        assert_eq!(effect.source_revision, "source-v1");
        assert!(rule.proof().is_none());
    }
    let NativeEffect::ProcessOwned(effect) = &rules[2].as_native().unwrap().effect else {
        panic!("process owner");
    };
    let ProcessSelector::Mysql {
        selector,
        transaction_members,
        ..
    } = &effect.selector
    else {
        panic!("MySQL selector");
    };
    assert_eq!(selector.resource.endpoint.host, "db.test");
    assert!(selector.sql.contains("'task_mysql' AS resource"));
    assert!(selector.sql.contains("'proof' AS literal"));
    assert!(transaction_members[0].proof.is_none());
    assert_eq!(transaction_members[0].contract.resource, selector.resource);
    let rendered = compacted(&rules, &names);
    assert_eq!(
        rendered["process_dependencies"]["tasks"]
            .as_mapping()
            .unwrap()
            .len(),
        1
    );
    let requests = &rendered["process_dependencies"]["tasks"]["refresh_background"]["requests"];
    assert_eq!(
        requests[2]["mysql"]["selector"]["resource"].as_str(),
        Some("task_mysql")
    );
    assert!(
        requests[2]["mysql"]["transaction_members"][0]
            .get("contract")
            .is_none()
    );
    let declaration: ProcessDeclaration =
        serde_yaml::from_value(rendered["process_dependencies"].clone()).unwrap();
    assert_eq!(
        native(expand(None, Some(declaration), Some("source-v1"), &names).unwrap()),
        rules
    );
}

#[test]
fn process_http_simple_form_roundtrips_without_authorities_or_a_default_port() {
    let declaration = processes(
        "tasks: {refresh: {requests: [{http: {host: 'keys.example.com', method: GET, path: /keys}}]}}",
    );
    let rules =
        native(expand(None, Some(declaration), Some("source-v1"), &BTreeMap::new()).unwrap());
    let NativeEffect::ProcessOwned(effect) = &rules[0].as_native().unwrap().effect else {
        panic!("process")
    };
    let ProcessSelector::Http {
        authorities,
        methods,
        path_prefixes,
    } = &effect.selector
    else {
        panic!("HTTP")
    };
    assert_eq!(authorities, &["keys.example.com"]);
    assert_eq!(methods, &["GET"]);
    assert_eq!(path_prefixes, &["/keys"]);
    let rendered = compacted(&rules, &BTreeMap::new());
    let request = &rendered["process_dependencies"]["tasks"]["refresh"]["requests"][0]["http"];
    assert_eq!(request["host"].as_str(), Some("keys.example.com"));
    assert_eq!(request["method"].as_str(), Some("GET"));
    assert_eq!(request["path"].as_str(), Some("/keys"));
    assert!(request.get("authorities").is_none());
    assert!(!serde_yaml::to_string(&rendered).unwrap().contains("443"));
}

#[test]
fn ids_exclude_evidence_but_include_actual_task_revision_and_resolved_resource() {
    let raw = "tasks:\n  refresh:\n    requests:\n    - mysql:\n        selector: {resource: task_mysql, sql: 'SELECT 1'}\n        transaction_members: [{resource: task_mysql, sql: 'SELECT 2'}]\n      proof: {source: 'startup.py:42', fact: 'Source refreshes its process state'}\n";
    let names = named();
    let first = native(expand(None, Some(processes(raw)), Some("source-v1"), &names).unwrap());
    let changed = native(
        expand(
            None,
            Some(processes(&raw.replace(
                "Source refreshes its process state",
                "Evidence wording changes",
            ))),
            Some("source-v1"),
            &names,
        )
        .unwrap(),
    );
    assert_eq!(first[0].id(), changed[0].id());
    let NativeEffect::ProcessOwned(effect) = &first[0].as_native().unwrap().effect else {
        panic!("process")
    };
    let ProcessSelector::Mysql {
        transaction_members,
        ..
    } = &effect.selector
    else {
        panic!("MySQL")
    };
    assert_eq!(
        transaction_members[0].proof.as_ref().unwrap().source,
        "startup.py:42 @ source-v1"
    );
    let task = native(
        expand(
            None,
            Some(processes(&raw.replace("  refresh:", "  another_refresh:"))),
            Some("source-v1"),
            &names,
        )
        .unwrap(),
    );
    let revision = native(expand(None, Some(processes(raw)), Some("source-v2"), &names).unwrap());
    assert_ne!(first[0].id(), task[0].id());
    assert_ne!(first[0].id(), revision[0].id());
    let renamed: BTreeMap<_, _> = [("renamed".to_owned(), names["task_mysql"].clone())].into();
    let alias = native(
        expand(
            None,
            Some(processes(&raw.replace("task_mysql", "renamed"))),
            Some("source-v1"),
            &renamed,
        )
        .unwrap(),
    );
    assert_eq!(first[0].id(), alias[0].id());
    assert!(
        !serde_yaml::to_string(&compacted(&first, &names))
            .unwrap()
            .contains("proof:")
    );
}

#[test]
fn strict_lifetime_shape_rejects_hidden_scopes_missing_hosts_and_semantic_duplicates() {
    for raw in [
        "requests: []\nresource: tasks",
        "requests: [{redis: {operation: GET, key: token}, id: hidden}]",
        "requests: [{redis: {operation: GET, key: token}, http: {host: api.example.com, method: GET, path: /}}]",
        "requests: [{http: {method: GET, path: /keys}}]",
        "requests: [{http: {host: 'api.example.com:443', method: GET, path: /keys}}]",
        "requests: [{http: {host: 'https://api.example.com', method: GET, path: /keys}}]",
        "requests: [{http: {host: api.example.com, method: GET, path: '/keys?query=1'}}]",
        "requests: [{redis: {operation: GET, key: token, database: 1}}]",
        "requests: [{redis: {operation: GET, key: token, field: invalid}}]",
        "requests: [{redis: {operation: HGET, key: token}}]",
        "requests: [{redis: {operation: GET, key: token}}, {redis: {operation: get, key: token}}]",
    ] {
        let result = serde_yaml::from_str(raw)
            .map_err(anyhow::Error::from)
            .and_then(|declaration| expand(Some(declaration), None, None, &BTreeMap::new()));
        assert!(result.is_err(), "{raw}");
    }
    for raw in [
        "tasks: {'': {requests: []}}",
        "tasks: {' refresh ': {requests: []}}",
        "tasks: {refresh: {requests: []}, refresh: {requests: []}}",
        "tasks: {refresh: {requests: [{http: {authorities: [api.example.com], methods: [GET], path_prefixes: [/keys]}}]}}",
        "tasks: {refresh: {requests: [{http: {host: api.example.com, method: GET, methods: [GET], path: /keys}}]}}",
    ] {
        let result = serde_yaml::from_str(raw)
            .map_err(anyhow::Error::from)
            .and_then(|declaration| {
                expand(None, Some(declaration), Some("source-v1"), &BTreeMap::new())
            });
        assert!(result.is_err(), "{raw}");
    }
    let declaration = processes(
        "tasks: {refresh: {requests: [{http: {host: api.example.com, method: GET, path: /keys}}]}}",
    );
    assert!(expand(None, Some(declaration), None, &BTreeMap::new()).is_err());
}

#[test]
fn compaction_never_drops_extra_api_or_selector_constraints() {
    let rules = native(
        expand(
            Some(localcache(
                "requests: [{http: {host: api.example.com, method: GET, path: /keys}}]",
            )),
            None,
            None,
            &BTreeMap::new(),
        )
        .unwrap(),
    );
    let mut constrained = rules[0].as_native().unwrap().clone();
    constrained.selector.api = Some("POST /tasks".into());
    let mut root = root();
    assert!(
        !compact(
            &PolicyRule::Native(Box::new(constrained)),
            &BTreeMap::new(),
            &mut root
        )
        .unwrap()
    );
    assert!(root.get("localcache").is_none());
    let mut constrained = rules[0].as_native().unwrap().clone();
    constrained.selector.http_host = Some("other.example.com".into());
    assert!(
        !compact(
            &PolicyRule::Native(Box::new(constrained)),
            &BTreeMap::new(),
            &mut root
        )
        .unwrap()
    );
    assert!(root.get("localcache").is_none());
}
