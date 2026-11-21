use super::*;
use serde_json::json;

fn field(path: &str, format: AddressFormat) -> AddressField {
    AddressField {
        path: path.into(),
        format,
        protocol: ProtocolHint::Auto,
        recursive: true,
        port_field: None,
    }
}

#[test]
fn separate_host_and_port_fields_use_declarative_request_and_body_predicates() {
    let rule: DocumentRule = serde_json::from_value(json!({
        "query": {"action": ["lookup", "lookupforupdate"]},
        "when": {"/code": 200},
        "decode": [{"path": "/body", "codec": "json"}],
        "fields": [{"path": "/nodes/*/*/host", "format": "ipv4", "port_field": "port", "protocol": "redis"}]
    })).unwrap();
    let compiled = CompiledRewrite::compile(&[rule]).unwrap();
    let bytes = serde_json::to_vec(&json!({"code":200, "body":serde_json::to_string(&json!({"nodes":{"ready":[{"host":"10.0.0.1", "port":6379,"weight":5}]}})).unwrap()})).unwrap();
    assert!(
        compiled
            .inspect_with_query(
                br#"{"code":200,"body":"signature"}"#,
                RewriteBudget::default(),
                Some("action=getsign")
            )
            .unwrap()
            .is_none()
    );
    assert!(
        compiled
            .inspect_with_query(
                br#"{"code":503,"body":"error"}"#,
                RewriteBudget::default(),
                Some("action=lookup")
            )
            .unwrap()
            .is_none()
    );
    let plan = compiled
        .inspect_with_query(&bytes, RewriteBudget::default(), Some("action=lookup"))
        .unwrap()
        .unwrap();
    let endpoint = plan.endpoints().next().unwrap();
    assert_eq!(endpoint.port, 6379);
    let bindings = routes(&plan);
    let output: Value = serde_json::from_slice(&plan.materialize(&bindings).unwrap()).unwrap();
    let body: Value = serde_json::from_str(output["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        body["nodes"]["ready"][0],
        json!({"host":"198.19.0.1","port":6379,"weight":5})
    );
}

fn routes(plan: &RewritePlan) -> BTreeMap<String, Ipv4Addr> {
    plan.endpoints()
        .enumerate()
        .map(|(index, endpoint)| {
            (
                endpoint.alias.clone(),
                Ipv4Addr::new(198, 19, 0, index as u8 + 1),
            )
        })
        .collect()
}

#[test]
fn generic_nested_yaml_fields_rewrite_all_declared_addresses_and_preserve_business_topology() {
    let rules = CompiledRewrite::compile(&[DocumentRule {
        query: BTreeMap::new(),
        when: BTreeMap::new(),
        transforms: vec![],
        decode: vec![DecodeAt {
            path: "/body/nodes/*/value".into(),
            codec: DocumentCodec::Yaml,
        }],
        fields: vec![
            field("/*/master", AddressFormat::HostPort),
            field("/*/slave", AddressFormat::HostPort),
        ],
    }])
    .unwrap();
    let document = json!({"code":200,"body":{"nodes":[{"value":"orders:\n  master: 10.0.0.1:3306\n  slave: [10.0.0.2:3306, 10.0.0.3:3306]\n  ttl: 60\n"}]},"keep":"10.0.0.4:3306"});
    let plan = rules
        .inspect(
            &serde_json::to_vec(&document).unwrap(),
            RewriteBudget::default(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(plan.endpoints().count(), 3);
    let bindings = routes(&plan);
    let output: Value = serde_json::from_slice(&plan.materialize(&bindings).unwrap()).unwrap();
    let embedded: Value =
        serde_yaml::from_str(output["body"]["nodes"][0]["value"].as_str().unwrap()).unwrap();
    assert_eq!(embedded["orders"]["ttl"], 60);
    assert_eq!(embedded["orders"]["slave"].as_array().unwrap().len(), 2);
    assert!(
        embedded["orders"]["master"]
            .as_str()
            .unwrap()
            .starts_with("198.19.")
    );
    assert_eq!(output["keep"], "10.0.0.4:3306");
}

#[test]
fn generic_json_strings_select_addresses_without_platform_names_or_node_reduction() {
    let compiled = CompiledRewrite::compile(&[DocumentRule {
        query: BTreeMap::new(),
        when: BTreeMap::new(),
        transforms: vec![],
        decode: vec![DecodeAt {
            path: "/body".into(),
            codec: DocumentCodec::Json,
        }],
        fields: vec![field("/nodes/*/*/host", AddressFormat::HostPort)],
    }])
    .unwrap();
    let inner =
        json!({"nodes":{"ready":[{"host":"10.0.0.1:6379"},{"host":"10.0.0.2:6379"}]},"keep":true});
    let document = json!({"body":serde_json::to_string(&inner).unwrap()});
    let plan = compiled
        .inspect(
            &serde_json::to_vec(&document).unwrap(),
            RewriteBudget::default(),
        )
        .unwrap()
        .unwrap();
    let bindings = routes(&plan);
    let output: Value = serde_json::from_slice(&plan.materialize(&bindings).unwrap()).unwrap();
    let result: Value = serde_json::from_str(output["body"].as_str().unwrap()).unwrap();
    assert_eq!(result["nodes"]["ready"].as_array().unwrap().len(), 2);
    assert_eq!(result["keep"], true);
}

#[test]
fn url_rewriting_preserves_credentials_path_query_and_fragment_bytes() {
    let compiled = CompiledRewrite::compile(&[DocumentRule {
        query: BTreeMap::new(),
        when: BTreeMap::new(),
        transforms: vec![],
        decode: vec![],
        fields: vec![field("/url", AddressFormat::Url)],
    }])
    .unwrap();
    let document =
        json!({"url":"http://user:password@10.0.0.1:8080/a%2Fb?x=1&x=%2f#section","other":7});
    let plan = compiled
        .inspect(
            &serde_json::to_vec(&document).unwrap(),
            RewriteBudget::default(),
        )
        .unwrap()
        .unwrap();
    let alias = plan.endpoints().next().unwrap().alias.clone();
    let bindings = routes(&plan);
    let output: Value = serde_json::from_slice(&plan.materialize(&bindings).unwrap()).unwrap();
    assert_eq!(
        output["url"],
        format!("http://user:password@{alias}:8080/a%2Fb?x=1&x=%2f#section")
    );
    assert_eq!(output["other"], 7);
}

#[test]
fn compile_budgets_missing_routes_and_conflicting_decoders_have_explicit_errors() {
    let rule = DocumentRule {
        query: BTreeMap::new(),
        when: BTreeMap::new(),
        transforms: vec![],
        decode: vec![],
        fields: vec![field("/url", AddressFormat::Url)],
    };
    let compiled = CompiledRewrite::compile(&[rule]).unwrap();
    let bytes = br#"{"url":"http://10.0.0.1/a"}"#;
    assert!(
        compiled
            .inspect(
                bytes,
                RewriteBudget {
                    max_decoded_bytes: 1,
                    max_endpoints: 1
                }
            )
            .is_err()
    );
    let plan = compiled
        .inspect(bytes, RewriteBudget::default())
        .unwrap()
        .unwrap();
    assert!(plan.materialize(&BTreeMap::new()).is_err());
    let mut rule = DocumentRule {
        query: BTreeMap::new(),
        when: BTreeMap::new(),
        transforms: vec![],
        decode: vec![DecodeAt {
            path: "/body".into(),
            codec: DocumentCodec::Json,
        }],
        fields: vec![field("/url", AddressFormat::Url)],
    };
    let first = rule.clone();
    rule.decode[0].codec = DocumentCodec::Yaml;
    let compiled = CompiledRewrite::compile(&[first, rule]).unwrap();
    let document = json!({"body":"{\"url\":\"http://10.0.0.1/a\"}"});
    assert!(
        compiled
            .inspect(
                &serde_json::to_vec(&document).unwrap(),
                RewriteBudget::default()
            )
            .is_err()
    );
}

#[test]
fn explicit_document_edits_work_without_addresses_and_remove_array_indexes_safely() {
    let rules: Vec<DocumentRule> = serde_yaml::from_str(
        r#"
- decode: [{path: /body/nodes/*/value, codec: yaml}]
  transforms:
  - {op: remove, path: /*/master_l1}
  - {op: take, path: /*/slave_l1, count: 1}
  - {op: set, path: /*/enabled, value: false}
"#,
    )
    .unwrap();
    let compiled = CompiledRewrite::compile(&rules).unwrap();
    let document = json!({"body":{"nodes":[{"value":"cache:\n  master_l1: localhost:11211\n  slave_l1: [[one], [two]]\n  enabled: true\n  ttl: 60\n"}]},"keep":true});
    let plan = compiled
        .inspect(
            &serde_json::to_vec(&document).unwrap(),
            RewriteBudget::default(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(plan.endpoints().count(), 0);
    let output: Value =
        serde_json::from_slice(&plan.materialize(&BTreeMap::new()).unwrap()).unwrap();
    let embedded: Value =
        serde_yaml::from_str(output["body"]["nodes"][0]["value"].as_str().unwrap()).unwrap();
    assert!(embedded["cache"].get("master_l1").is_none());
    assert_eq!(embedded["cache"]["slave_l1"], json!([["one"]]));
    assert_eq!(embedded["cache"]["enabled"], false);
    assert_eq!(embedded["cache"]["ttl"], 60);
    assert_eq!(output["keep"], true);

    let rules: Vec<DocumentRule> =
        serde_yaml::from_str("- transforms: [{op: remove, path: /items/*}]").unwrap();
    let plan = CompiledRewrite::compile(&rules)
        .unwrap()
        .inspect(
            &serde_json::to_vec(&json!({"items":(0..15).collect::<Vec<_>>()})).unwrap(),
            RewriteBudget::default(),
        )
        .unwrap()
        .unwrap();
    let output: Value =
        serde_json::from_slice(&plan.materialize(&BTreeMap::new()).unwrap()).unwrap();
    assert_eq!(output["items"], json!([]));
}

#[test]
fn distinct_original_authorities_receive_distinct_routes_even_with_the_same_effective_port() {
    let rules: Vec<DocumentRule> =
        serde_yaml::from_str("- fields: [{path: /*, format: url}]").unwrap();
    let plan = CompiledRewrite::compile(&rules)
        .unwrap()
        .inspect(
            br#"["http://10.0.0.1/a","http://10.0.0.1:80/b"]"#,
            RewriteBudget::default(),
        )
        .unwrap()
        .unwrap();
    let endpoints = plan.endpoints().collect::<Vec<_>>();
    assert_eq!(endpoints.len(), 2);
    assert_ne!(endpoints[0].alias, endpoints[1].alias);
    assert!(
        endpoints
            .iter()
            .all(|endpoint| endpoint.alias.split('.').next().unwrap().len() <= 63)
    );
}
