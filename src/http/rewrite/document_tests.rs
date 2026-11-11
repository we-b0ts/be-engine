use super::*;
use serde_json::{Value, json};

#[tokio::test]
async fn declared_nested_documents_register_real_routes_and_normalize_response_headers() {
    let config: HttpResponseRewriteConfig = serde_yaml::from_str(
        r#"
rules:
- name: authored-cache-config
  authorities: [config.test]
  methods: [GET]
  path: /config
  plugin:
    name: documents
    rules:
    - decode: [{path: /body/nodes/*/value, codec: yaml}]
      fields: [{path: /*/master, format: host_port, protocol: redis}]
      transforms: [{op: remove, path: /*/master_l1}]
"#,
    )
    .unwrap();
    let registry = FakeDnsRegistry::new("198.19.0.0/16").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(ETAG, "old".parse().unwrap());
    let input = serde_json::to_vec(&json!({"body":{"nodes":[{"value":"cache:\n  master: 10.0.0.1:6379\n  master_l1: local\n  keep: 7\n"}]}})).unwrap();
    let output = apply(
        &CompiledRewrites::new(&config).unwrap(),
        &registry,
        &KubectlProxyManager::default(),
        "",
        1024 * 1024,
        RewriteInput {
            method: &Method::GET,
            uri: &"/config".parse().unwrap(),
            authority: Some("config.test"),
            status: StatusCode::OK,
            headers: &headers,
            body: &input,
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert!(output.headers.get(ETAG).is_none());
    assert_eq!(
        output.headers[CONTENT_LENGTH],
        output.body.len().to_string()
    );
    assert_eq!(output.discovered_tcp_targets.len(), 1);
    let target = &output.discovered_tcp_targets[0];
    assert_eq!(target.protocol, "redis");
    assert_eq!(target.upstream_ip, Ipv4Addr::new(10, 0, 0, 1));
    let document: Value = serde_json::from_slice(&output.body).unwrap();
    let embedded: Value =
        serde_yaml::from_str(document["body"]["nodes"][0]["value"].as_str().unwrap()).unwrap();
    assert_eq!(
        embedded["cache"]["master"],
        format!("{}:6379", target.advertised_ip)
    );
    assert!(embedded["cache"].get("master_l1").is_none());
    assert_eq!(embedded["cache"]["keep"], 7);
}
