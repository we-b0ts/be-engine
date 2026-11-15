use std::{collections::BTreeMap, sync::Arc};
use traffic_policy::{PolicyRegistry, TransformInput};
use traffic_response_rewrite::ResponseRewritePolicy;
use traffic_value::Value;

fn value(value: serde_json::Value) -> Value {
    serde_json::from_value(value).unwrap()
}

fn registry() -> PolicyRegistry {
    let mut registry = PolicyRegistry::default();
    registry.register(Arc::new(ResponseRewritePolicy)).unwrap();
    registry
}

#[test]
fn nested_naming_response_requests_a_route_before_rewriting_the_recorded_value() {
    let registry = registry();
    let configuration = value(serde_json::json!({"rules":[{
        "decode":[{"path":"/body","codec":"json"}],
        "fields":[{"path":"/nodes/*/*/host","format":"ipv4","port_field":"port"}]
    }]}));
    assert!(registry.prepare("documents", &configuration).is_err());
    let policy = registry
        .prepare_transform("documents", &configuration)
        .unwrap();
    let original = serde_json::to_vec(&serde_json::json!({
        "code":200, "body": r#"{"nodes":{"service":[{"host":"10.0.0.7","port":3306,"weight":3}]}}"#
    }))
    .unwrap();
    let plan = policy
        .inspect(&TransformInput {
            bytes: &original,
            context: &Value::Null,
        })
        .unwrap()
        .unwrap();
    assert_eq!(plan.requests().len(), 1);
    assert_eq!(plan.requests()[0].capability, "network.route");
    assert_eq!(
        plan.requests()[0]
            .parameters
            .pointer("/upstream_ip")
            .and_then(Value::as_str),
        Some("10.0.0.7")
    );
    assert!(plan.materialize(&BTreeMap::new()).is_err());
    let plan = policy
        .inspect(&TransformInput {
            bytes: &original,
            context: &Value::Null,
        })
        .unwrap()
        .unwrap();
    let routes = BTreeMap::from([(
        plan.requests()[0].id.clone(),
        value(serde_json::json!({"advertised_ip":"198.19.0.7"})),
    )]);
    let rewritten = plan.materialize(&routes).unwrap();
    let outer: serde_json::Value = serde_json::from_slice(&rewritten.bytes).unwrap();
    let body: serde_json::Value = serde_json::from_str(outer["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        body["nodes"]["service"][0],
        serde_json::json!({"host":"198.19.0.7","port":3306,"weight":3})
    );
    let source: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert!(source["body"].as_str().unwrap().contains("10.0.0.7"));
}

#[test]
fn cache_configuration_uses_the_same_registered_transform_and_route_contract() {
    let registry = registry();
    let configuration = value(serde_json::json!({"rules":[{
        "query":{"action":["lookup"]},
        "decode":[{"path":"/body/nodes/*/value","codec":"yaml"}],
        "fields":[{"path":"/*/master","format":"host_port","recursive":true}]
    }]}));
    let policy = registry
        .prepare_transform("documents", &configuration)
        .unwrap();
    let original = serde_json::to_vec(&serde_json::json!({
        "body":{"nodes":[{"value":"cache:\n  master: [10.0.0.8:6379]\n  mode: stable\n"}]}
    }))
    .unwrap();
    assert!(
        policy
            .inspect(&TransformInput {
                bytes: &original,
                context: &value(serde_json::json!({"query":"action=other"})),
            })
            .unwrap()
            .is_none()
    );
    let plan = policy
        .inspect(&TransformInput {
            bytes: &original,
            context: &value(serde_json::json!({"query":"action=lookup"})),
        })
        .unwrap()
        .unwrap();
    let routes = BTreeMap::from([(
        plan.requests()[0].id.clone(),
        value(serde_json::json!({"advertised_ip":"198.19.0.8"})),
    )]);
    let rewritten = plan.materialize(&routes).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&rewritten.bytes).unwrap();
    let embedded = body["body"]["nodes"][0]["value"].as_str().unwrap();
    assert!(embedded.contains("198.19.0.8:6379"));
    assert!(embedded.contains("stable"));
    assert!(
        PolicyRegistry::default()
            .prepare_transform("documents", &configuration)
            .is_err()
    );
}
