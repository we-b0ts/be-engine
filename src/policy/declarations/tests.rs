use crate::policy::{compile_policy, parse_policy, render_policy};

#[test]
fn aliases_do_not_create_field_rules_and_roundtrip() {
    let policy = parse_policy("format: traffic-policy/v2\nresources:\n  cache: {protocol: redis, endpoint: 'cache.test:6379', database: 0}\njson:\n  fields:\n    /id: {kind: identity, formats: [uuid]}\n").unwrap();
    assert!(compile_policy(&policy).unwrap().rules.is_empty());
    let rendered = render_policy(&policy).unwrap();
    assert_eq!(parse_policy(&rendered).unwrap(), policy);
}

#[test]
fn retired_field_authoring_is_rejected_instead_of_lowered() {
    for document in [
        "responses: {}",
        "resources:\n  db: {protocol: mysql, endpoint: 'db.test:3306', tables: {}}",
        "resources:\n  cache: {protocol: redis, endpoint: 'cache.test:6379', keys: []}",
        "resources:\n  cache: {protocol: redis, endpoint: 'cache.test:6379', proof: {source: x, fact: y}}",
        "rules: [{id: old, surface: api.response, match: {api: 'GET /x'}, slot: body, codec: json, contract: {'/id': unordered}, proof: {source: 'source.py:1', fact: old}}]",
    ] {
        assert!(
            parse_policy(&format!("format: traffic-policy/v2\n{document}\n")).is_err(),
            "{document}"
        );
    }
    let native = "format: traffic-policy/v2\nrules:\n- id: old-ref\n  match: {resource: {protocol: redis, endpoint: 'cache.test:6379'}, operation: SET, key: {kind: exact, value: item}}\n  effect:\n    kind: redis_sequence\n    commands:\n    - operation: SET\n      arguments:\n        1: {field_ref: {resource: cache, key: 0, pointer: /at}}\n  proof: {source: 'source.py:1', fact: 'An actual Source write'}\n";
    assert!(parse_policy(native).is_err());
}
