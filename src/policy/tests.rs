use super::*;
mod literal_paths;

fn native_policy(api: &str) -> TrafficPolicy {
    parse_policy(
        &serde_json::json!({"format":POLICY_FORMAT,"rules":[{
            "id":"header","match":{"api":api},"effect":{"kind":"response_header_date",
                "header":"content-disposition","parameter":"filename","format":"%Y-%m-%d"},
            "proof":{"source":"source.py:1","fact":"Source renders the current request date"}
        }]})
        .to_string(),
    )
    .unwrap()
}

#[test]
fn endpoint_identity_remains_explicit_in_native_aliases() {
    for value in ["cache:6379", "127.0.0.1:11211", "[::1]:6379"] {
        assert_eq!(Endpoint::parse(value).unwrap().to_string(), value);
    }
    for value in [
        "cache",
        "cache:0",
        "redis://cache:6379",
        "user@cache:6379",
        "*:6379",
        "::1:6379",
    ] {
        assert!(Endpoint::parse(value).is_err(), "{value}");
    }
    for database in [serde_json::json!("app"), serde_json::json!(-1)] {
        assert!(
            parse_policy(
                &serde_json::json!({"format":POLICY_FORMAT,"resources":{"cache":{
            "protocol":"redis","endpoint":"cache:6379","database":database}}})
                .to_string()
            )
            .is_err()
        );
    }
}

#[test]
fn proof_changes_preserve_runtime_native_behavior_identity() {
    let document = native_policy("GET /sessions");
    let before = compile_policy(&document).unwrap();
    let mut changed = document.clone();
    let PolicyRule::Native(rule) = &mut changed.rules[0] else {
        unreachable!()
    };
    rule.proof
        .as_mut()
        .unwrap()
        .fact
        .push_str(" in the HTTP response");
    let after = compile_policy(&changed).unwrap();
    assert_eq!(before.fingerprints.full, after.fingerprints.full);
    assert_eq!(before.fingerprints.runtime, after.fingerprints.runtime);
    assert_eq!(before.fingerprints.capture, after.fingerprints.capture);
    assert_eq!(
        before.fingerprints.classification,
        after.fingerprints.classification
    );
}

#[test]
fn all_closed_capabilities_have_one_descriptor_and_proof_requirements() {
    for id in [
        CapabilityId::Unordered,
        CapabilityId::RelativeTime,
        CapabilityId::Duration,
        CapabilityId::RebaseTime,
        CapabilityId::Identity,
    ] {
        assert_eq!(
            capabilities().iter().filter(|item| item.id == id).count(),
            1
        );
        assert!(!id.descriptor().source_proof.is_empty());
        assert!(!id.name().is_empty());
    }
}

#[test]
fn malformed_native_rule_errors_identify_rule_and_typed_field() {
    let error=parse_policy("format: traffic-policy/v2\nrules:\n- id: wrong-native\n  match: {api: 'GET /test'}\n  effect: {kind: response_generated, unexpected: true}\n  proof: {source: Source, fact: 'A typed fact'}\n").unwrap_err();
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("wrong-native"), "{diagnostic}");
    assert!(!diagnostic.contains("did not match any variant of untagged enum PolicyRule"));
}

#[test]
fn documented_self_contained_examples_compile() {
    let document = include_str!("../../docs/unified-rule-contracts.md");
    let mut examples = 0;
    for block in document.split("```yaml\n").skip(1) {
        let yaml = block.split("```").next().unwrap();
        if yaml.starts_with("format: traffic-policy/v2") {
            parse_policy(yaml)
                .unwrap_or_else(|error| panic!("documented policy is invalid: {error:#}"));
            examples += 1;
        }
    }
    assert!(examples >= 1);
}
