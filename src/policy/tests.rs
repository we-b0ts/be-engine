use super::*;
mod literal_paths;

fn json_rule(surface: &str) -> String {
    let selector = if surface == "api.response" {
        "api: GET /sessions"
    } else {
        "api: GET /sessions\n      resource: {protocol: redis, endpoint: 'cache:6379', database: 0}\n      operation: GET\n      key: {prefix: 'session:'}"
    };
    format!(
        "format: traffic-policy/v1\nrules:\n  - id: session\n    surface: {surface}\n    match:\n      {selector}\n    slot: {}\n    codec: json\n    contract:\n      /expires_at: {{kind: time, format: unix_microseconds, relation: preserve_offset, anchor: case.request_start}}\n    proof: {{source: 'src/session.rs:12-18', fact: 'Expiry is request time plus a fixed lifetime'}}\n",
        if surface == "api.response" {
            "body"
        } else {
            "value"
        }
    )
}

#[test]
fn three_surfaces_compile_to_distinct_typed_effects() {
    for surface in ["api.response", "dependency.request", "dependency.response"] {
        let document = parse_policy(&json_rule(surface)).unwrap();
        let compiled = compile_policy(&document).unwrap();
        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(
            compiled.rules[0].effect,
            if surface == "dependency.response" {
                RuleEffect::Deliver
            } else {
                RuleEffect::Compare
            }
        );
        assert_eq!(compiled.rules[0].capabilities, [CapabilityId::RelativeTime]);
        assert_eq!(
            &compiled.rules[0].rule,
            document.rules[0].as_value().unwrap()
        );
    }
}

#[test]
fn delivery_reuses_only_same_rule_declared_timestamps() {
    let valid = format!(
        "{}    delivery: {{rebase_time: [/expires_at]}}\n",
        json_rule("dependency.response")
    );
    let compiled = compile_policy(&parse_policy(&valid).unwrap()).unwrap();
    assert!(compiled.rules[0].delivery_time.contains_key("/expires_at"));
    assert!(
        compiled.rules[0]
            .capabilities
            .contains(&CapabilityId::RebaseTime)
    );
    for invalid in [
        valid.replace("rebase_time: [/expires_at]", "rebase_time: [/other]"),
        valid.replace(
            "rebase_time: [/expires_at]",
            "rebase_time: [/expires_at, /expires_at]",
        ),
        valid.replace("dependency.response", "dependency.request"),
    ] {
        assert!(parse_policy(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn unknown_fields_unsupported_contracts_and_duplicate_paths_fail_closed() {
    let raw = json_rule("api.response");
    for invalid in [
        raw.replace("format: traffic-policy/v1", "format: traffic-policy/v2"),
        raw.replace("codec: json", "codec: json\n    ignore: true"),
        raw.replace("kind: time", "kind: random"),
        raw.replace("relation: preserve_offset", "relation: ignore"),
        raw.replace("anchor: case.request_start", "anchor: arbitrary_clock"),
        raw.replace(
            "    proof:",
            "      /expires_at: {kind: unordered}\n    proof:",
        ),
        raw.replace(
            "fact: 'Expiry is request time plus a fixed lifetime'",
            "fact: ''",
        ),
    ] {
        assert!(parse_policy(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn source_conditions_are_typed_and_missing_or_wrong_types_never_match() {
    let raw = format!(
        "{}    when:\n      request_body_json:\n        /mode: {{not_equals: offline}}\n",
        json_rule("api.response")
    );
    let document = parse_policy(&raw).unwrap();
    let condition = document.rules[0].as_value().unwrap().when.as_ref().unwrap();
    assert!(condition.matches_body(&serde_json::json!({"mode":"online"})));
    for body in [
        serde_json::json!({}),
        serde_json::json!({"mode":null}),
        serde_json::json!({"mode":1}),
        serde_json::json!({"mode":"offline"}),
    ] {
        assert!(!condition.matches_body(&body));
    }
    assert!(parse_policy(&raw.replace("not_equals: offline", "not_equals: null")).is_err());
    assert!(parse_policy(&raw.replace("/mode:", "/modes/*:")).is_err());
}

#[test]
fn endpoint_and_database_identity_are_explicit() {
    for value in ["cache:6379", "127.0.0.1:11211", "[::1]:6379"] {
        let endpoint = Endpoint::parse(value).unwrap();
        assert_eq!(endpoint.to_string(), value);
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
    assert!(
        parse_policy(&json_rule("dependency.request").replace("database: 0", "database: app"))
            .is_err()
    );
    assert!(
        parse_policy(&json_rule("dependency.request").replace("database: 0", "database: -1"))
            .is_err()
    );
}

#[test]
fn protobuf_bindings_use_same_capabilities_and_preserve_type_requirements() {
    let raw = json_rule("dependency.request")
        .replace("codec: json", "codec:\n      kind: protobuf\n      fields:\n        /expires_at: {field_path: [3, 1], field_type: int64}");
    let compiled = compile_policy(&parse_policy(&raw).unwrap()).unwrap();
    assert_eq!(compiled.rules[0].capabilities, [CapabilityId::RelativeTime]);
    for invalid in [
        raw.replace("field_type: int64", "field_type: string"),
        raw.replace("field_path: [3, 1]", "field_path: [3, 0]"),
        raw.replace("field_path: [3, 1]", "field_path: [19000]"),
        raw.replace("field_type: int64", "field_type: int64, repeated: true"),
    ] {
        assert!(parse_policy(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn nested_unordered_elements_can_have_independent_time_contracts() {
    let raw = json_rule("api.response").replace(
        "      /expires_at:",
        "      /members: {kind: unordered}\n      /members/*/expires_at:",
    );
    assert!(parse_policy(&raw).is_ok());
    assert!(parse_policy(&raw.replace("/members/*/expires_at", "/members/0/expires_at")).is_err());
    let invalid = json_rule("api.response").replace(
        "    proof:",
        "      /expires_at/child: {kind: unordered}\n    proof:",
    );
    assert!(parse_policy(&invalid).is_err());
}

#[test]
fn proof_only_changes_do_not_change_executed_behavior_fingerprint() {
    let document = parse_policy(&json_rule("api.response")).unwrap();
    let before = compile_policy(&document).unwrap();
    let mut changed = document.clone();
    changed.rules[0]
        .as_value_mut()
        .unwrap()
        .proof
        .fact
        .push_str(" and is used to validate expiry");
    let after = compile_policy(&changed).unwrap();
    assert_ne!(before.fingerprints.full, after.fingerprints.full);
    assert_eq!(before.fingerprints.runtime, after.fingerprints.runtime);
    changed.rules[0]
        .as_value_mut()
        .unwrap()
        .contract
        .insert("/members".into(), FieldContract::Unordered);
    assert_ne!(
        before.fingerprints.runtime,
        compile_policy(&changed).unwrap().fingerprints.runtime
    );
    assert_eq!(before.fingerprints.capture, after.fingerprints.capture);
    assert_eq!(
        before.fingerprints.classification,
        after.fingerprints.classification
    );
}

#[test]
fn all_closed_capabilities_have_one_descriptor_and_proof_requirements() {
    let registered = capabilities();
    for id in [
        CapabilityId::Unordered,
        CapabilityId::RelativeTime,
        CapabilityId::Duration,
        CapabilityId::RebaseTime,
    ] {
        assert_eq!(registered.iter().filter(|item| item.id == id).count(), 1);
        assert!(!id.descriptor().source_proof.is_empty());
        assert!(!id.name().is_empty());
    }
}

#[test]
fn naive_relative_times_allow_omitted_offsets_and_validate_optional_offsets() {
    let raw = json_rule("api.response").replace(
        "format: unix_microseconds",
        "format: iso8601_naive, utc_offset: '+08:00'",
    );
    let policy = parse_policy(&raw).unwrap();
    let time = policy.rules[0].as_value().unwrap().contract["/expires_at"]
        .time()
        .unwrap();
    assert!(time.utc_offset.is_none());
    assert_eq!(time.offset().unwrap().unwrap().local_minus_utc(), 0);
    let implicit = raw.replace(", utc_offset: '+08:00'", "");
    let policy = parse_policy(&implicit).unwrap();
    let time = policy.rules[0].as_value().unwrap().contract["/expires_at"]
        .time()
        .unwrap();
    assert!(time.utc_offset.is_none());
    assert_eq!(time.offset().unwrap().unwrap().local_minus_utc(), 0);
    assert!(parse_policy(&implicit.replace("preserve_offset", "request_window")).is_err());
    let window = parse_policy(&raw.replace("preserve_offset", "request_window")).unwrap();
    assert_eq!(
        window.rules[0].as_value().unwrap().contract["/expires_at"]
            .time()
            .unwrap()
            .offset()
            .unwrap()
            .unwrap()
            .local_minus_utc(),
        8 * 3600
    );
    for invalid in [
        raw.replace("'+08:00'", "'+24:00'"),
        raw.replace("'+08:00'", "'Asia/Shanghai'"),
        raw.replace("iso8601_naive", "unix_seconds"),
    ] {
        assert!(parse_policy(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn overlapping_scopes_and_wildcard_leaf_ownership_are_rejected() {
    let mut policy = parse_policy(&json_rule("dependency.request")).unwrap();
    let mut other = policy.rules[0].as_value().unwrap().clone();
    other.id = "other".into();
    other.selector.api = None;
    other.selector.key = Some(KeySelector {
        exact: Some("session:123".into()),
        ..Default::default()
    });
    policy.rules.push(other.into());
    assert!(compile_policy(&policy).is_err());
    policy.rules[1]
        .as_value_mut()
        .unwrap()
        .selector
        .resource
        .as_mut()
        .unwrap()
        .database = Some(Database::Index(1));
    compile_policy(&policy).unwrap();
    let mut policy = parse_policy(&json_rule("api.response")).unwrap();
    let time = policy.rules[0]
        .as_value_mut()
        .unwrap()
        .contract
        .remove("/expires_at")
        .unwrap();
    policy.rules[0]
        .as_value_mut()
        .unwrap()
        .contract
        .insert("/members/*/time".into(), time.clone());
    policy.rules[0]
        .as_value_mut()
        .unwrap()
        .contract
        .insert("/members/0/time".into(), time);
    assert!(compile_policy(&policy).is_err());
}

#[test]
fn protobuf_bindings_cannot_hide_scalar_ancestors_or_repeated_message_scope() {
    let mut policy = parse_policy(&json_rule("api.response")).unwrap();
    policy.rules[0].as_value_mut().unwrap().contract.clear();
    policy.rules[0]
        .as_value_mut()
        .unwrap()
        .contract
        .insert("/members".into(), FieldContract::Unordered);
    policy.rules[0].as_value_mut().unwrap().codec = Codec::Protobuf(ProtobufCodec {
        fields: std::collections::BTreeMap::from([
            (
                "/members".into(),
                ProtobufField {
                    field_path: vec![3],
                    field_type: ProtobufType::Message,
                    repeated: true,
                },
            ),
            (
                "/members/*/expires".into(),
                ProtobufField {
                    field_path: vec![3, 1],
                    field_type: ProtobufType::Int64,
                    repeated: false,
                },
            ),
        ]),
    });
    compile_policy(&policy).unwrap();
    let Codec::Protobuf(codec) = &mut policy.rules[0].as_value_mut().unwrap().codec else {
        unreachable!()
    };
    let child = codec.fields.remove("/members/*/expires").unwrap();
    codec.fields.insert("/expires".into(), child);
    assert!(compile_policy(&policy).is_err());
    let Codec::Protobuf(codec) = &mut policy.rules[0].as_value_mut().unwrap().codec else {
        unreachable!()
    };
    codec.fields.get_mut("/members").unwrap().field_type = ProtobufType::Int64;
    assert!(compile_policy(&policy).is_err());
}

#[test]
fn malformed_rule_errors_identify_the_rule_and_typed_field() {
    let error = parse_policy(
        r#"format: traffic-policy/v1
rules:
  - id: wrong-native
    match: {api: GET /test}
    effect: {kind: response_generated, unexpected: true}
    proof: {source: Source, fact: A typed fact}
"#,
    )
    .unwrap_err();
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("wrong-native"), "{diagnostic}");
    assert!(
        !diagnostic.contains("did not match any variant of untagged enum PolicyRule"),
        "{diagnostic}"
    );
}

#[test]
fn hget_field_scopes_are_explicit_and_disjoint() {
    let mut document = parse_policy(&json_rule("dependency.response")).unwrap();
    let first = document.rules[0].as_value_mut().unwrap();
    first.selector.operation = Some("HGET".into());
    first.selector.hash_field = Some(KeySelector {
        exact: Some("one".into()),
        ..Default::default()
    });
    let mut second = first.clone();
    second.id = "second-field".into();
    second.selector.hash_field.as_mut().unwrap().exact = Some("two".into());
    document.rules.push(second.into());
    compile_policy(&document).unwrap();
    document.rules[1]
        .as_value_mut()
        .unwrap()
        .selector
        .hash_field = None;
    assert!(compile_policy(&document).is_err());
    document.rules.pop();
    document.rules[0].as_value_mut().unwrap().selector.operation = Some("GET".into());
    assert!(compile_policy(&document).is_err());
}

#[test]
fn documented_self_contained_examples_compile() {
    let document = include_str!("../../docs/unified-rule-contracts.md");
    let mut examples = 0;
    for block in document.split("```yaml\n").skip(1) {
        let yaml = block.split("```").next().unwrap();
        if yaml.starts_with("format: traffic-policy/v1") {
            parse_policy(yaml)
                .unwrap_or_else(|error| panic!("documented policy is invalid: {error:#}"));
            examples += 1;
        }
    }
    assert!(examples >= 2);
}
