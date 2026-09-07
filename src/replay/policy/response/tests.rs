use super::*;

fn uuid(pointer: &str) -> GeneratedResponseRule {
    GeneratedResponseRule {
        unit: None,
        format: None,
        pointer: pointer.to_string(),
        source_evidence: "src/token.rs:issue_token".to_string(),
        source_example: "<redacted source UUID>".to_string(),
        target_example: "<redacted target UUID>".to_string(),
    }
}

#[test]
fn rejects_overlapping_array_patterns_and_explicit_indexes() {
    for (left, right) in [
        ("/data/*/id", "/data/0/id"),
        ("/data/*/items/0", "/data/1/items/*"),
        ("/data/*/id", "/data"),
    ] {
        let rules = ResponseRules {
            json: BTreeMap::from([(
                "GET /api/resource".into(),
                JsonResponseRules {
                    uuid: vec![uuid(left)],
                    unordered: vec![unordered(right)],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        assert!(
            validate_response_rules(&rules)
                .unwrap_err()
                .to_string()
                .contains("overlapping response rules")
        );
    }
}

fn counter(pointer: &str) -> CounterResponseRule {
    CounterResponseRule {
        pointer: pointer.to_string(),
        source_evidence: "src/user.rs:load live count".to_string(),
        source_example: "100".to_string(),
        target_example: "101".to_string(),
    }
}

fn unordered(pointer: &str) -> JsonUnorderedResponseRule {
    JsonUnorderedResponseRule {
        pointer: pointer.to_string(),
        source_evidence: "src/config.rs:collection is a set".to_string(),
    }
}

#[test]
fn matches_exact_and_segment_pattern_apis() {
    let rules = ResponseRules {
        json: BTreeMap::from([
            (
                "GET /api/resource/token".to_string(),
                JsonResponseRules {
                    uuid: vec![uuid("/content")],
                    ..Default::default()
                },
            ),
            (
                "GET /api/sessions/*".to_string(),
                JsonResponseRules {
                    uuid: vec![uuid("/data/id")],
                    ..Default::default()
                },
            ),
        ]),
        ..Default::default()
    };

    assert_eq!(
        rules
            .matching_replay_fields("GET", "/api/resource/token")
            .iter()
            .map(|field| field.pointer.as_str())
            .collect::<Vec<_>>(),
        vec!["/content"]
    );
    assert_eq!(
        rules
            .matching_replay_fields("GET", "/api/sessions/42")
            .iter()
            .map(|field| field.pointer.as_str())
            .collect::<Vec<_>>(),
        vec!["/data/id"]
    );
}

#[test]
fn rejects_overlapping_routes_for_the_same_pointer() {
    let rules = ResponseRules {
        json: BTreeMap::from([
            (
                "GET /api/sessions/*".to_string(),
                JsonResponseRules {
                    uuid: vec![uuid("/content")],
                    ..Default::default()
                },
            ),
            (
                "GET /api/sessions/current".to_string(),
                JsonResponseRules {
                    uuid: vec![uuid("/content")],
                    ..Default::default()
                },
            ),
        ]),
        ..Default::default()
    };

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn rejects_overlapping_rule_kinds_in_one_json_api() {
    let rules = ResponseRules {
        json: BTreeMap::from([(
            "GET /api/resource".to_string(),
            JsonResponseRules {
                uuid: vec![uuid("/content/0/id")],
                unordered: vec![unordered("/content")],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn rejects_overlapping_replay_and_comparison_rules() {
    let rules = ResponseRules {
        json: BTreeMap::from([(
            "GET /api/users/show".to_string(),
            JsonResponseRules {
                uuid: vec![uuid("/followers_count")],
                counter: vec![counter("/followers_count")],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn accepts_json_rules_on_a_motan_gateway() {
    let rules = ResponseRules {
        json: BTreeMap::from([(
            "MOTAN /rpc/example".to_string(),
            JsonResponseRules {
                unordered: vec![unordered("/content")],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    validate_response_rules(&rules).unwrap();
    assert_eq!(
        rules.matching_replay_fields("MOTAN", "/rpc/example")[0].kind,
        ResponseRuleKind::Unordered
    );
}

#[test]
fn matches_and_identifies_unordered_fields() {
    let rules = ResponseRules {
        json: BTreeMap::from([(
            "GET /api/config/ansible_facts".to_string(),
            JsonResponseRules {
                unordered: vec![unordered("/general/sudo_users")],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    let fields = rules.matching_replay_fields("GET", "/api/config/ansible_facts");

    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].kind, ResponseRuleKind::Unordered);
    assert_eq!(
        fields[0].id,
        "response:unordered:GET /api/config/ansible_facts:/general/sudo_users"
    );
}

#[test]
fn counter_fields_are_available_only_to_comparison_matching() {
    let rules = ResponseRules {
        json: BTreeMap::from([(
            "GET /api/users/show".to_string(),
            JsonResponseRules {
                counter: vec![counter("/followers_count")],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    assert!(
        rules
            .matching_replay_fields("GET", "/api/users/show")
            .is_empty()
    );
    let fields = rules.matching_comparison_fields("GET", "/api/users/show");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].kind, ResponseRuleKind::Counter);
    assert_eq!(
        fields[0].id,
        "response:comparison:counter:GET /api/users/show:/followers_count"
    );
}

#[test]
fn rejects_invalid_json_pointer_escape() {
    assert!(validate_json_pointer("/content/~2").is_err());
}

#[test]
fn rejects_generated_rules_without_auditable_evidence() {
    let rules = ResponseRules {
        json: BTreeMap::from([(
            "GET /api/resource".to_string(),
            JsonResponseRules {
                uuid: vec![GeneratedResponseRule {
                    unit: None,
                    format: None,
                    pointer: "/content".to_string(),
                    source_evidence: "src/token.rs:issue_token".to_string(),
                    source_example: "<same>".to_string(),
                    target_example: "<same>".to_string(),
                }],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn accepts_only_concrete_generated_scalar_rule_kinds() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
json:
  "GET /api/resource":
    timestamp:
      - pointer: /created_at
        format: unix_seconds
        source_evidence: src/resource.rs:created_at uses current time
        source_example: "100"
        target_example: "101"
    duration:
      - pointer: /elapsed
        unit: seconds
        source_evidence: src/resource.rs:elapsed measures runtime duration
        source_example: "10"
        target_example: "11"
    uuid:
      - pointer: /request_id
        source_evidence: src/resource.rs:request_id generates a UUID
        source_example: source-uuid
        target_example: target-uuid
    random:
      - pointer: /nonce
        source_evidence: src/resource.rs:nonce uses random bytes
        source_example: source-nonce
        target_example: target-nonce
"#,
    )
    .unwrap();

    validate_response_rules(&rules).unwrap();
    assert_eq!(response_rule_ids(&rules).len(), 4);
}

#[test]
fn rejects_abstract_or_business_use_generated_rule_keys() {
    for kind in ["dynamic", "nonce", "random_salt"] {
        let yaml = format!(
            r#"
json:
  "GET /api/resource":
    {kind}:
      - pointer: /value
        source_evidence: src/resource.rs:value generation
        source_example: source
        target_example: target
"#
        );
        let error = serde_yaml::from_str::<ResponseRules>(&yaml).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("unknown field `{kind}`"))
        );
    }
}

#[test]
fn rejects_the_old_rule_kind_first_shape() {
    let error = serde_yaml::from_str::<ResponseRules>(
        r#"
dynamic:
  "GET /api/resource":
    - pointer: /content
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("unknown field `dynamic`"));
}
