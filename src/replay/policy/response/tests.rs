use super::*;

fn dynamic(pointer: &str) -> DynamicResponseRule {
    DynamicResponseRule {
        pointer: pointer.to_string(),
        mechanisms: vec![DynamicResponseMechanism::Uuid],
        source_evidence: "src/token.rs:issue_token".to_string(),
        source_example: "<redacted source UUID>".to_string(),
        target_example: "<redacted target UUID>".to_string(),
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
    }
}

#[test]
fn matches_exact_and_segment_pattern_apis() {
    let rules = ResponseRules {
        json: BTreeMap::from([
            (
                "GET /api/resource/token".to_string(),
                JsonResponseRules {
                    dynamic: vec![dynamic("/content")],
                    ..Default::default()
                },
            ),
            (
                "GET /api/sessions/*".to_string(),
                JsonResponseRules {
                    dynamic: vec![dynamic("/data/id")],
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
                    dynamic: vec![dynamic("/content")],
                    ..Default::default()
                },
            ),
            (
                "GET /api/sessions/current".to_string(),
                JsonResponseRules {
                    dynamic: vec![dynamic("/content")],
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
                dynamic: vec![dynamic("/content/0/id")],
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
                dynamic: vec![dynamic("/followers_count")],
                counter: vec![counter("/followers_count")],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn rejects_json_rules_on_the_motan_carrier() {
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

    assert!(validate_response_rules(&rules).is_err());
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
fn rejects_dynamic_rules_without_auditable_evidence() {
    let rules = ResponseRules {
        json: BTreeMap::from([(
            "GET /api/resource".to_string(),
            JsonResponseRules {
                dynamic: vec![DynamicResponseRule {
                    pointer: "/content".to_string(),
                    mechanisms: vec![DynamicResponseMechanism::Uuid],
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
