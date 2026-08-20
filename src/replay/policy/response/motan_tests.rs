use super::*;

#[test]
fn accepts_protocol_only_then_reviewable_protobuf_paths() {
    let protocol_only = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/example": {}
"#,
    )
    .unwrap();
    validate_response_rules(&protocol_only).unwrap();
    assert!(
        protocol_only.protobuf["MOTAN /rpc/example"]
            .unordered
            .is_empty()
    );

    let reviewed = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/example":
    unordered:
      - field_path: [3, 1, 6, 3]
        display_path: rule_collection.experiments.groups.white_list
        element_type: string
        source_evidence: src/rule.rs:white_list is a set
"#,
    )
    .unwrap();
    validate_response_rules(&reviewed).unwrap();
    let path = &reviewed.protobuf["MOTAN /rpc/example"].unordered[0];
    assert_eq!(path.field_path.display_path(), "3.1.6.3");
}

#[test]
fn unordered_motan_selectors_require_source_evidence() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/example":
    unordered:
      - field_path: [3]
        display_path: response.names
        element_type: string
"#,
    );

    assert!(rules.is_err());
}

#[test]
fn does_not_offer_bytes_as_an_unordered_element_type() {
    let error = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/example":
    unordered:
      - field_path: [3]
        display_path: payload
        element_type: bytes
        source_evidence: src/rule.rs:payload is a set
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("unknown variant `bytes`"));
}

#[test]
fn accepts_reviewable_hessian2_value_paths() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
hessian2:
  "MOTAN /rpc/example":
    unordered:
      - value_path: [ruleCollection, groups, "*", whiteList]
        display_path: rule_collection.groups[].white_list
        source_evidence: src/rule.rs:white_list is a set
"#,
    )
    .unwrap();

    validate_response_rules(&rules).unwrap();
    let path = &rules.hessian2["MOTAN /rpc/example"].unordered[0];
    assert_eq!(
        path.value_path.display_path(),
        "$.ruleCollection.groups[*].whiteList"
    );
}

#[test]
fn rejects_a_selector_from_another_body_protocol() {
    let error = serde_yaml::from_str::<ResponseRules>(
        r#"
hessian2:
  "MOTAN /rpc/example":
    unordered:
      - field_path: [3]
        display_path: response.names
        element_type: string
        source_evidence: src/rule.rs:names is a set
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("unknown field `field_path`"));
}

#[test]
fn requires_a_semantic_display_path_for_review() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/example":
    unordered:
      - field_path: [3, 1, 6, 3]
        display_path: 3.1.6.3
        element_type: string
        source_evidence: src/rule.rs:white_list is a set
"#,
    )
    .unwrap();

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn accepts_reviewable_hessian2_joined_string_paths() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
hessian2:
  "MOTAN /rpc/example":
    unordered_joined_string:
      - value_path: [result, whiteList]
        display_path: cache_result.white_list
        separator: ","
        source_evidence: src/cache.rs:white_list is set-joined
"#,
    )
    .unwrap();

    validate_response_rules(&rules).unwrap();
    let joined = &rules.hessian2["MOTAN /rpc/example"].unordered_joined_string[0];
    assert_eq!(joined.value_path.display_path(), "$.result.whiteList");
    assert_eq!(joined.separator, ",");
}

#[test]
fn rejects_joined_string_rules_on_protobuf() {
    let error = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/example":
    unordered_joined_string:
      - value_path: [result, whiteList]
        display_path: cache_result.white_list
        separator: ","
        source_evidence: src/cache.rs:white_list is set-joined
"#,
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("unknown field `unordered_joined_string`")
    );
}

#[test]
fn rejects_a_joined_string_path_with_an_empty_separator() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
hessian2:
  "MOTAN /rpc/example":
    unordered_joined_string:
      - value_path: [result, whiteList]
        display_path: cache_result.white_list
        separator: ""
        source_evidence: src/cache.rs:white_list is set-joined
"#,
    )
    .unwrap();

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn rejects_a_joined_string_path_colliding_with_an_unordered_list_path() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
hessian2:
  "MOTAN /rpc/example":
    unordered:
      - value_path: [result, whiteList]
        display_path: cache_result.white_list
        source_evidence: src/cache.rs:white_list is a set
    unordered_joined_string:
      - value_path: [result, whiteList]
        display_path: cache_result.white_list_joined
        separator: ","
        source_evidence: src/cache.rs:white_list is set-joined
"#,
    )
    .unwrap();

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn rejects_overlapping_body_protocol_routes() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/*": {}
hessian2:
  "MOTAN /rpc/example": {}
"#,
    )
    .unwrap();

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn rejects_the_old_motan_protocol_shape() {
    let error = serde_yaml::from_str::<ResponseRules>(
        r#"
motan:
  "MOTAN /rpc/example":
    protocol: protobuf
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("unknown field `motan`"));
}
