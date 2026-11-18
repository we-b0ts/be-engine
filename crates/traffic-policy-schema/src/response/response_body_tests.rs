use super::*;

#[test]
fn accepts_codec_only_then_reviewable_protobuf_paths() {
    let codec_only = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/example": {}
"#,
    )
    .unwrap();
    validate_response_rules(&codec_only, traffic_extensions::policies()).unwrap();
    assert!(
        codec_only.protobuf["MOTAN /rpc/example"]
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
    validate_response_rules(&reviewed, traffic_extensions::policies()).unwrap();
    let path = &reviewed.protobuf["MOTAN /rpc/example"].unordered[0];
    assert_eq!(path.field_path.display_path(), "3.1.6.3");
}

#[test]
fn docx_timestamp_rules_require_a_safe_part_and_auditable_examples() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
docx:
  "GET /api/tasks/*/export/docx":
    timestamp:
      - part: docProps/core.xml
        element: dcterms:created
        format: rfc3339
        source_evidence: src/docx.rs:generator sets created from the current request clock
        source_example: 2024-01-02T03:04:05Z
        target_example: 2024-01-02T04:04:05Z
"#,
    )
    .unwrap();
    validate_response_rules(&rules, traffic_extensions::policies()).unwrap();

    for part in ["../core.xml", "/docProps/core.xml"] {
        let yaml = format!(
            "docx:\n  'GET /export':\n    timestamp:\n      - part: {part}\n        element: dcterms:created\n        format: rfc3339\n        source_evidence: src/docx.rs:created\n        source_example: old\n        target_example: new\n"
        );
        let rules = serde_yaml::from_str::<ResponseRules>(&yaml).unwrap();
        assert!(validate_response_rules(&rules, traffic_extensions::policies()).is_err());
    }
}

#[test]
fn unordered_response_body_selectors_require_source_evidence() {
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

    validate_response_rules(&rules, traffic_extensions::policies()).unwrap();
    let path = &rules.hessian2["MOTAN /rpc/example"].unordered[0];
    assert_eq!(
        path.value_path.display_path(),
        "$.ruleCollection.groups[*].whiteList"
    );
}

#[test]
fn rejects_a_selector_from_another_body_codec() {
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

    assert!(validate_response_rules(&rules, traffic_extensions::policies()).is_err());
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

    validate_response_rules(&rules, traffic_extensions::policies()).unwrap();
    let joined = &rules.hessian2["MOTAN /rpc/example"].unordered_joined_string[0];
    assert_eq!(joined.value_path.display_path(), "$.result.whiteList");
    assert_eq!(joined.separator, ",");
}

#[test]
fn accepts_reviewable_protobuf_joined_string_paths() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/example":
    unordered_joined_string:
      - field_path: [3, 1]
        display_path: cache_result.white_list
        field_type: string
        separator: ","
        source_evidence: src/cache.rs:white_list is set-joined
"#,
    )
    .unwrap();

    validate_response_rules(&rules, traffic_extensions::policies()).unwrap();
    let joined = &rules.protobuf["MOTAN /rpc/example"].unordered_joined_string[0];
    assert_eq!(joined.field_path.display_path(), "3.1");
    assert_eq!(joined.field_type, ProtobufJoinedStringFieldType::String);
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

    assert!(validate_response_rules(&rules, traffic_extensions::policies()).is_err());
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

    assert!(validate_response_rules(&rules, traffic_extensions::policies()).is_err());
}

#[test]
fn rejects_overlapping_body_codec_routes() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
protobuf:
  "MOTAN /rpc/*": {}
hessian2:
  "MOTAN /rpc/example": {}
"#,
    )
    .unwrap();

    assert!(validate_response_rules(&rules, traffic_extensions::policies()).is_err());
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
