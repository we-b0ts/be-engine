use super::*;

#[test]
fn accepts_protocol_only_then_reviewable_motan_paths() {
    let protocol_only = serde_yaml::from_str::<ResponseRules>(
        r#"
motan:
  "MOTAN /rpc/example":
    protocol: protobuf
"#,
    )
    .unwrap();
    validate_response_rules(&protocol_only).unwrap();
    assert!(
        protocol_only.motan["MOTAN /rpc/example"]
            .unordered_paths
            .is_empty()
    );

    let reviewed = serde_yaml::from_str::<ResponseRules>(
        r#"
motan:
  "MOTAN /rpc/example":
    protocol: protobuf
    unordered_paths:
      - field_path: [3, 1, 6, 3]
        display_path: rule_collection.experiments.groups.white_list
        element_type: string
"#,
    )
    .unwrap();
    validate_response_rules(&reviewed).unwrap();
    let MotanUnorderedPath::Protobuf(path) =
        &reviewed.motan["MOTAN /rpc/example"].unordered_paths[0]
    else {
        panic!("expected protobuf unordered path");
    };
    assert_eq!(path.field_path.display_path(), "3.1.6.3");
}

#[test]
fn does_not_offer_bytes_as_an_unordered_element_type() {
    let error = serde_yaml::from_str::<ResponseRules>(
        r#"
motan:
  "MOTAN /rpc/example":
    protocol: protobuf
    unordered_paths:
      - field_path: [3]
        display_path: payload
        element_type: bytes
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("unknown variant `bytes`"));
}

#[test]
fn accepts_reviewable_hessian2_value_paths() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
motan:
  "MOTAN /rpc/example":
    protocol: hessian2
    unordered_paths:
      - value_path: [ruleCollection, groups, "*", whiteList]
        display_path: rule_collection.groups[].white_list
"#,
    )
    .unwrap();

    validate_response_rules(&rules).unwrap();
    let MotanUnorderedPath::Hessian2(path) = &rules.motan["MOTAN /rpc/example"].unordered_paths[0]
    else {
        panic!("expected Hessian2 unordered path");
    };
    assert_eq!(
        path.value_path.display_path(),
        "$.ruleCollection.groups[*].whiteList"
    );
}

#[test]
fn rejects_unordered_paths_for_another_body_protocol() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
motan:
  "MOTAN /rpc/example":
    protocol: hessian2
    unordered_paths:
      - field_path: [3]
        display_path: response.names
        element_type: string
"#,
    )
    .unwrap();

    assert!(validate_response_rules(&rules).is_err());
}

#[test]
fn requires_a_semantic_display_path_for_review() {
    let rules = serde_yaml::from_str::<ResponseRules>(
        r#"
motan:
  "MOTAN /rpc/example":
    protocol: protobuf
    unordered_paths:
      - field_path: [3, 1, 6, 3]
        display_path: 3.1.6.3
        element_type: string
"#,
    )
    .unwrap();

    assert!(validate_response_rules(&rules).is_err());
}
