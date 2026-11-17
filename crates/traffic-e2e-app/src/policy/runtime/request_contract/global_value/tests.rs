use super::*;

const A: &str = "11111111-1111-4111-8111-111111111111";
const X: &str = "22222222-2222-4222-8222-222222222222";
const Y: &str = "33333333-3333-4333-8333-333333333333";

fn owner() -> RequestContracts {
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /item_id: {kind: identity, formats: [uuid]}
    /item/id: {kind: identity, formats: [uuid]}
    /created_at: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap();
    let mut owner = RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    owner.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            method: "POST".into(),
            path: "/any-api".into(),
            source_uri: String::new(),
            source_input_error: None,
            recorded: DateTime::from_timestamp(1000, 0),
            actual: DateTime::from_timestamp(2000, 0),
            dir: PathBuf::new(),
            dependencies_path: PathBuf::new(),
            conditions: Default::default(),
            source_body: None,
        },
    );
    owner
}

fn url_owner() -> RequestContracts {
    let mut owner = owner();
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /session_id: {kind: identity, formats: [uuid]}
    /authorize_url: {kind: url, formats: [url]}
    /links/*: {kind: url, formats: [url]}
"#,
    )
    .unwrap();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    owner
}

#[test]
fn url_query_delivery_shares_one_uncommitted_identity_with_root_and_other_urls() {
    let owner = url_owner();
    let original = serde_json::json!({"session_id":A,
        "authorize_url":format!("https://auth.test/authorize?session_id={A}&keep=x%20y#fixed"),
        "links":[format!("https://auth.test/other?session_id={A}")]
    });
    let bytes = serde_json::to_vec(&original).unwrap();
    let delivery = crate::value_contract::response_delivery::Delivery::prepare_global(
        &bytes,
        owner.global_json().unwrap(),
        Default::default(),
    )
    .unwrap();
    assert!(delivery.has_identities());
    let (rendered, decision) = delivery
        .render_with_identities(Utc::now(), &owner, "case")
        .unwrap();
    assert!(
        !owner.has_identities("case"),
        "rendering must not publish candidate correspondences"
    );
    let value: Value = serde_json::from_slice(&rendered).unwrap();
    let id = value["session_id"].as_str().unwrap();
    assert_eq!(
        value["authorize_url"],
        format!("https://auth.test/authorize?session_id={id}&keep=x%20y#fixed")
    );
    assert_eq!(
        value["links"][0],
        format!("https://auth.test/other?session_id={id}")
    );
    let compared = owner
        .compare_global_value(&bytes, &rendered, &[], Default::default())
        .unwrap();
    assert!(compared.passed(), "{:?}", compared.differences);
    owner.commit_identity(decision).unwrap();
    let (again, _) = delivery
        .render_with_identities(Utc::now(), &owner, "case")
        .unwrap();
    assert_eq!(rendered, again);
}

#[test]
fn a_url_only_echo_reuses_the_accepted_primary_json_identity() {
    let owner = url_owner();
    let before = serde_json::json!({"session_id":A}).to_string();
    let after = serde_json::json!({"session_id":X}).to_string();
    let comparison = owner
        .compare_global_value(before.as_bytes(), after.as_bytes(), &[], Default::default())
        .unwrap();
    owner
        .commit_identity(owner.identity_decision("case", &comparison).unwrap())
        .unwrap();
    let source = serde_json::json!({"authorize_url":format!("https://auth.test/authorize?session_id={A}&keep=x%20y")}).to_string();
    let prepared = crate::value_contract::response_delivery::Delivery::prepare_global(
        source.as_bytes(),
        owner.global_json().unwrap(),
        Default::default(),
    )
    .unwrap();
    let (payload, _) = prepared
        .render_with_identities(Utc::now(), &owner, "case")
        .unwrap();
    let value: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        value["authorize_url"],
        format!("https://auth.test/authorize?session_id={X}&keep=x%20y")
    );
    let unchanged = owner
        .compare_global_value(
            source.as_bytes(),
            source.as_bytes(),
            &[],
            Default::default(),
        )
        .unwrap();
    assert!(
        owner.identity_decision("case", &unchanged).is_err(),
        "a byte-equal URL must not escape an already accepted Source-to-Target id relation"
    );
}

#[test]
fn global_time_delivery_and_optional_fields_preserve_unselected_values() {
    let owner = owner();
    let clocks = owner.contract_clocks(
        Some("case"),
        DateTime::from_timestamp(1000, 0),
        DateTime::from_timestamp(2000, 0),
        None,
        None,
    );
    let source = br#"{ "created_at": 1005, "stable": "unchanged" }"#;
    let delivery = crate::value_contract::response_delivery::Delivery::prepare_global(
        source,
        owner.global_json().unwrap(),
        clocks,
    )
    .unwrap();
    let bytes = delivery
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    let parsed = crate::json_value::parse(&bytes).unwrap();
    assert_eq!(parsed["created_at"], 2005);
    assert_eq!(parsed["stable"], "unchanged");
    let absent = br#"{ "stable": true }"#;
    let delivery = crate::value_contract::response_delivery::Delivery::prepare_global(
        absent,
        owner.global_json().unwrap(),
        Default::default(),
    )
    .unwrap();
    assert_eq!(delivery.render(Utc::now()).unwrap(), absent);
    assert!(delivery.validation().evaluated.is_empty());
    assert!(
        !owner
            .compare_global_value(absent, br#"{"stable":true,"created_at":2000}"#, &[], clocks)
            .unwrap()
            .passed()
    );
    assert!(
        owner
            .compare_global_value(
                br#"{"created_at":null}"#,
                br#"{"created_at":null}"#,
                &[],
                clocks
            )
            .unwrap()
            .passed()
    );
    assert!(
        owner
            .compare_global_value(b"opaque", b"opaque", &[], Default::default())
            .unwrap()
            .passed()
    );
    assert!(
        !owner
            .compare_global_value(b"opaque", b"changed", &[], Default::default())
            .unwrap()
            .passed()
    );
}

#[test]
fn delivery_pins_equal_unrecognized_identity_scalars_and_keeps_null_mapping_free() {
    for scalar in [
        serde_json::json!(""),
        serde_json::json!("external-id"),
        serde_json::json!(false),
        serde_json::json!(1.5),
    ] {
        let owner = owner();
        let source = serde_json::json!({"item_id":scalar});
        let mut logical = source.clone();
        let (decision, paths) = owner
            .translate_global_identity_logical("case", &source, &mut logical)
            .unwrap();
        assert_eq!(logical, source);
        assert!(paths.is_empty());
        owner.commit_identity(decision).unwrap();
        assert!(owner.has_identities("case"));
    }
    let owner = owner();
    let source = serde_json::json!({"item_id":null});
    let mut logical = source.clone();
    let (decision, _) = owner
        .translate_global_identity_logical("case", &source, &mut logical)
        .unwrap();
    owner.commit_identity(decision).unwrap();
    assert!(!owner.has_identities("case"));
}

#[test]
fn an_unrecognized_identity_delivery_never_rewrites_a_previously_renamed_value() {
    let owner = owner();
    owner
        .commit_identity(
            owner
                .preview_identity_pairs(
                    "case",
                    &[crate::value_contract::identities::IdentityPair {
                        source: serde_json::json!("external-id").to_string(),
                        target: serde_json::json!("changed-id").to_string(),
                    }],
                )
                .unwrap(),
        )
        .unwrap();
    let source = serde_json::json!({"item_id":"external-id"});
    let mut logical = source.clone();
    assert!(
        owner
            .translate_global_identity_logical("case", &source, &mut logical)
            .is_err()
    );
    assert_eq!(logical, source);
}
