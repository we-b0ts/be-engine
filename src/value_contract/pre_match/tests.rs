use super::*;

fn plan() -> CompiledJsonPolicy {
    CompiledJsonPolicy {
        time: Default::default(),
        signatures: Default::default(),
        fields: Default::default(),
        fingerprint: String::new(),
    }
}

#[test]
fn multiple_unproven_fields_match_temporarily_and_keep_proof_drafts() {
    let a =
        br#"{"id":"123e4567-e89b-42d3-a456-426614174000","created_at":1700000000,"text":"same"}"#;
    let b =
        br#"{"id":"123e4567-e89b-42d3-a456-426614174001","created_at":1700000010,"text":"same"}"#;
    let clocks = AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: chrono::DateTime::from_timestamp(1700000000, 0),
            target: chrono::DateTime::from_timestamp(1700000010, 0),
        },
        ..Default::default()
    };
    let checked = preview("case", a, b, &plan(), clocks).unwrap();
    assert!(checked.passed());
    assert_eq!(checked.pre_matches.len(), 2);
    assert_eq!(checked.identity_pairs().len(), 1);
    for candidate in checked.pre_matches {
        assert!(candidate.source_proof_required);
        crate::policy::parse_and_compile_policy(
            &serde_yaml::to_string(&candidate.draft_policy).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn structural_changes_business_scalars_unknown_bytes_and_declared_failures_stay_strict() {
    let a = br#"{"id":"123e4567-e89b-42d3-a456-426614174000","status":1}"#;
    for b in [
        br#"{"id":"123e4567-e89b-42d3-a456-426614174001","status":2}"#.as_slice(),
        br#"{"id":"not-a-uuid","status":1}"#,
        br#"{"id":"123e4567-e89b-42d3-a456-426614174001"}"#,
        b"not json",
    ] {
        assert!(preview("case", a, b, &plan(), Default::default()).is_none());
    }
    let strict = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [{hex: 12}]}\n").unwrap();
    assert!(
        preview(
            "case",
            a,
            br#"{"id":"123e4567-e89b-42d3-a456-426614174001","status":1}"#,
            strict.global_json.as_ref().unwrap(),
            Default::default()
        )
        .is_none()
    );
}

#[test]
fn builtin_dates_never_become_provisional_rule_hints_even_when_another_field_needs_one() {
    let source =
        br#"{"id":"123e4567-e89b-42d3-a456-426614174000","at":"2020-01-01T00:00:00.123Z"}"#;
    let target =
        br#"{"id":"123e4567-e89b-42d3-a456-426614174001","at":"2021-01-01T00:00:00.123Z"}"#;
    let clocks = AnchorClocks::for_request(
        Default::default(),
        crate::value_contract::time::ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2021-01-01T00:00:00Z".parse().unwrap()),
        },
        Default::default(),
    );
    let plan = plan();
    let preview = super::super::hypothesis::preview_json("case", source, target, &plan, clocks);
    let comparison = preview.comparison.unwrap();
    assert_eq!(comparison.pre_matches.len(), 1);
    assert!(
        preview
            .attempts
            .iter()
            .all(|attempt| attempt.candidate.pointer == "/id")
    );
    let invalid =
        br#"{"id":"123e4567-e89b-42d3-a456-426614174001","at":"2021-01-01T00:00:00.123000Z"}"#;
    let preview = super::super::hypothesis::preview_json("case", source, invalid, &plan, clocks);
    assert!(preview.comparison.is_none());
    assert!(
        preview
            .attempts
            .iter()
            .all(|attempt| attempt.candidate.pointer == "/id")
    );
}
