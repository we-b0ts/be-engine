use super::*;
use serde_json::json;

fn contract(format: IdentityFormat) -> FieldContract {
    FieldContract::Identity {
        binding: "entity".into(),
        prefix: "msg_".into(),
        format,
    }
}

#[test]
fn identity_bindings_span_rule_ids_and_preserve_bijection_without_cross_case_state() {
    let contract = contract(IdentityFormat::Decimal);
    let compare = |source: Value, target: Value, id: &str| {
        super::super::compare(
            &source,
            &target,
            &[Field {
                rule_id: id,
                pointer: "",
                contract: &contract,
            }],
            AnchorClocks::default(),
        )
    };
    let mut result = compare(json!("msg_11"), json!("msg_1001"), "added");
    result.merge_and_validate(compare(json!("msg_11"), json!("msg_1001"), "delta"));
    assert!(result.passed());
    let mut wrong_reference = result.clone();
    wrong_reference.merge_and_validate(compare(json!("msg_11"), json!("msg_1002"), "done"));
    assert!(!wrong_reference.passed());
    result.merge_and_validate(compare(json!("msg_12"), json!("msg_1001"), "second-item"));
    assert!(!result.passed());
    assert!(compare(json!("msg_11"), json!("msg_9000"), "next-case").passed());
}

#[test]
fn identity_strings_validate_uuid_canonical_form_and_decimal_boundaries() {
    for (format, source, target, passed) in [
        (
            IdentityFormat::Decimal,
            "msg_1",
            "msg_18446744073709551615",
            true,
        ),
        (
            IdentityFormat::Decimal,
            "msg_1",
            "msg_18446744073709551616",
            false,
        ),
        (IdentityFormat::Decimal, "msg_0", "msg_1", false),
        (IdentityFormat::Decimal, "msg_01", "msg_1", false),
        (
            IdentityFormat::Uuid,
            "msg_11111111-1111-4111-8111-111111111111",
            "msg_22222222-2222-4222-8222-222222222222",
            true,
        ),
        (
            IdentityFormat::Uuid,
            "msg_11111111-1111-4111-8111-111111111111",
            "msg_00000000-0000-0000-0000-000000000000",
            false,
        ),
    ] {
        let contract = contract(format);
        assert_eq!(
            super::super::compare(
                &json!(source),
                &json!(target),
                &[Field {
                    rule_id: "identity",
                    pointer: "",
                    contract: &contract
                }],
                AnchorClocks::default()
            )
            .passed(),
            passed
        );
    }
}

#[test]
fn identity_state_is_bounded_and_existing_entities_remain_valid_at_limit() {
    let mut state = Bijection::default();
    for index in 0u64..4096 {
        let digest: [u8; 32] = Sha256::digest(index.to_be_bytes()).into();
        state.bind(digest, digest).unwrap();
    }
    let existing = Sha256::digest(0u64.to_be_bytes()).into();
    state.bind(existing, existing).unwrap();
    assert!(
        state
            .bind(Sha256::digest(4096u64.to_be_bytes()).into(), [0; 32])
            .is_err()
    );
}

#[test]
fn repeated_frame_times_do_not_accumulate_duplicate_relationships() {
    let mut result = Comparison::default();
    for _ in 0..1000 {
        let mut frame = Comparison::default();
        frame.relationships.insert(
            (
                TimeAnchor::DependencyRequestStart,
                Some("response".into()),
                Default::default(),
            ),
            vec![(1, 61)],
        );
        result.merge_and_validate(frame);
    }
    assert!(result.passed());
    assert_eq!(result.relationships.values().next().unwrap().len(), 1);
    let mut wrong = Comparison::default();
    wrong.relationships.insert(
        (
            TimeAnchor::DependencyRequestStart,
            Some("response".into()),
            Default::default(),
        ),
        vec![(1, 62)],
    );
    result.merge_and_validate(wrong);
    assert!(!result.passed());
}

#[test]
fn fixed_hex_identity_validates_both_sides_and_preserves_shared_bijection() {
    let contract = contract(IdentityFormat::Hex(12));
    let compare = |a: &str, b: &str| {
        super::super::compare(
            &json!(a),
            &json!(b),
            &[Field {
                rule_id: "hex",
                pointer: "",
                contract: &contract,
            }],
            AnchorClocks::default(),
        )
    };
    let source = "msg_0123456789ab";
    let target = "msg_abcdef123456";
    assert!(compare(source, target).passed());
    for bad in [
        "msg_ABCDEF123456",
        "msg_abcdef12345",
        "msg_abcdef1234567",
        "msg_abcdef12345g",
        "msg_abcdef１２３４５６",
        "bad_abcdef123456",
    ] {
        assert!(!compare(source, bad).passed(), "{bad}");
        assert!(!compare(bad, target).passed(), "{bad}");
    }
    let mut state = compare(source, target);
    state.merge_and_validate(compare(source, target));
    assert!(state.passed());
    let mut changed = state.clone();
    changed.merge_and_validate(compare(source, "msg_abcdef654321"));
    assert!(!changed.passed());
    state.merge_and_validate(compare("msg_0123456789ac", target));
    assert!(!state.passed());
}
