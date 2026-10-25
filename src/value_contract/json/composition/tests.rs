use super::*;
use serde_json::json;

fn time() -> FieldContract {
    serde_json::from_value(
        json!({"kind":"time","format":"unix_seconds","relation":"preserve_offset"}),
    )
    .unwrap()
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: time::ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    }
}

#[test]
fn native_verification_and_global_time_both_validate_same_leaf() {
    let time = time();
    let fields = [Field {
        rule_id: crate::policy::GLOBAL_JSON_ID,
        pointer: "/expires_at",
        contract: &time,
    }];
    let verify = |context: LeafContext<'_>| {
        if context.source_root["signature_valid"] != true
            || context.target_root["signature_valid"] != true
        {
            return Err("native signature rejected".into());
        }
        if context.source.as_i64() != Some(1060) || context.target.as_i64() != Some(2060) {
            return Err("signed expiry companion changed".into());
        }
        Ok(LeafObservations {
            time_validations: 1,
            ..Default::default()
        })
    };
    let verified = [VerifiedField {
        rule_id: "signed-token",
        pointer: "/expires_at",
        verifier: &verify,
    }];
    let source = json!({"expires_at":1060,"signature_valid":true});
    let target = json!({"expires_at":2060,"signature_valid":true});
    let comparison =
        super::super::compare_with_verified(&source, &target, &fields, &[], &verified, clocks());
    assert!(comparison.passed(), "{:?}", comparison.differences);
    assert!(comparison.evaluated.contains(crate::policy::GLOBAL_JSON_ID));
    assert!(comparison.evaluated.contains("signed-token"));
    assert!(
        !super::super::compare_with_verified(
            &source,
            &json!({"expires_at":2060,"signature_valid":false}),
            &fields,
            &[],
            &verified,
            clocks()
        )
        .passed()
    );
    assert!(
        !super::super::compare_with_verified(
            &source,
            &json!({"expires_at":2061,"signature_valid":true}),
            &fields,
            &[],
            &verified,
            clocks()
        )
        .passed()
    );
    // Unequal values still require the global relative clock, even with a permissive verifier.
    let permissive = |_: LeafContext<'_>| Ok(LeafObservations::default());
    let checked = [VerifiedField {
        rule_id: "native",
        pointer: "/expires_at",
        verifier: &permissive,
    }];
    assert!(
        !super::super::compare_with_verified(
            &source,
            &json!({"expires_at":1010,"signature_valid":true}),
            &fields,
            &[],
            &checked,
            clocks()
        )
        .passed()
    );
}

#[test]
fn failed_native_proof_does_not_retain_global_identity_correspondence() {
    let identity: FieldContract =
        serde_json::from_value(json!({"kind":"identity","format":{"hex":4},"prefix":"msg_"}))
            .unwrap();
    let fields = [Field {
        rule_id: crate::policy::GLOBAL_JSON_ID,
        pointer: "/id",
        contract: &identity,
    }];
    let reject = |_: LeafContext<'_>| Err("invalid native proof".into());
    let verified = [VerifiedField {
        rule_id: "native",
        pointer: "/id",
        verifier: &reject,
    }];
    let comparison = super::super::compare_with_verified(
        &json!({"id":"msg_abcd"}),
        &json!({"id":"msg_1234"}),
        &fields,
        &[],
        &verified,
        Default::default(),
    );
    assert!(!comparison.passed());
    assert!(comparison.identity_pairs().is_empty());
}
