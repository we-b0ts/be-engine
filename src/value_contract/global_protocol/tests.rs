use super::*;
use crate::value_contract::{global, json::AnchorClocks, time::ClockPair};
use serde_json::json;
fn plan(fields: &str) -> CompiledJsonPolicy {
    serde_yaml::from_str::<crate::policy::JsonPolicy>(&format!("fields:\n{fields}"))
        .unwrap()
        .compile()
        .unwrap()
}
#[test]
fn aws_url_format_preserves_static_parts_signature_shape_and_credential_scope() {
    let policy = plan("  /download_path: {kind: url, formats: [aws_sigv4]}\n");
    let source = format!(
        "https://store.test/bucket/key?X-Amz-Date=20200101T000000Z&X-Amz-Credential=ak%2F20200101%2Fregion%2Fs3%2Faws4_request&X-Amz-Signature={}&X-Amz-Expires=3600",
        "a".repeat(64)
    );
    let target = source
        .replace("20200101", "20261018")
        .replace(&"a".repeat(64), &"b".repeat(64));
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2026-10-18T00:00:00Z".parse().unwrap()),
        },
        ..Default::default()
    };
    let compare = |target: &str| {
        global::compare_logical(
            &json!({"download_path":source}),
            &json!({"download_path":target}),
            &policy,
            &[],
            clocks,
        )
        .unwrap()
    };
    assert!(compare(&target).passed());
    for changed in [
        target.replace("store.test", "other.test"),
        target.replace("/bucket/key", "/bucket/other"),
        target.replace("Expires=3600", "Expires=7200"),
        target.replace("%2Fregion%2F", "%2Fother%2F"),
        target.replace("%2F20261018%2F", "%2F20261017%2F"),
        target.replace(&"b".repeat(64), "bad-signature"),
        format!("{target}&X-Amz-Date=20261018T000000Z"),
        target.replace("20261018T000000Z", "20261018T000030Z"),
    ] {
        assert!(!compare(&changed).passed());
    }
    assert!(
        global::compare_logical(
            &json!({"download_path":null}),
            &json!({"download_path":null}),
            &policy,
            &[],
            Default::default(),
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn bounded_string_format_keeps_original_maximum_without_weakening_generic_string() {
    let policy = plan("  /headers/origin: {kind: identity, formats: [{string: 255}]}\n");
    let source = json!({"headers":{"origin":"process-a"}});
    let good = json!({"headers":{"origin":"process-b"}});
    assert!(
        global::compare_logical(&source, &good, &policy, &[], Default::default(),)
            .unwrap()
            .passed()
    );
    let bad = json!({"headers":{"origin":"x".repeat(256)}});
    assert!(
        !global::compare_logical(&source, &bad, &policy, &[], Default::default(),)
            .unwrap()
            .passed()
    );
}

#[test]
fn jwt_is_a_complete_identity_format_without_signature_claim_or_clock_checks() {
    let policy = plan(
        "  /access_token: {kind: identity, formats: [jwt]}\n  /copy: {kind: identity, formats: [jwt]}\n",
    );
    let source = crate::request_rules::tests::token(
        json!({"iat":1000,"exp":1060,"role":"reader"}),
        "source-key",
    );
    // A different signing key and different business claims are deliberately
    // irrelevant to a whole-token identity correspondence.
    let target =
        crate::request_rules::tests::token(json!({"iat":3,"exp":4,"role":"writer"}), "target-key");
    let before = json!({"access_token":source,"copy":source});
    let after = json!({"access_token":target,"copy":target});
    let checked =
        global::compare_logical(&before, &after, &policy, &[], Default::default()).unwrap();
    assert!(checked.passed(), "{:?}", checked.differences);
    assert_eq!(checked.identity_pairs().len(), 1);
    assert!(checked.time_validations.is_empty());
    let mut inconsistent = after.clone();
    inconsistent["copy"] = json!(crate::request_rules::tests::token(
        json!({"exp":7}),
        "third-key"
    ));
    assert!(
        !global::compare_logical(&before, &inconsistent, &policy, &[], Default::default())
            .unwrap()
            .passed()
    );
    assert!(
        !global::compare_logical(
            &before,
            &json!({"access_token":"malformed","copy":"malformed"}),
            &policy,
            &[],
            Default::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        global::compare_logical(
            &json!({"access_token":"malformed"}),
            &json!({"access_token":"malformed"}),
            &policy,
            &[],
            Default::default()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn jwt_identity_preserves_large_whole_tokens_during_delivery() {
    use crate::value_contract::identities::{
        IdentityDecision, IdentityDelivery, IdentityStore, PreparedIdentityDelivery,
    };
    let policy = plan("  /access_token: {kind: identity, formats: [jwt]}\n");
    let source = crate::request_rules::tests::token(json!({"payload":"x".repeat(4096)}), "source");
    let target =
        crate::request_rules::tests::token(json!({"different":"y".repeat(4096)}), "target");
    assert!(source.len() > 1024);
    let checked = global::compare_logical(
        &json!({"access_token":source}),
        &json!({"access_token":target}),
        &policy,
        &[],
        Default::default(),
    )
    .unwrap();
    assert!(checked.passed());
    let mut store = IdentityStore::default();
    store
        .commit(IdentityDecision::prepare("case", checked.identity_pairs()).unwrap())
        .unwrap();
    let value = json!(source);
    let prepared = PreparedIdentityDelivery::prepare(IdentityDelivery {
        prefix: "",
        format: crate::policy::IdentityFormat::Jwt,
        value: &value,
    })
    .unwrap();
    let (delivered, _) = store.deliveries("case", &[prepared]).unwrap();
    assert_eq!(delivered, vec![json!(target)]);
}
