use super::*;
use crate::policy::{CompiledJsonPolicy, GLOBAL_JSON_ID};
use crate::value_contract::time::ClockPair;
use serde_json::json;

fn fixture(fields: serde_json::Value) -> CompiledJsonPolicy {
    crate::policy::parse_and_compile_policy(
        &json!({"format":"traffic-policy/v2","json":{"fields":fields}}).to_string(),
    )
    .unwrap()
    .global_json
    .unwrap()
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    }
}

fn compared(
    source: &serde_json::Value,
    target: &serde_json::Value,
    plan: &CompiledJsonPolicy,
) -> Comparison {
    crate::value_contract::global::compare(
        &serde_json::to_vec(source).unwrap(),
        &serde_json::to_vec(target).unwrap(),
        plan,
        &[],
        clocks(),
    )
    .unwrap()
}

#[test]
fn global_delivery_decodes_source_once_and_preserves_business_fields() {
    let plan = fixture(json!({"/time":{"kind":"time","formats":["unix_seconds"]}}));
    let original = br#"{ "time":1000,"stable":7 }"#;
    let (delivery, decodes) = crate::value_codec::measured_decodes(|| {
        Delivery::prepare_global(original, &plan, clocks()).unwrap()
    });
    assert_eq!(decodes, 1);
    assert!(delivery.validation().time_validations.is_empty());
    assert!(delivery.validation().evaluated.contains(GLOBAL_JSON_ID));
    let rendered = delivery
        .render(clocks().dependency.target.unwrap())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rendered).unwrap(),
        json!({"time":2000,"stable":7})
    );
    assert!(
        Delivery::prepare_global(original, &plan, Default::default())
            .unwrap()
            .render(clocks().dependency.target.unwrap())
            .is_err()
    );
}

#[test]
fn source_self_validation_preserves_equal_invalid_formats_and_rejects_bad_json() {
    let plan = fixture(json!({"/time":{"kind":"time","formats":["unix_seconds"]}}));
    let invalid = br#"{"time":"1000"}"#;
    let delivery = Delivery::prepare_global(invalid, &plan, clocks()).unwrap();
    assert_eq!(
        delivery
            .render(clocks().dependency.target.unwrap())
            .unwrap(),
        invalid
    );
    for source in [br#"{"time":1000,"time":1001}"#.as_slice(), b"truncated"] {
        assert!(Delivery::prepare_global(source, &plan, clocks()).is_err());
    }
}

#[test]
fn absent_fields_keep_original_bytes_without_clocks_or_positive_witnesses() {
    let plan = fixture(json!({"/time":{"kind":"time","formats":["unix_seconds"]}}));
    let original = br#"{ "stable":7 }"#;
    let (prepared, decodes) = crate::value_codec::measured_decodes(|| {
        Delivery::prepare_global(original, &plan, AnchorClocks::default()).unwrap()
    });
    assert_eq!(decodes, 1);
    assert!(prepared.validation().evaluated.is_empty());
    assert!(prepared.validation().time_validations.is_empty());
    assert_eq!(
        prepared
            .render(clocks().dependency.target.unwrap())
            .unwrap(),
        original
    );
}

#[test]
fn optional_time_fields_reject_presence_changes_and_invalid_nonnull_values() {
    let plan = fixture(json!({"/time":{"kind":"time","formats":["unix_seconds"]}}));
    for (source, target) in [
        (json!({"stable":7}), json!({"stable":7,"time":2010})),
        (json!({"stable":7,"time":1010}), json!({"stable":7})),
        (json!({"time":null}), json!({})),
        (json!({}), json!({"time":null})),
        (json!({"time":"invalid"}), json!({"time":"changed"})),
    ] {
        assert!(
            !compared(&source, &target, &plan).passed(),
            "{source} -> {target}"
        );
    }
}

#[test]
fn wildcard_times_preserve_each_offset_and_keep_other_fields_exact() {
    let plan = fixture(json!({"/items/*/at":{"kind":"time","formats":["unix_seconds"]}}));
    let source = json!({"items":[{"at":1010,"id":1},{"at":1010,"id":2}]});
    assert!(
        compared(
            &source,
            &json!({"items":[{"at":2010,"id":1},{"at":2011,"id":2}]}),
            &plan
        )
        .passed()
    );
    assert!(
        !compared(
            &source,
            &json!({"items":[{"at":2010,"id":1},{"at":2011,"id":3}]}),
            &plan
        )
        .passed()
    );
}

#[test]
fn nullable_timestamps_keep_null_exact_and_validate_nonnull_values() {
    let plan = fixture(json!({"/completedAt":{"kind":"time","formats":["unix_seconds"]}}));
    for (source, target, passed) in [
        (
            json!({"completedAt":null}),
            json!({"completedAt":null}),
            true,
        ),
        (
            json!({"completedAt":1010}),
            json!({"completedAt":2010}),
            true,
        ),
        (
            json!({"completedAt":null}),
            json!({"completedAt":2010}),
            false,
        ),
        (
            json!({"completedAt":1010}),
            json!({"completedAt":null}),
            false,
        ),
        (
            json!({"completedAt":"broken"}),
            json!({"completedAt":"broken"}),
            true,
        ),
        (json!({"completedAt":null}), json!({}), false),
    ] {
        assert_eq!(
            compared(&source, &target, &plan).passed(),
            passed,
            "{source} -> {target}"
        );
    }
    let original = br#"{ "completedAt": null }"#;
    let prepared = Delivery::prepare_global(original, &plan, Default::default()).unwrap();
    assert_eq!(
        prepared
            .render(clocks().dependency.target.unwrap())
            .unwrap(),
        original
    );
    assert!(prepared.validation().time_validations.is_empty());
}
