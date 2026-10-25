use super::*;
use chrono::DateTime;
use serde_json::json;

fn plan(fields: &str) -> CompiledJsonPolicy {
    serde_yaml::from_str::<crate::policy::JsonPolicy>(&format!("fields:\n{fields}"))
        .unwrap()
        .compile()
        .unwrap()
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: time::ClockPair {
            source: DateTime::from_timestamp(1000, 0),
            target: DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    }
}

#[test]
fn automatic_json_composes_time_identity_unordered_and_strict_remainder() {
    let plan = plan(
        "  /created_at: {kind: time, formats: [unix_seconds]}\n  /item_id: {kind: identity, formats: [{prefix: msg_, hex: 4}]}\n  /item/id: {kind: identity, formats: [{prefix: msg_, hex: 4}]}\n  /values: {kind: unordered}\n",
    );
    let source = br#"{"created_at":1010,"item_id":"msg_abcd","item":{"id":"msg_abcd"},"values":[1,2,2],"stable":true}"#;
    let target = br#"{"created_at":2010,"item_id":"msg_1234","item":{"id":"msg_1234"},"values":[2,1,2],"stable":true}"#;
    let result = compare(source, target, &plan, &[], clocks()).unwrap();
    assert!(result.passed(), "{:?}", result.differences);
    assert!(result.evaluated.contains(GLOBAL_JSON_ID));
    let text = std::str::from_utf8(target).unwrap();
    assert!(
        !compare(
            source,
            text.replace("1234\"}", "5678\"}").as_bytes(),
            &plan,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            source,
            text.replace("true", "false").as_bytes(),
            &plan,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            source,
            text.replace("[2,1,2]", "[2,1,1]").as_bytes(),
            &plan,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn unknown_source_is_exact_and_known_json_cannot_fall_back_after_failure() {
    let plan = plan("  /id: {kind: identity, formats: [uuid]}\n");
    assert!(
        compare(
            b"binary\0x",
            b"binary\0x",
            &plan,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            b"binary\0x",
            b"binary\0y",
            &plan,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(compare(b"{}", b"broken", &plan, &[], AnchorClocks::default()).is_err());
    assert!(
        compare(
            br#"{"id":"invalid"}"#,
            br#"{"id":"invalid"}"#,
            &plan,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        compare(b"{}", b"{}", &plan, &[], AnchorClocks::default())
            .unwrap()
            .passed()
    );
    assert!(
        !compare(b"{}", br#"{"id":"a"}"#, &plan, &[], AnchorClocks::default())
            .unwrap()
            .passed()
    );
}

#[test]
fn delivery_shifts_present_times_once_and_keeps_absent_original_bytes() {
    let plan = plan("  /created_at: {kind: time, formats: [unix_seconds]}\n");
    let absent = b"{ \"unselected\": 1 }";
    assert_eq!(
        materialize(absent, &plan, &[], AnchorClocks::default()).unwrap(),
        absent
    );
    let delivered = materialize(
        br#"{"created_at":1010,"unselected":1}"#,
        &plan,
        &[],
        clocks(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&delivered).unwrap(),
        json!({"created_at":2010,"unselected":1})
    );
}

#[test]
fn mixed_formats_are_chosen_per_source_leaf_before_target_comparison() {
    let plan = plan("  /values/*: {kind: identity, formats: [uuid, {prefix: msg_, hex: 4}]}\n");
    let source = json!({"values":["c30b86d7-6675-4f7a-8fd8-a0e862b73731","msg_abcd"]});
    assert!(
        compare_logical(
            &source,
            &json!({"values":["a4950434-e01e-4e27-96ae-9623f60299ce","msg_1234"]}),
            &plan,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare_logical(
            &source,
            &json!({"values":["msg_1234","a4950434-e01e-4e27-96ae-9623f60299ce"]}),
            &plan,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn correspondence_uses_complete_typed_ids_across_different_field_formats() {
    let prefixed = plan(
        "  /user: {kind: identity, formats: [{prefix: user_, format: decimal}]}\n  /order: {kind: identity, formats: [{prefix: order_, format: decimal}]}\n",
    );
    assert!(
        compare_logical(
            &json!({"user":"user_11","order":"order_11"}),
            &json!({"user":"user_101","order":"order_102"}),
            &prefixed,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    let different_formats = plan(
        "  /a: {kind: identity, formats: [decimal]}\n  /b: {kind: identity, formats: [{hex: 2}]}\n",
    );
    let source = json!({"a":"11","b":"11"});
    assert!(
        !compare_logical(
            &source,
            &json!({"a":"22","b":"33"}),
            &different_formats,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        compare_logical(
            &source,
            &json!({"a":"22","b":"22"}),
            &different_formats,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        compare_logical(
            &json!({"a":11,"b":"11"}),
            &json!({"a":22,"b":"33"}),
            &different_formats,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn compatible_legacy_time_delivery_is_translated_once_and_conflicts_fail() {
    let policy = plan("  /created_at: {kind: time, formats: [unix_seconds]}\n");
    let rule: crate::policy::Rule = serde_json::from_value(json!({
        "id":"old-clock", "surface":"dependency.response",
        "match":{"resource":{"protocol":"redis","endpoint":"cache:6379","database":0},"operation":"GET","key":{"exact":"clock"}},
        "slot":"value","codec":"json",
        "contract":{"/created_at":{"kind":"time","format":"unix_seconds","relation":"preserve_offset","clock_group":"legacy-clock"}},
        "delivery":{"rebase_time":["/created_at"]},
        "proof":{"source":"service.py:10","fact":"The application emits this generated request clock."}
    })).unwrap();
    let legacy = crate::policy::compile_rule(&rule).unwrap();
    let source = br#"{"created_at":1010,"strict":true}"#;
    let delivered = materialize(source, &policy, &[&legacy], clocks()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&delivered).unwrap(),
        json!({"created_at":2010,"strict":true})
    );
    let check = compare(source, &delivered, &policy, &[&legacy], clocks()).unwrap();
    assert!(check.passed(), "{:?}", check.differences);
    assert!(check.evaluated.contains("old-clock"));
    assert!(check.evaluated.contains(GLOBAL_JSON_ID));
    let conflict = plan("  /created_at: {kind: identity, formats: [decimal]}\n");
    assert!(
        !compare(source, &delivered, &conflict, &[&legacy], clocks())
            .unwrap()
            .passed()
    );
}

#[test]
fn authenticated_global_read_copy_does_not_authorize_other_values() {
    use crate::value_contract::time_copies::{TimeCopyPosition, TimeCopyStore};
    let policy = plan("  /created_at: {kind: time, formats: [unix_seconds]}\n");
    let position = TimeCopyPosition::Redis {
        host: "cache",
        port: 6379,
        database: 0,
        key: b"task",
        container: crate::policy::RedisContainer::String,
        hash_field: None,
    };
    let mut store = TimeCopyStore::default();
    store.set_record_clocks(time::ClockPair {
        source: DateTime::from_timestamp(0, 0),
        target: DateTime::from_timestamp(0, 0),
    });
    store.set_lookup_clocks(clocks().dependency);
    store
        .record(
            "case",
            position,
            position,
            "/created_at",
            "/created_at",
            &json!(10),
            &json!(20),
        )
        .unwrap();
    let proof = store
        .proof(
            "case",
            position,
            position,
            "/created_at",
            "/created_at",
            &json!(10),
            &json!(20),
            GLOBAL_JSON_ID,
        )
        .unwrap();
    let source = CodecView::decode(&Codec::Json, br#"{"created_at":10,"strict":1}"#).unwrap();
    let target = CodecView::decode(&Codec::Json, br#"{"created_at":20,"strict":1}"#).unwrap();
    assert!(
        compare_decoded(&source, &source, &policy, &[], clocks())
            .unwrap()
            .passed()
    );
    assert!(
        !compare_decoded(&source, &target, &policy, &[], clocks())
            .unwrap()
            .passed()
    );
    assert!(
        compare_decoded_with_time_copies(
            &source,
            &target,
            &policy,
            &[],
            clocks(),
            std::slice::from_ref(&proof)
        )
        .unwrap()
        .passed()
    );
    let changed = CodecView::decode(&Codec::Json, br#"{"created_at":11,"strict":1}"#).unwrap();
    assert!(
        !compare_decoded_with_time_copies(&source, &changed, &policy, &[], clocks(), &[proof])
            .unwrap()
            .passed()
    );
}

#[test]
fn numeric_epoch_units_are_selected_from_source_clock_and_target_cannot_switch_units() {
    let policy = plan("  /timestamp: {kind: time, formats: [unix_seconds, unix_milliseconds]}\n");
    for (source, target) in [(1010, 2010), (1010000, 2010000)] {
        assert!(
            compare_logical(
                &json!({"timestamp":source}),
                &json!({"timestamp":target}),
                &policy,
                &[],
                clocks()
            )
            .unwrap()
            .passed()
        );
        let delivered =
            materialize_logical(&json!({"timestamp":source}), &policy, &[], clocks()).unwrap();
        assert_eq!(delivered, json!({"timestamp":target}));
    }
    assert!(
        !compare_logical(
            &json!({"timestamp":1010000}),
            &json!({"timestamp":2010}),
            &policy,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    let source = json!({"timestamp":1010});
    let exact = compare_logical(&source, &source, &policy, &[], AnchorClocks::default()).unwrap();
    assert!(exact.passed());
    assert!(exact.time_validations.is_empty());
    assert!(
        !compare_logical(
            &source,
            &json!({"timestamp":2010}),
            &policy,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert_eq!(
        materialize_logical(&source, &policy, &[], AnchorClocks::default()).unwrap(),
        source
    );
    let tie = AnchorClocks {
        dependency: time::ClockPair {
            source: DateTime::from_timestamp(500, 500_000_000),
            target: DateTime::from_timestamp(1500, 500_000_000),
        },
        ..Default::default()
    };
    let same = json!({"timestamp":1000});
    assert!(
        compare_logical(&same, &same, &policy, &[], tie)
            .unwrap()
            .passed()
    );
    assert!(
        !compare_logical(&same, &json!({"timestamp":2000}), &policy, &[], tie)
            .unwrap()
            .passed()
    );
}

#[test]
fn implicit_null_is_exact_without_clocks_and_remains_distinct_from_missing() {
    let policy = plan(
        "  /created_at: {kind: time, formats: [unix_seconds]}\n  /id: {kind: identity, formats: [uuid]}\n",
    );
    let source = json!({"created_at":null,"id":null});
    let comparison =
        compare_logical(&source, &source, &policy, &[], AnchorClocks::default()).unwrap();
    assert!(comparison.passed());
    assert!(comparison.time_validations.is_empty());
    assert!(comparison.identity_pairs().is_empty());
    assert_eq!(
        materialize_logical(&source, &policy, &[], AnchorClocks::default()).unwrap(),
        source
    );
    assert!(
        !compare_logical(
            &source,
            &json!({"id":null}),
            &policy,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare_logical(
            &source,
            &json!({"created_at":2010,"id":null}),
            &policy,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn equal_unknown_ids_stay_exact_and_target_cannot_choose_the_format() {
    let policy = plan("  /id: {kind: identity, formats: [{prefix: msg_, hex: 4}]}\n");
    let source = json!({"id":"upstream-call-id"});
    let compared =
        compare_logical(&source, &source, &policy, &[], AnchorClocks::default()).unwrap();
    assert!(compared.passed());
    assert_eq!(compared.identity_pairs().len(), 1);
    assert!(
        !compare_logical(
            &source,
            &json!({"id":"different-call-id"}),
            &policy,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    let source = json!({"id":"msg_abcd"});
    assert!(
        compare_logical(
            &source,
            &json!({"id":"msg_1234"}),
            &policy,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare_logical(
            &source,
            &json!({"id":"upstream-call-id"}),
            &policy,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn equal_scalars_need_no_time_format_or_clock_but_keep_identity_anchors() {
    let policy = plan(
        "  /at: {kind: time, formats: [unix_seconds]}\n  /id: {kind: identity, formats: [uuid]}\n",
    );
    for source in [
        json!({"at":"1970-01-01 00:00:00","id":"externally-fixed"}),
        json!({"at":17,"id":""}),
        json!({"at":false,"id":true}),
        json!({"at":null,"id":1.25}),
    ] {
        let comparison =
            compare_logical(&source, &source, &policy, &[], Default::default()).unwrap();
        assert!(comparison.passed(), "{:?}", comparison.differences);
        assert!(comparison.time_validations.is_empty());
        assert_eq!(comparison.identity_pairs().len(), 1);
        if !source["at"].is_number() {
            assert_eq!(
                materialize_logical(&source, &policy, &[], Default::default()).unwrap(),
                source
            );
        }
        let mut changed = source.clone();
        changed["at"] = json!("another-format");
        assert!(
            !compare_logical(&source, &changed, &policy, &[], Default::default())
                .unwrap()
                .passed()
        );
    }
}

#[test]
fn equal_whole_json_still_anchors_nested_ids_and_unordered_pairing_chooses_equality() {
    let policy =
        plan("  /rows: {kind: unordered}\n  /rows/*/id: {kind: identity, formats: [{hex: 4}]}\n");
    let source = json!({"rows":[{"id":"aaaa","name":"A"},{"id":"bbbb","name":"B"}]});
    let equal = compare_logical(&source, &source, &policy, &[], Default::default()).unwrap();
    assert!(equal.passed());
    assert_eq!(equal.identity_pairs().len(), 2);
    // Same-index ID equality cannot anchor an element before stable members
    // determine its actual unordered partner.
    let swapped = json!({"rows":[{"id":"aaaa","name":"B"},{"id":"bbbb","name":"A"}]});
    let swapped = compare_logical(&source, &swapped, &policy, &[], Default::default()).unwrap();
    assert!(swapped.passed(), "{:?}", swapped.differences);
    let mut combined = equal;
    combined.merge_and_validate(swapped);
    assert!(!combined.passed());
}

#[test]
fn global_duration_declares_only_one_unit_with_optional_presence_and_equal_scalar_priority() {
    let policy = plan("  /items/*/waitingDurationSeconds: {kind: duration, formats: [seconds]}\n");
    let source = json!({"items":[{"status":"waiting","waitingDurationSeconds":10},{"status":"published","waitingDurationSeconds":20},{}]});
    let target = json!({"items":[{"status":"waiting","waitingDurationSeconds":1010},{"status":"published","waitingDurationSeconds":20},{}]});
    let comparison = compare_logical(&source, &target, &policy, &[], clocks()).unwrap();
    assert!(comparison.passed(), "{:?}", comparison.differences);
    assert!(
        compare_logical(&source, &source, &policy, &[], Default::default())
            .unwrap()
            .passed()
    );
    let fixed = json!({"items":[{"waitingDurationSeconds":"fixed"}]});
    assert!(
        compare_logical(&fixed, &fixed, &policy, &[], Default::default())
            .unwrap()
            .passed()
    );
    for changed in [
        json!({"items":[{"status":"waiting","waitingDurationSeconds":2000},{"status":"published","waitingDurationSeconds":20},{}]}),
        json!({"items":[{"status":"published","waitingDurationSeconds":1010},{"status":"published","waitingDurationSeconds":20},{}]}),
        json!({"items":[{"status":"waiting","waitingDurationSeconds":1010},{"status":"published"},{}]}),
    ] {
        assert!(
            !compare_logical(&source, &changed, &policy, &[], clocks())
                .unwrap()
                .passed()
        );
    }
}

#[test]
fn bounded_string_formats_keep_prefixes_and_complete_value_correspondence() {
    let policy = plan(
        "  /_content_key: {kind: identity, formats: [{prefix: 'chat:streaming:block_content:', format: string}]}\n  /copy: {kind: identity, formats: [{prefix: 'chat:streaming:block_content:', format: string}]}\n",
    );
    let source = json!({"_content_key":"chat:streaming:block_content:42:text-1000","copy":"chat:streaming:block_content:42:text-1000"});
    let target = json!({"_content_key":"chat:streaming:block_content:42:thinking-abcdef123456","copy":"chat:streaming:block_content:42:thinking-abcdef123456"});
    let comparison = compare_logical(&source, &target, &policy, &[], Default::default()).unwrap();
    assert!(comparison.passed(), "{:?}", comparison.differences);
    assert_eq!(comparison.identity_pairs().len(), 1);
    for changed in [
        json!({"_content_key":"other:42:text-2000","copy":"other:42:text-2000"}),
        json!({"_content_key":"chat:streaming:block_content:42:text-2000","copy":"chat:streaming:block_content:42:text-3000"}),
        json!({"_content_key":"chat:streaming:block_content:42:\n","copy":"chat:streaming:block_content:42:\n"}),
        json!({"_content_key":format!("chat:streaming:block_content:{}","x".repeat(1024)),"copy":"chat:streaming:block_content:42:text-2000"}),
    ] {
        assert!(
            !compare_logical(&source, &changed, &policy, &[], Default::default())
                .unwrap()
                .passed()
        );
    }
}
