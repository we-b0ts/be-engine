use super::*;
use crate::policy::{CompiledJsonPolicy, JsonPolicy};
use crate::value_codec::CodecView;
use crate::value_contract::{global, json::AnchorClocks, time::ClockPair};
use serde_json::json;

fn plan() -> CompiledJsonPolicy {
    JsonPolicy::default().compile().unwrap()
}

fn clocks() -> AnchorClocks {
    AnchorClocks::for_request(
        Default::default(),
        ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2021-01-01T00:00:00Z".parse().unwrap()),
        },
        Default::default(),
    )
}

#[test]
fn only_complete_valid_standard_strings_are_builtin_times() {
    for (value, format) in [
        (
            "2020-01-01T08:00:00.123456789+08:00",
            TimestampFormat::Rfc3339,
        ),
        ("2020-01-01T00:00:00Z", TimestampFormat::Rfc3339),
        ("2020-01-01T08:00:00.123456", TimestampFormat::Iso8601Naive),
        ("2020-01-01 08:00:00", TimestampFormat::SqlDatetime),
        ("2020-01-01", TimestampFormat::CalendarDate),
    ] {
        let selected = contract(&json!(value), &TimePolicy::default())
            .unwrap()
            .time()
            .unwrap();
        assert_eq!(selected.format, format);
        assert_eq!(selected.anchor, TimeAnchor::Observation);
    }
    for value in [
        json!(1_700_000_000),
        json!(1_700_000_000.25),
        json!(null),
        json!(true),
        json!("1700000000"),
        json!("v2020-01-01"),
        json!("2020-1-01"),
        json!("2020-02-30"),
        json!("2020-01-01T25:00:00Z"),
        json!("2020-01-01T00:00:00.1234567890Z"),
        json!("2020-01-01T00:00:00+0800"),
    ] {
        assert!(
            contract(&value, &TimePolicy::default()).is_none(),
            "recognized {value}"
        );
    }
}

#[test]
fn nested_standard_times_compare_without_authored_paths_and_keep_strict_remainder() {
    let source = json!({"rows":[{"id":7,"when":"2020-01-01T00:00:02.123Z"}], "nested":{"sql":"2020-01-01 08:00:02", "date":"2020-01-01"},"counter":17});
    let target = json!({"rows":[{"id":7,"when":"2021-01-01T00:00:02.123Z"}], "nested":{"sql":"2021-01-01 08:00:02", "date":"2021-01-01"},"counter":17});
    let check = global::compare_logical(&source, &target, &plan(), &[], clocks()).unwrap();
    assert!(check.passed(), "{:?}", check.differences);
    assert!(check.evaluated.contains(RULE_ID));
    assert!(!check.evaluated.contains(crate::policy::GLOBAL_JSON_ID));
    assert!(check.pre_matches.is_empty());
    for target in [
        json!({"rows":[{"id":8,"when":"2021-01-01T00:00:02.123Z"}],"nested":{"sql":"2021-01-01 08:00:02","date":"2021-01-01"},"counter":17}),
        json!({"rows":[],"nested":{"sql":"2021-01-01 08:00:02","date":"2021-01-01"},"counter":17}),
        json!({"rows":[{"id":7,"when":"2021-01-01T00:00:02.123000Z"}],"nested":{"sql":"2021-01-01 08:00:02","date":"2021-01-01"},"counter":17}),
        json!({"rows":[{"id":7,"when":"2021-01-01T00:00:02.123Z"}],"nested":{"sql":"2021-01-01 08:00:02"},"counter":17}),
    ] {
        assert!(
            !global::compare_logical(&source, &target, &plan(), &[], clocks())
                .unwrap()
                .passed()
        );
    }
    assert!(
        !global::compare_logical(
            &json!(1_700_000_000),
            &json!(1_800_000_000),
            &plan(),
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn missing_event_clock_cannot_borrow_primary_request_time() {
    let source = json!("2020-01-01T00:00:00Z");
    let target = json!("2021-01-01T00:00:00Z");
    let clocks = AnchorClocks::for_response(clocks().dependency, ClockPair::default());
    assert!(
        !global::compare_logical(&source, &target, &plan(), &[], clocks)
            .unwrap()
            .passed()
    );
    assert!(
        global::compare_logical(&source, &source, &plan(), &[], clocks)
            .unwrap()
            .passed()
    );
}

#[test]
fn preflight_source_coverage_retains_builtin_witnesses_without_authored_evidence() {
    let source = br#"{"when":"2020-01-01T00:00:02.123Z","strict":7}"#;
    let plan = plan();
    let replay = global::compare(source, source, &plan, &[], clocks()).unwrap();
    assert!(replay.passed());
    assert!(
        replay.evaluated.is_empty(),
        "exact replay retains its fast path"
    );
    let coverage = global::compare_source_coverage(source, &plan, &[], clocks()).unwrap();
    assert!(coverage.passed());
    assert!(coverage.evaluated.contains(RULE_ID));
    assert!(!coverage.evaluated.contains(crate::policy::GLOBAL_JSON_ID));
}

#[test]
fn automatic_patterns_generalize_array_positions_but_keep_numeric_object_keys_exact() {
    let source = json!({"0":{"at":"2020-01-01"}, "rows":[{"a/b":{"1":"2020-01-01"}}]});
    let selected = plan()
        .selected_fields_with_clocks(&source, clocks())
        .unwrap();
    let patterns = selected
        .iter()
        .map(|field| (field.pointer.as_str(), field.pattern.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(patterns["/0/at"], "/0/at");
    assert_eq!(patterns["/rows/0/a~1b/1"], "/rows/*/a~1b/1");
    assert_eq!(pointer_pattern(&json!("2020-01-01"), ""), "");
}

#[test]
fn numeric_only_rules_keep_numeric_semantics_and_builtin_string_branch() {
    let policy: JsonPolicy =
        serde_yaml::from_str("fields:\n  /at: {kind: time, formats: [unix_seconds]}\n").unwrap();
    let plan = policy.compile().unwrap();
    let selected = plan
        .selected_fields_with_clocks(&json!({"at":"2020-01-01T08:00:00"}), clocks())
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].rule_id, RULE_ID);
    assert_eq!(
        selected[0].contract.time().unwrap().utc_offset.as_deref(),
        Some("+08:00")
    );
    let selected = plan
        .selected_fields_with_clocks(&json!({"at":1_577_836_800}), clocks())
        .unwrap();
    assert_eq!(selected[0].rule_id, crate::policy::GLOBAL_JSON_ID);

    let policy: JsonPolicy = serde_yaml::from_str(
        "fields:\n  /at: {kind: time, formats: [{format: iso8601_naive, utc_offset: '-03:00'}]}\n",
    )
    .unwrap();
    let selected = policy
        .compile()
        .unwrap()
        .selected_fields_with_clocks(&json!({"at":"2020-01-01T08:00:00"}), clocks())
        .unwrap();
    assert_eq!(selected[0].rule_id, crate::policy::GLOBAL_JSON_ID);
    assert_eq!(
        selected[0].contract.time().unwrap().utc_offset.as_deref(),
        Some("-03:00")
    );
}

#[test]
fn global_identity_owner_is_never_replaced_by_automatic_date_semantics() {
    let policy: JsonPolicy =
        serde_yaml::from_str("fields:\n  /at: {kind: identity, formats: [string]}\n").unwrap();
    let policy = policy.compile().unwrap();
    let source = json!({"at":"2020-01-01"});
    let selected = policy
        .selected_fields_with_clocks(&source, clocks())
        .unwrap();
    assert_eq!(selected[0].rule_id, crate::policy::GLOBAL_JSON_ID);
    assert!(selected[0].contract.time().is_none());
    let check =
        global::compare_logical(&source, &source, &policy, &[], Default::default()).unwrap();
    assert_eq!(
        check.identity_pairs().len(),
        1,
        "exact fast path must retain authored identity anchors"
    );
    assert!(check.time_validations.is_empty());
    assert_eq!(
        global::materialize_logical(&source, &policy, &[], Default::default()).unwrap(),
        source
    );
}

#[test]
fn explicit_value_rule_keeps_ownership_without_granting_automatic_delivery() {
    let rule: crate::policy::Rule = serde_json::from_value(json!({
        "id":"business-day", "surface":"dependency.response",
        "match":{"resource":{"protocol":"redis","endpoint":"cache:6379"},"operation":"GET","key":{"exact":"clock"}},
        "slot":"value","codec":"json",
        "contract":{"/date":{"kind":"time","format":"calendar_date","relation":"preserve_offset","utc_offset":"+00:00"}},
        "proof":{"source":"service.py:date","fact":"This stored date uses UTC civil days and is compared without input translation."}
    })).unwrap();
    let rule = crate::policy::compile_rule(&rule).unwrap();
    let source = json!({"date":"2026-01-01","strict":7});
    let clocks = AnchorClocks::for_request(
        Default::default(),
        ClockPair {
            source: Some("2026-01-01T15:00:00Z".parse().unwrap()),
            target: Some("2026-01-01T17:00:00Z".parse().unwrap()),
        },
        Default::default(),
    );
    let output = global::materialize_logical(&source, &plan(), &[&rule], clocks).unwrap();
    assert_eq!(
        output, source,
        "automatic +08 day rebasing must not override an explicit comparison-only owner"
    );
    let checked = global::compare_logical(&source, &output, &plan(), &[&rule], clocks).unwrap();
    assert!(checked.passed(), "{:?}", checked.differences);
    assert!(!checked.evaluated.contains(RULE_ID));
}

#[test]
fn builtin_time_compares_mixed_precision_but_never_changes_delivered_source_bytes() {
    let source = br#"{ "whole":"2020-01-01T00:00:02Z", "milli":"2020-01-01T00:00:02.123Z", "micro":"2020-01-01 08:00:02.123456", "nano":"2020-01-01T08:00:02.123456789+08:00", "strict":7 }"#;
    let clocks = AnchorClocks::for_request(
        Default::default(),
        ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2021-01-01T00:00:00.456789123Z".parse().unwrap()),
        },
        Default::default(),
    );
    let output = global::materialize(source, &plan(), &[], clocks).unwrap();
    assert_eq!(output, source);
    assert_eq!(
        global::materialize(source, &plan(), &[], Default::default()).unwrap(),
        source,
        "recognizing a timestamp grants no delivery permission or clock requirement"
    );
    let target = br#"{ "whole":"2021-01-01T00:00:02Z", "milli":"2021-01-01T00:00:02.579Z", "micro":"2021-01-01 08:00:02.580245", "nano":"2021-01-01T08:00:02.580245912+08:00", "strict":7 }"#;
    assert!(
        global::compare(source, target, &plan(), &[], clocks)
            .unwrap()
            .passed()
    );
}

#[test]
fn typed_protobuf_string_times_reuse_the_same_automatic_kernel_and_protect_unknown_wire() {
    let codec = crate::value_codec::protobuf(crate::policy::ProtobufCodec {
        fields: std::collections::BTreeMap::from([(
            "/at".into(),
            crate::policy::ProtobufField {
                field_path: vec![1],
                field_type: crate::policy::ProtobufType::String,
                repeated: false,
            },
        )]),
    });
    let wire = |year: &str, unknown| {
        let text = format!("{year}-01-01T00:00:02Z");
        [
            vec![0x0a, text.len() as u8],
            text.into_bytes(),
            vec![0x10, unknown],
        ]
        .concat()
    };
    let source = CodecView::decode(&codec, &wire("2020", 7)).unwrap();
    let target = CodecView::decode(&codec, &wire("2021", 7)).unwrap();
    let check = global::compare_decoded(&source, &target, &plan(), &[], clocks()).unwrap();
    assert!(check.passed(), "{:?}", check.differences);
    assert!(check.evaluated.contains(RULE_ID));
    let changed = CodecView::decode(&codec, &wire("2021", 8)).unwrap();
    assert!(
        !global::compare_decoded(&source, &changed, &plan(), &[], clocks())
            .unwrap()
            .passed()
    );
    let fields = plan()
        .selected_fields_with_clocks(&source.logical, clocks())
        .unwrap();
    assert!(fields.iter().all(|field| !field.pointer.contains('\0')));
}

#[test]
fn large_exact_json_without_temporal_work_keeps_its_fast_no_clock_behavior() {
    let source =
        json!({"rows":(0..20_000).map(|i| json!({"id":i,"name":"stable"})).collect::<Vec<_>>()});
    assert!(fields(&source, &TimePolicy::default()).unwrap().is_empty());
    let result =
        global::compare_logical(&source, &source, &plan(), &[], Default::default()).unwrap();
    assert!(result.passed());
    let mut target = source.clone();
    target["rows"][19_999]["id"] = json!(-1);
    assert!(
        !global::compare_logical(&source, &target, &plan(), &[], Default::default())
            .unwrap()
            .passed()
    );
}
