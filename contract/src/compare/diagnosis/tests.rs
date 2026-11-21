use super::*;
use serde_json::Value;

#[test]
fn pointers_presence_types_and_array_multiplicity_are_explicit() {
    let source = br#"{"a/b":{"~x":null},"items":[1,1,2],"typed":1}"#;
    let target = br#"{"a/b":{},"items":[2,1,1],"typed":"1","extra":null}"#;
    let result = differences(source, target, 0);
    let values = result["differences"].as_array().unwrap();
    let missing = values.iter().find(|v| v["pointer"] == "/a~1b/~0x").unwrap();
    assert_eq!(missing["source"]["value"], Value::Null);
    assert_eq!(missing["source"]["presence"], "present");
    assert_eq!(missing["target"]["presence"], "missing");
    assert!(values.iter().any(|v| v["kind"] == "array_order_mismatch"));
    assert!(values.iter().any(|v| v["kind"] == "type_mismatch"));
    let changed = differences(br#"[1,1,2]"#, br#"[1,2,2]"#, 0);
    assert!(!changed.to_string().contains("array_order_mismatch"));
}

#[test]
fn long_unicode_strings_point_at_the_actual_change_instead_of_the_prefix() {
    let prefix = "中文🦀".repeat(3000);
    let source = serde_json::to_vec(&json!({"prompt":format!("{prefix}source-end")})).unwrap();
    let target = serde_json::to_vec(&json!({"prompt":format!("{prefix}target-end")})).unwrap();
    let result = differences(&source, &target, 0);
    let difference = &result["differences"][0];
    assert_eq!(difference["pointer"], "/prompt");
    assert_eq!(
        difference["string_difference"]["first_different_byte"],
        prefix.len()
    );
    assert!(
        difference["string_difference"]["source_context"]["data"]
            .as_str()
            .unwrap()
            .contains("source-end")
    );
    assert!(serde_json::to_vec(&result).unwrap().len() < 4000);
}

#[test]
fn pagination_and_binary_prefix_changes_keep_exact_offsets() {
    let source = serde_json::to_vec(&vec![0; 55]).unwrap();
    let target = serde_json::to_vec(&vec![1; 55]).unwrap();
    let first = differences(&source, &target, 0);
    assert_eq!(first["total_differences"], 55);
    assert_eq!(first["next_offset"], 20);
    let last = differences(&source, &target, 40);
    assert_eq!(last["returned_differences"], 15);
    assert_eq!(last["next_offset"], Value::Null);
    let binary = differences(&[0xff, 0, 4], &[0xff, 0, 5, 6], 0);
    assert_eq!(binary["codec"], "bytes");
    assert_eq!(binary["differences"][0]["bytes"]["first_different_byte"], 2);
    assert_eq!(differences(b"", b"", 0)["total_differences"], 0);
}

#[test]
fn rule_evaluation_reuses_the_shared_comparator_and_raw_diffs_remain_distinct() {
    use crate::{
        compare::{AnchorClocks, Field, RegisteredRules, compare_all},
        rule::FieldContract,
    };
    let source = json!({"items":[1,2],"stable":"same"});
    let target = json!({"items":[2,1],"stable":"same"});
    let contract = FieldContract::Unordered;
    let fields = [Field {
        rule_id: "source-proven-set",
        pointer: "/items",
        contract: &contract,
    }];
    let metadata = RegisteredRules(traffic_extensions::policies());
    let result = compare_all(
        &source,
        &target,
        &fields,
        &[],
        &[],
        AnchorClocks::default(),
        &[],
        &metadata,
    );
    assert!(result.passed());
    assert!(result.evaluated.contains("source-proven-set"));
    assert!(
        differences(
            &serde_json::to_vec(&source).unwrap(),
            &serde_json::to_vec(&target).unwrap(),
            0
        )["differences_found"]
            .as_u64()
            .unwrap()
            > 0
    );
    let failed = compare_all(
        &source,
        &json!({"items":[2,1],"stable":"changed"}),
        &fields,
        &[],
        &[],
        AnchorClocks::default(),
        &[],
        &metadata,
    );
    assert!(!failed.passed());
    assert_eq!(failed.differences[0].pointer, "/stable");
}

#[test]
fn codec_scalar_categories_survive_diagnosis_and_collection_hints() {
    use traffic_value::{Number, Value as Logical};
    let source = Logical::Array(vec![
        Logical::Bytes(vec![1, 2]),
        Logical::Number(Number::Signed(1)),
    ]);
    let target = Logical::Array(vec![
        Logical::Number(Number::Unsigned(1)),
        Logical::Array(vec![
            Logical::Number(Number::Unsigned(1)),
            Logical::Number(Number::Unsigned(2)),
        ]),
    ]);
    let result = super::differences(&source, &target, "native", 0);
    assert!(result["analysis_complete"].as_bool().unwrap());
    assert!(!result.to_string().contains("array_order_mismatch"));

    let number = super::at_pointer(&source, &source, "/1");
    assert_eq!(number["source"]["representation"], "signed");
    let bytes = super::at_pointer(
        &Logical::Bytes(vec![0xff, 1]),
        &Logical::Bytes(vec![0xff, 2]),
        "",
    );
    assert_eq!(bytes["source"]["type"], "bytes");
    assert_eq!(bytes["bytes"]["first_different_byte"], 1);
}

fn differences(source: &[u8], target: &[u8], offset: usize) -> Value {
    match (
        serde_json::from_slice::<traffic_value::Value>(source),
        serde_json::from_slice::<traffic_value::Value>(target),
    ) {
        (Ok(source), Ok(target)) => super::differences(&source, &target, "json", offset),
        _ => super::byte_differences(source, target, "bytes", offset),
    }
}
