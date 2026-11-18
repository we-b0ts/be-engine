use super::*;
use serde_json::json;

#[test]
fn many_global_fields_keep_clock_checks_accounting_and_strict_remainder() {
    let plan = serde_yaml::from_str::<crate::policy::JsonPolicy>(
        "fields:\n  /items/*/timestamp: {kind: time, formats: [unix_seconds]}\n",
    )
    .unwrap()
    .compile()
    .unwrap();
    let source = json!({"items":(0..512).map(|i|json!({"timestamp":1060+i,"text":"exact"})).collect::<Vec<_>>()});
    let mut target = source.clone();
    for value in target["items"].as_array_mut().unwrap() {
        value["timestamp"] = json!(value["timestamp"].as_i64().unwrap() + 1000);
    }
    let clocks = crate::value_contract::json::AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    };
    let compare = |target: &Value| {
        crate::value_contract::global::compare_logical(&source, target, &plan, &[], clocks).unwrap()
    };
    let result = compare(&target);
    assert!(result.passed(), "{:?}", result.differences);
    assert_eq!(result.time_validations[crate::policy::GLOBAL_JSON_ID], 512);
    target["items"][400]["timestamp"] = json!(9999);
    assert!(!compare(&target).passed());
    target["items"][400]["timestamp"] = json!(2460);
    target["items"][400]["text"] = json!("changed");
    assert!(!compare(&target).passed());
}
