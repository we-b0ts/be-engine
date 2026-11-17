use super::*;
use crate::value_contract::time::ClockPair;
use serde_json::json;
fn policy(headers: &str) -> HttpPolicy {
    serde_yaml::from_str::<HttpPolicy>(&format!("headers:\n{headers}"))
        .unwrap()
        .compile()
        .unwrap()
}
fn snapshot(name: &str, values: &[&str]) -> HeaderSnapshot {
    BTreeMap::from([(
        name.into(),
        values.iter().map(|value| value.to_string()).collect(),
    )])
}
fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2026-10-18T00:00:00Z".parse().unwrap()),
        },
        ..Default::default()
    }
}
#[test]
fn global_header_time_preserves_case_insensitive_presence_repeated_order_and_native_remainder() {
    let policy = policy("  X-Amz-Date: {kind: time, formats: [amz_date]}\n");
    let source = snapshot("X-AMZ-DATE", &["20200101T000000Z", "20200101T000030Z"]);
    let target = snapshot("x-amz-date", &["20261018T000000Z", "20261018T000030Z"]);
    let checked = compare(&source, &target, &policy, clocks()).unwrap();
    assert!(checked.passed(), "{:?}", checked.differences);
    assert_eq!(checked.time_validations[GLOBAL_HTTP_ID], 2);
    for target in [
        snapshot("x-amz-date", &["20261018T000030Z", "20261018T000000Z"]),
        snapshot("x-amz-date", &["20261018T000000Z"]),
        snapshot("x-amz-date", &["20261018T000030Z", "20261018T000060Z"]),
        HeaderSnapshot::new(),
    ] {
        assert!(
            !compare(&source, &target, &policy, clocks())
                .unwrap()
                .passed()
        );
    }
    assert!(
        compare(&source, &source, &policy, Default::default())
            .unwrap()
            .passed()
    );
    assert!(
        !compare(&HeaderSnapshot::new(), &target, &policy, clocks())
            .unwrap()
            .passed()
    );
    assert!(
        compare(
            &HeaderSnapshot::new(),
            &HeaderSnapshot::new(),
            &policy,
            Default::default()
        )
        .unwrap()
        .evaluated
        .is_empty()
    );
    let mut with_remainder = target.clone();
    with_remainder.insert("x-static".into(), vec!["changed".into()]);
    let masked = mask(&source, &with_remainder, &policy).unwrap();
    assert_eq!(masked["x-amz-date"], source["X-AMZ-DATE"]);
    assert_eq!(masked["x-static"], vec!["changed"]);
}
#[test]
fn header_identity_is_the_complete_text_value_and_joins_the_json_identity_graph() {
    let policy = policy("  x-item-id: {kind: identity, formats: [uuid]}\n");
    let a = "11111111-1111-4111-8111-111111111111";
    let b = "22222222-2222-4222-8222-222222222222";
    let c = "33333333-3333-4333-8333-333333333333";
    let header = compare(
        &snapshot("X-Item-Id", &[a, a]),
        &snapshot("x-item-id", &[b, b]),
        &policy,
        Default::default(),
    )
    .unwrap();
    assert!(header.passed());
    assert_eq!(header.identity_pairs().len(), 1);
    assert!(
        !compare(
            &snapshot("x-item-id", &[a, a]),
            &snapshot("x-item-id", &[b, c]),
            &policy,
            Default::default()
        )
        .unwrap()
        .passed()
    );
    let json_plan = JsonPolicy {
        fields: BTreeMap::from([("/id".into(), policy.headers["x-item-id"].clone())]),
    }
    .compile()
    .unwrap();
    let mut joined = header;
    joined.merge_and_validate(
        super::super::global::compare_logical(
            &json!({"id":a}),
            &json!({"id":c}),
            &json_plan,
            &[],
            Default::default(),
        )
        .unwrap(),
    );
    assert!(!joined.passed());
}
#[test]
fn numeric_time_text_uses_source_format_while_unknown_header_text_stays_exact() {
    let policy = policy("  x-created: {kind: time, formats: [unix_seconds]}\n");
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    };
    assert!(
        compare(
            &snapshot("x-created", &["1000"]),
            &snapshot("x-created", &["2000"]),
            &policy,
            clocks
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            &snapshot("x-created", &[r#"{"x":1}"#]),
            &snapshot("x-created", &[r#"{ "x":1}"#]),
            &policy,
            clocks
        )
        .unwrap()
        .passed()
    );
    let mut ambiguous = snapshot("X-Created", &["1000"]);
    ambiguous.insert("x-created".into(), vec!["1000".into()]);
    assert!(compare(&ambiguous, &HeaderSnapshot::new(), &policy, clocks).is_err());
}

#[test]
fn unavailable_source_header_captures_remain_exact_without_identity_evidence() {
    let policy = policy("  authorization: {kind: identity, formats: [string]}\n");
    let source = snapshot("authorization", &["<redacted>"]);
    let same = compare(&source, &source, &policy, Default::default()).unwrap();
    assert!(same.passed());
    assert!(same.identity_pairs().is_empty());
    assert!(same.evaluated.is_empty());
    assert!(
        !compare(
            &source,
            &snapshot("authorization", &["different"]),
            &policy,
            Default::default()
        )
        .unwrap()
        .passed()
    );
}
