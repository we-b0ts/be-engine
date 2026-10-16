use super::*;
use chrono::{TimeZone, Utc};
use serde_json::json;

fn clocks() -> AnchorClocks {
    AnchorClocks {
        case: ClockPair {
            source: Some(Utc.timestamp_opt(10, 0).unwrap()),
            target: Some(Utc.timestamp_opt(110, 0).unwrap()),
        },
        ..Default::default()
    }
}

#[test]
fn multiset_preserves_duplicates_and_stable_fields() {
    let contract = FieldContract::Unordered;
    let fields = [Field {
        rule_id: "members",
        pointer: "/members",
        contract: &contract,
    }];
    let source = json!({"members":[1,1,2],"stable":true});
    assert!(
        compare(
            &source,
            &json!({"members":[2,1,1],"stable":true}),
            &fields,
            clocks()
        )
        .passed()
    );
    assert!(
        !compare(
            &source,
            &json!({"members":[2,2,1],"stable":true}),
            &fields,
            clocks()
        )
        .passed()
    );
    assert!(
        !compare(
            &source,
            &json!({"members":[2,1,1],"stable":false}),
            &fields,
            clocks()
        )
        .passed()
    );
}

#[test]
fn time_requires_independent_anchors_even_for_equal_values() {
    let contract = FieldContract::Time {
        format: TimestampFormat::UnixMicroseconds,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::ApiRequestStart,
        utc_offset: None,
    };
    let fields = [Field {
        rule_id: "clock",
        pointer: "/t",
        contract: &contract,
    }];
    let source = json!({"t":12_000_001});
    assert!(!compare(&source, &source, &fields, Default::default()).passed());
    assert!(compare(&source, &json!({"t":112_000_001}), &fields, clocks()).passed());
    assert!(!compare(&source, &json!({"t":118_000_001}), &fields, clocks()).passed());
}

#[test]
fn unordered_time_pairs_whole_elements_and_rejects_relationship_changes() {
    let unordered = FieldContract::Unordered;
    let time = FieldContract::Time {
        format: TimestampFormat::UnixMicroseconds,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::ApiRequestStart,
        utc_offset: None,
    };
    let fields = [
        Field {
            rule_id: "members",
            pointer: "/members",
            contract: &unordered,
        },
        Field {
            rule_id: "clock",
            pointer: "/members/*/t",
            contract: &time,
        },
    ];
    let source = json!({"members":[{"id":1,"t":12_000_001},{"id":2,"t":13_000_002}]});
    let target = json!({"members":[{"id":2,"t":113_000_002},{"id":1,"t":112_000_001}]});
    assert!(compare(&source, &target, &fields, clocks()).passed());
    let inconsistent = json!({"members":[{"id":2,"t":113_000_005},{"id":1,"t":112_000_001}]});
    assert!(!compare(&source, &inconsistent, &fields, clocks()).passed());
    let wrong_id = json!({"members":[{"id":1,"t":113_000_002},{"id":1,"t":112_000_001}]});
    assert!(!compare(&source, &wrong_id, &fields, clocks()).passed());
}

#[test]
fn null_absence_numeric_category_and_missing_rule_are_distinct() {
    assert!(!compare(&json!({"a":null}), &json!({}), &[], clocks()).passed());
    assert!(!compare(&json!({"a":1}), &json!({"a":1.0}), &[], clocks()).passed());
    let contract = FieldContract::Unordered;
    assert!(
        !compare(
            &json!({}),
            &json!({}),
            &[Field {
                rule_id: "missing",
                pointer: "/a",
                contract: &contract
            }],
            clocks()
        )
        .passed()
    );
}

#[test]
fn evaluated_usage_includes_equal_selected_fields() {
    let contract = FieldContract::Unordered;
    let value = json!({"a":[1,2]});
    let result = compare(
        &value,
        &value,
        &[Field {
            rule_id: "evaluated",
            pointer: "/a",
            contract: &contract,
        }],
        clocks(),
    );
    assert!(result.passed());
    assert!(result.evaluated.contains("evaluated"));
}
