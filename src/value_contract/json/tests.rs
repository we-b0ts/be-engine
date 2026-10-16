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
fn source_sibling_condition_keeps_terminal_durations_exact_through_unordered_pairing() {
    let duration = FieldContract::Conditional {
        when: crate::policy::FieldCondition {
            relative_pointer: "../status".into(),
            not_in: vec![crate::policy::SourceScalar::String("closed".into())],
        },
        contract: Box::new(FieldContract::Duration {
            unit: crate::policy::DurationUnit::Seconds,
            anchor: crate::policy::TimeAnchor::ApiRequestStart,
        }),
    };
    let unordered = FieldContract::Unordered;
    let fields = [
        Field {
            rule_id: "duration",
            pointer: "/items/*/duration",
            contract: &duration,
        },
        Field {
            rule_id: "members",
            pointer: "/items",
            contract: &unordered,
        },
    ];
    let source = json!({"items":[{"id":1,"status":"pending","duration":10},{"id":2,"status":"closed","duration":7}]});
    let target = json!({"items":[{"id":2,"status":"closed","duration":7},{"id":1,"status":"pending","duration":110}]});
    assert!(compare(&source, &target, &fields, clocks()).passed());
    let mut wrong = target.clone();
    wrong["items"][0]["duration"] = json!(107);
    assert!(!compare(&source, &wrong, &fields, clocks()).passed());
    wrong = target.clone();
    wrong["items"][1]["duration"] = json!(10);
    assert!(!compare(&source, &wrong, &fields, clocks()).passed());
    wrong = target;
    wrong["items"][1]["status"] = json!("closed");
    assert!(!compare(&source, &wrong, &fields, clocks()).passed());
    for broken in [
        json!({"items":[{"id":1,"duration":10}]}),
        json!({"items":[{"id":1,"status":false,"duration":10}]}),
    ] {
        assert!(!compare(&broken, &broken, &fields, clocks()).passed());
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
        clock_group: None,
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
        clock_group: None,
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

#[test]
fn explicitly_independent_clocks_keep_each_anchor_window_and_strict_group_copies() {
    let clock = |group: Option<&str>| FieldContract::Time {
        format: TimestampFormat::UnixMicroseconds,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::ApiRequestStart,
        utc_offset: None,
        clock_group: group.map(str::to_owned),
    };
    let shared = clock(None);
    let event = clock(Some("event"));
    let independent = clock(Some("after_commit"));
    let source = json!({"a":12_000_001,"copy":12_000_001,"b":13_000_002});
    let target = json!({"a":112_000_001,"copy":112_000_001,"b":113_500_002});
    let default = [
        Field {
            rule_id: "time",
            pointer: "/a",
            contract: &shared,
        },
        Field {
            rule_id: "time",
            pointer: "/copy",
            contract: &shared,
        },
        Field {
            rule_id: "time",
            pointer: "/b",
            contract: &shared,
        },
    ];
    assert!(!compare(&source, &target, &default, clocks()).passed());
    let grouped = [
        Field {
            rule_id: "time",
            pointer: "/a",
            contract: &event,
        },
        Field {
            rule_id: "time",
            pointer: "/copy",
            contract: &event,
        },
        Field {
            rule_id: "time",
            pointer: "/b",
            contract: &independent,
        },
    ];
    assert!(compare(&source, &target, &grouped, clocks()).passed());
    let mut changed = target.clone();
    changed["copy"] = json!(112_000_002);
    assert!(!compare(&source, &changed, &grouped, clocks()).passed());
    changed = target;
    changed["b"] = json!(119_000_002);
    assert!(!compare(&source, &changed, &grouped, clocks()).passed());
}
