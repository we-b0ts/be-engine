use super::*;
use chrono::{TimeZone, Utc};
use serde_json::json;

fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
            source: Some(Utc.timestamp_opt(10, 0).unwrap()),
            target: Some(Utc.timestamp_opt(110, 0).unwrap()),
        },
        ..Default::default()
    }
}

fn time(scope: ClockScope) -> FieldContract {
    FieldContract::Time {
        format: TimestampFormat::UnixMicroseconds,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::DependencyRequestStart,
        utc_offset: None,
        clock_group: Some("row-7".into()),
        clock_scope: scope,
    }
}

#[test]
fn array_scope_separates_reads_but_retains_copies_and_strict_structure() {
    let scoped = time(ClockScope::ArrayElement);
    let shared = time(ClockScope::Shared);
    let source = json!({"blocks":[{"at":12_000_000,"copy":12_000_000,"text":"a"},{"at":13_000_000,"copy":13_000_000,"text":"b"}]});
    let target = json!({"blocks":[{"at":112_000_000,"copy":112_000_000,"text":"a"},{"at":113_500_000,"copy":113_500_000,"text":"b"}]});
    let compare_with = |a: &Value, b: &Value, contract: &FieldContract| {
        compare(
            a,
            b,
            &[
                Field {
                    rule_id: "at",
                    pointer: "/blocks/*/at",
                    contract,
                },
                Field {
                    rule_id: "copy",
                    pointer: "/blocks/*/copy",
                    contract,
                },
            ],
            clocks(),
        )
    };
    assert!(compare_with(&source, &target, &scoped).passed());
    assert!(!compare_with(&source, &target, &shared).passed());
    for mutation in ["copy", "stable", "order", "length", "type", "anchor"] {
        let mut bad = target.clone();
        match mutation {
            "copy" => bad["blocks"][1]["copy"] = json!(113_500_001),
            "stable" => bad["blocks"][1]["text"] = json!("wrong"),
            "order" => bad["blocks"].as_array_mut().unwrap().reverse(),
            "length" => {
                bad["blocks"].as_array_mut().unwrap().pop();
            }
            "type" => bad["blocks"][1]["at"] = json!("113500000"),
            _ => bad["blocks"][1]["at"] = json!(119_000_000),
        }
        assert!(!compare_with(&source, &bad, &scoped).passed(), "{mutation}");
    }
    for value in [
        json!({"blocks":[]}),
        json!({"stable":1}),
        json!({"blocks":[{"text":"no clock"}]}),
    ] {
        assert!(compare_with(&value, &value, &scoped).passed());
        let mut changed = value.clone();
        changed["blocks"] = json!([{"at":112_000_000}]);
        assert!(!compare_with(&value, &changed, &scoped).passed());
    }
}

#[test]
fn nested_arrays_keep_full_coordinates_and_object_numbers_remain_exact() {
    let contract = time(ClockScope::ArrayElement);
    let fields = [Field {
        rule_id: "clock",
        pointer: "/groups/*/blocks/*/at",
        contract: &contract,
    }];
    let source = json!({"groups":[{"blocks":[{"at":12_000_000}]},{"blocks":[{"at":12_000_000}]}]});
    let target =
        json!({"groups":[{"blocks":[{"at":112_000_000}]},{"blocks":[{"at":112_500_000}]}]});
    assert!(compare(&source, &target, &fields, clocks()).passed());
    let source = json!({"groups":{"0":{"blocks":[{"at":12_000_000}]}}});
    let target = json!({"groups":{"0":{"blocks":[{"at":112_000_000}]}}});
    assert!(!compare(&source, &target, &fields, clocks()).passed());
    assert!(compare(&source, &source, &fields, clocks()).passed());
    let literal = json!({"groups":{"*":{"blocks":[{"at":12_000_000}]}}});
    assert!(!compare(&literal, &literal, &fields, clocks()).passed());
}

fn entity(source: Value, target: Value, array: bool) -> Comparison {
    let clock = time(ClockScope::Entity {
        relative_pointer: "../id".into(),
    });
    let identity = FieldContract::Identity {
        prefix: "text-".into(),
        format: crate::rule::IdentityFormat::Decimal,
    };
    let (at, id) = if array {
        ("/blocks/*/at", "/blocks/*/id")
    } else {
        ("/block/at", "/block/id")
    };
    compare(
        &source,
        &target,
        &[
            Field {
                rule_id: "clock",
                pointer: at,
                contract: &clock,
            },
            Field {
                rule_id: "identity",
                pointer: id,
                contract: &identity,
            },
        ],
        clocks(),
    )
}

#[test]
fn entity_clocks_follow_identity_across_frames_and_terminal_array_positions() {
    let mut result = entity(
        json!({"block":{"id":"text-1","at":12_000_000}}),
        json!({"block":{"id":"text-101","at":112_000_000}}),
        false,
    );
    result.merge_and_validate(entity(
        json!({"block":{"id":"text-2","at":13_000_000}}),
        json!({"block":{"id":"text-102","at":113_500_000}}),
        false,
    ));
    assert!(result.passed());
    let source =
        json!({"blocks":[{"id":"text-1","at":12_000_000},{"id":"text-2","at":13_000_000}]});
    let target =
        json!({"blocks":[{"id":"text-101","at":112_000_000},{"id":"text-102","at":113_500_000}]});
    let mut correct = result.clone();
    correct.merge_and_validate(entity(source.clone(), target.clone(), true));
    assert!(correct.passed());
    for bad_identity in [false, true] {
        let mut changed = target.clone();
        if bad_identity {
            changed["blocks"][1]["id"] = json!("text-101");
        } else {
            changed["blocks"][1]["at"] = json!(113_500_001);
        }
        let mut wrong = result.clone();
        wrong.merge_and_validate(entity(source.clone(), changed, true));
        assert!(!wrong.passed());
    }
    assert!(entity(source, target, true).passed());
}

#[test]
fn scopes_share_one_bounded_relationship_budget_across_frames() {
    let mut result = Comparison::default();
    for index in 0..=MAX_TIME_OBSERVATIONS {
        let mut frame = Comparison::default();
        frame.relationships.insert(
            (
                TimeAnchor::DependencyRequestStart,
                Some("same-name".into()),
                ScopeKey::ArrayElement(format!("/blocks/{index}")),
            ),
            vec![(1, 101)],
        );
        result.merge_and_validate(frame);
    }
    assert!(!result.passed());
    assert_eq!(result.relationships.len(), MAX_TIME_OBSERVATIONS);
}
