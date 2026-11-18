use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::test_compare as compare;
    use serde_json::json;

    fn contract(group: &str) -> FieldContract {
        serde_json::from_value(json!({"kind":"time","format":"unix_seconds",
            "relation":"preserve_offset","clock_group":group}))
        .unwrap()
    }

    #[test]
    fn compatible_clocks_retain_both_rule_usage_and_contextual_relationships() {
        let global = contract("field-a");
        let contextual = contract("same-clock");
        let fields = [
            Field {
                rule_id: "global",
                pointer: "/a",
                contract: &global,
            },
            Field {
                rule_id: "context",
                pointer: "/a",
                contract: &contextual,
            },
            Field {
                rule_id: "context",
                pointer: "/b",
                contract: &contextual,
            },
        ];
        let clocks = AnchorClocks {
            dependency: time::ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        let source = json!({"a":1010,"b":1020});
        let result = compare(&source, &json!({"a":2010,"b":2020}), &fields, clocks);
        assert!(result.passed(), "{:?}", result.differences);
        assert_eq!(
            result.evaluated,
            BTreeSet::from(["global".into(), "context".into()])
        );
        assert!(!compare(&source, &json!({"a":2010,"b":2021}), &fields, clocks).passed());
        let incompatible = FieldContract::Unordered;
        let invalid = [
            fields[0],
            Field {
                rule_id: "invalid",
                pointer: "/a",
                contract: &incompatible,
            },
        ];
        assert!(!compare(&source, &source, &invalid, clocks).passed());
    }

    #[test]
    fn nested_schema_occurrences_keep_outer_carriers_and_explicit_groups_distinct() {
        let automatic = contract("schema.0123456789abcdef0123456789abcdef");
        let explicit = contract("source-clock");
        let fields = [
            Field {
                rule_id: "global",
                pointer: "/automatic",
                contract: &automatic,
            },
            Field {
                rule_id: "explicit",
                pointer: "/explicit",
                contract: &explicit,
            },
        ];
        let clocks = AnchorClocks {
            dependency: time::ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        let source = json!({"automatic":1010});
        let mut nested = compare(&source, &json!({"automatic":2010}), &fields[..1], clocks);
        assert!(nested.passed());
        nested.scope_schema_clocks_in("cipher:/user");
        nested.scope_schema_clocks(1);
        let mut conflicting = compare(&source, &json!({"automatic":2011}), &fields[..1], clocks);
        assert!(conflicting.passed());
        conflicting.scope_schema_clocks_in("cipher:/user");
        conflicting.scope_schema_clocks(2);
        nested.merge_and_validate(conflicting);
        assert!(
            nested.passed(),
            "independent physical values keep their own schema groups"
        );

        let mut explicit = compare(
            &json!({"explicit":1020}),
            &json!({"explicit":2020}),
            &fields[1..],
            clocks,
        );
        explicit.scope_schema_clocks_in("cipher:/user");
        explicit.scope_schema_clocks(1);
        let mut conflicting = compare(
            &json!({"explicit":1020}),
            &json!({"explicit":2021}),
            &fields[1..],
            clocks,
        );
        conflicting.scope_schema_clocks_in("cipher:/user");
        conflicting.scope_schema_clocks(2);
        explicit.merge_and_validate(conflicting);
        assert!(
            !explicit.passed(),
            "explicit Source groups still relate independent carrier observations"
        );
    }
}

#[cfg(test)]
mod sentinel_tests {
    use super::*;
    use crate::compare::test_compare as compare;
    use serde_json::json;

    #[test]
    fn inactive_self_guard_dominates_contextual_time_permission() {
        let guarded:FieldContract=serde_json::from_value(json!({"kind":"conditional","when":{"relative_pointer":".","not_in":[0]},"contract":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"}})).unwrap();
        let context = guarded.unconditional().clone();
        let fields = [
            Field {
                rule_id: "field",
                pointer: "",
                contract: &guarded,
            },
            Field {
                rule_id: "context",
                pointer: "",
                contract: &context,
            },
        ];
        let clocks = AnchorClocks {
            dependency: time::ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        assert!(compare(&json!(0), &json!(0), &fields, clocks).passed());
        assert!(!compare(&json!(0), &json!(1000), &fields, clocks).passed());
        assert!(compare(&json!(1010), &json!(2010), &fields, clocks).passed());
    }
}
