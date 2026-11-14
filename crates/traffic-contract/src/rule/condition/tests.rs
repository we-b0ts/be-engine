use super::*;
use serde_json::json;

#[test]
fn field_conditions_select_source_siblings_and_preserve_target_discriminators() {
    let when: FieldCondition =
        serde_json::from_value(json!({"relative_pointer":"../type","equals":"text"})).unwrap();
    when.validate("/block/id").unwrap();
    for (kind, active) in [("text", true), ("thinking", false), ("tool", false)] {
        let source = json!({"block":{"type":kind,"id":"original"}});
        let target = json!({"block":{"type":kind,"id":"independent"}});
        assert_eq!(
            when.matches_pair(&source, &target, "/block/id", "/block/id")
                .unwrap(),
            active
        );
        let changed = json!({"block":{"type":"other","id":"original"}});
        assert!(
            when.matches_pair(&source, &changed, "/block/id", "/block/id")
                .is_err()
        );
    }
    for value in [
        json!({"block":{}}),
        json!({"block":{"type":null}}),
        json!({"block":{"type":1}}),
    ] {
        assert!(
            when.matches_pair(&value, &value, "/block/id", "/block/id")
                .is_err()
        );
    }
    // Reordered collections supply independent concrete Source/Target paths.
    let source = json!({"items":[{"type":"text"} ,{"type":"tool"}]});
    let target = json!({"items":[{"type":"tool"} ,{"type":"text"}]});
    assert!(
        when.matches_pair(&source, &target, "/items/0/id", "/items/1/id")
            .unwrap()
    );
}

#[test]
fn field_conditions_reject_ambiguous_predicates_and_sibling_scope_escapes() {
    for raw in [
        json!({"relative_pointer":"../type","equals":null}),
        json!({"relative_pointer":"../type","equals":null,"not_in":["tool"]}),
        json!({"relative_pointer":"../type","equals":"text","not_in":["tool"]}),
        json!({"relative_pointer":"../type","not_in":[]}),
        json!({"relative_pointer":"../type","not_in":[true,"tool"]}),
        json!({"relative_pointer":"../../type","equals":"text"}),
        json!({"relative_pointer":"../*/type","equals":"text"}),
        json!({"relative_pointer":"../id","equals":"text"}),
    ] {
        assert!(
            serde_json::from_value::<FieldCondition>(raw.clone())
                .and_then(|v| v.validate("/id").map_err(serde::de::Error::custom))
                .is_err(),
            "{raw}"
        );
    }
}

#[test]
fn self_conditions_preserve_exact_sentinels_and_reject_target_branch_changes() {
    let when: FieldCondition =
        serde_json::from_value(json!({"relative_pointer":".","not_in":["1970-01-01 00:00:00"]}))
            .unwrap();
    when.validate("").unwrap();
    assert!(
        !when
            .matches_pair(
                &json!("1970-01-01 00:00:00"),
                &json!("1970-01-01 00:00:00"),
                "",
                ""
            )
            .unwrap()
    );
    assert!(
        when.matches_pair(
            &json!("2026-10-23 12:00:00"),
            &json!("2026-10-24 12:00:00"),
            "",
            ""
        )
        .unwrap()
    );
    assert!(
        when.matches_pair(
            &json!("1970-01-01 00:00:00"),
            &json!("2026-10-23 12:00:00"),
            "",
            ""
        )
        .is_err()
    );
}

#[test]
fn nullable_self_conditions_distinguish_null_from_missing_and_preserve_branch() {
    let when: FieldCondition =
        serde_json::from_value(json!({"relative_pointer":".","not_in":[null]})).unwrap();
    when.validate("/completedAt").unwrap();
    assert!(
        !when
            .matches_pair(
                &json!({"completedAt":null}),
                &json!({"completedAt":null}),
                "/completedAt",
                "/completedAt"
            )
            .unwrap()
    );
    assert!(
        when.matches_pair(
            &json!({"completedAt":"2026-10-23T00:00:00"}),
            &json!({"completedAt":"2026-10-24T00:00:00"}),
            "/completedAt",
            "/completedAt"
        )
        .unwrap()
    );
    assert!(
        when.matches_pair(&json!({}), &json!({}), "/completedAt", "/completedAt")
            .is_err()
    );
    assert!(
        when.matches_pair(
            &json!({"completedAt":null}),
            &json!({"completedAt":"2026-10-24T00:00:00"}),
            "/completedAt",
            "/completedAt"
        )
        .is_err()
    );
}

#[test]
fn self_conditions_support_both_null_and_a_typed_sentinel_without_relaxing_types() {
    for excluded in [
        json!([null, "1970-01-01 00:00:00"]),
        json!(["1970-01-01 00:00:00", null]),
    ] {
        let when: FieldCondition =
            serde_json::from_value(json!({"relative_pointer":".","not_in":excluded})).unwrap();
        when.validate("").unwrap();
        for sentinel in [json!(null), json!("1970-01-01 00:00:00")] {
            assert!(!when.matches_pair(&sentinel, &sentinel, "", "").unwrap());
        }
        assert!(
            when.matches_pair(
                &json!("2026-10-23 00:00:00"),
                &json!("2026-10-24 00:00:00"),
                "",
                ""
            )
            .unwrap()
        );
        assert!(when.matches_pair(&json!(3), &json!(3), "", "").is_err());
    }
}
