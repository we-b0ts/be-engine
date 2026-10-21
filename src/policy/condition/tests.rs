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
