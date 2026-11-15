use super::*;
use serde_json::json;

fn selected(pointer: &str, contract: FieldContract) -> SelectedGlobalField {
    SelectedGlobalField {
        pattern: pointer.into(),
        pointer: pointer.into(),
        contract,
        rule_id: traffic_policy_value::fields::GLOBAL_JSON_ID,
        origin: traffic_policy_value::fields::FieldOrigin::Declared,
    }
}

fn legacy<'a>(
    source: &Value,
    mut fields: Vec<Field<'a>>,
    selected: &'a [SelectedGlobalField],
) -> Vec<Field<'a>> {
    for selected in selected {
        let existing = fields
            .iter()
            .filter(|field| {
                delivery::select(field.pointer, source)
                    .is_ok_and(|paths| paths.contains(&selected.pointer))
            })
            .collect::<Vec<_>>();
        if existing.is_empty()
            || !existing
                .iter()
                .all(|field| *field.contract == selected.contract)
        {
            fields.push(Field {
                rule_id: selected.rule_id,
                pointer: &selected.pointer,
                contract: &selected.contract,
            });
        }
    }
    fields
}

#[test]
fn indexed_composition_matches_previous_selection_for_overlaps_and_source_shapes() {
    let source = json!({"items":[{"id":1},{"id":2}],"object":{"0":{"id":3}},"*":4,"a/b":{"~":5}});
    let identity = FieldContract::IdentityAnchor;
    let other = FieldContract::Unordered;
    let fields = vec![
        Field {
            rule_id: "first",
            pointer: "/items/*/id",
            contract: &identity,
        },
        Field {
            rule_id: "second",
            pointer: "/items/0/id",
            contract: &other,
        },
        Field {
            rule_id: "object",
            pointer: "/object/*/id",
            contract: &identity,
        },
        Field {
            rule_id: "escaped",
            pointer: "/a~1b/~0",
            contract: &identity,
        },
    ];
    let declarations = vec![
        selected("/items/0/id", identity.clone()),
        selected("/items/1/id", identity.clone()),
        selected("/items/1/id", identity.clone()),
        selected("/object/0/id", identity.clone()),
        selected("/*", identity.clone()),
        selected("/*", identity.clone()),
        selected("/a~1b/~0", identity.clone()),
        selected("/missing", identity.clone()),
    ];
    let expected = legacy(&source, fields.clone(), &declarations);
    let actual = append(&source, fields, &declarations);
    let signature = |fields: Vec<Field<'_>>| {
        fields
            .into_iter()
            .map(|field| {
                (
                    field.rule_id.to_owned(),
                    field.pointer.to_owned(),
                    field.contract.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(signature(expected), signature(actual));
}
