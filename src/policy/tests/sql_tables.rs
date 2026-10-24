use super::*;
use serde_json::{Value, json};

fn value() -> Value {
    json!({"id":"completed","surface":"dependency.request","match":{"api":"GET /api","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"operation":"COM_QUERY","sql":"UPDATE {{table}} SET payload=?, updated_at=? WHERE {{table}}.id=?","table_series":{"prefix":"tasks_","start":1,"end":2,"width":4}},
        "slot":{"sql_value":0},"codec":"json","contract":{"/status/completedAt":{"kind":"conditional","when":{"relative_pointer":"../status","equals":"COMPLETED"},"contract":{"relative_time":"iso8601_naive","clock_group":"completed"}}},
        "proof":{"source":"tasks.py:complete","fact":"Completion time is generated only in the terminal branch; all other fields and rows stay exact"}})
}

fn compile(rules: Value) -> anyhow::Result<CompiledPolicy> {
    parse_and_compile_policy(&json!({"format":"traffic-policy/v2","rules":rules}).to_string())
}

#[test]
fn sql_value_table_selectors_reuse_bounded_native_table_admission() {
    for declaration in [
        json!({"table_series":{"prefix":"tasks_","start":1,"end":2,"width":4}}),
        json!({"tables":["tasks_0001","tasks_0002"]}),
        json!({"table_patterns":["tasks_*"]}),
    ] {
        let mut rule = value();
        rule["match"]
            .as_object_mut()
            .unwrap()
            .remove("table_series");
        rule["match"]
            .as_object_mut()
            .unwrap()
            .extend(declaration.as_object().unwrap().clone());
        let doc = parse_policy(&json!({"format":"traffic-policy/v2","rules":[rule]}).to_string())
            .unwrap();
        let rendered = render_policy(&doc).unwrap();
        assert_eq!(parse_policy(&rendered).unwrap(), doc);
        assert!(compile_policy(&doc).is_ok());
    }
    for (field, replacement) in [
        (
            "table_series",
            json!({"prefix":"tasks_","start":2,"end":1,"width":4}),
        ),
        (
            "table_series",
            json!({"prefix":"tasks_","start":0,"end":1023,"width":11}),
        ),
        ("table_patterns", json!(["*"])),
        (
            "sql",
            json!("UPDATE pre_{{table}} SET payload=?, updated_at=? WHERE id=?"),
        ),
        (
            "sql",
            json!("UPDATE tasks SET payload=?, updated_at=? WHERE id=?"),
        ),
        (
            "sql",
            json!("UPDATE tasks SET payload=?, note='{{table}}' WHERE id=?"),
        ),
        (
            "sql",
            json!("UPDATE {{table}} SET payload=?, updated_at=? WHERE id=?; DELETE FROM tasks"),
        ),
    ] {
        let mut rule = value();
        rule["match"][field] = replacement;
        assert!(compile(json!([rule])).is_err(), "{field}");
    }
    let mut rule = value();
    rule["match"]
        .as_object_mut()
        .unwrap()
        .remove("table_series");
    assert!(compile(json!([rule])).is_err());
    let mut rule = value();
    rule["match"]["resource"]["protocol"] = json!("redis");
    assert!(compile(json!([rule])).is_err());
}

#[test]
fn sql_value_table_ownership_checks_declared_ranges_against_values_and_native_fields() {
    for native in [false, true] {
        for (start, end, accepted) in [(3, 4, true), (2, 3, false), (0, 1023, false)] {
            let mut other = value();
            other["id"] = json!("other");
            other["match"]["table_series"] =
                json!({"prefix":"tasks_","start":start,"end":end,"width":4});
            if native {
                for field in ["surface", "slot", "codec", "contract"] {
                    other.as_object_mut().unwrap().remove(field);
                }
                other["effect"] = json!({"kind":"mysql_values","values":{"0":{"kind":"json","fields":{"/status/completedAt":{"relative_time":"iso8601_naive","clock_group":"completed"}}}}});
            }
            assert_eq!(
                compile(json!([value(), other])).is_ok(),
                accepted,
                "native={native}, {start}..{end}"
            );
        }
    }
    for (table, accepted) in [("tasks_0002", false), ("tasks_0003", true)] {
        let mut other = value();
        other["id"] = json!("physical");
        other["match"]
            .as_object_mut()
            .unwrap()
            .remove("table_series");
        other["match"]["sql"] = json!(format!(
            "UPDATE {table} SET payload=?, updated_at=? WHERE {table}.id=?"
        ));
        assert_eq!(
            compile(json!([value(), other])).is_ok(),
            accepted,
            "{table}"
        );
    }
    let mut disjoint_field = value();
    disjoint_field["id"] = json!("updated");
    for field in ["surface", "slot", "codec", "contract"] {
        disjoint_field.as_object_mut().unwrap().remove(field);
    }
    disjoint_field["effect"] =
        json!({"kind":"mysql_values","values":{"1":{"relative_time":"sql_datetime"}}});
    assert!(compile(json!([value(), disjoint_field])).is_ok());
}
