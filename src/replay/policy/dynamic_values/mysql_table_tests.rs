use super::*;
use crate::replay::{ReplaySessionIdentity, policy::matcher::MysqlPolicyContext};
use serde_json::json;

fn rule() -> DynamicValueRule {
    serde_json::from_value(json!({"id":"name","api":"/items","targets":[{"host":"service.test","port":3306}],
        "capture":{"protocol":"mysql","target":{"host":"service.test","port":3306},"database":"app",
            "sql":"SELECT id FROM {{table}} WHERE {{table}}.name=? AND owner_id=?",
            "table_series":{"prefix":"items_","start":0,"end":2,"width":4},"value_index":0},
        "source_evidence":"ItemStore selects items_{user_id % 3:04d} and generates a fresh random name"})).unwrap()
}

#[test]
fn mysql_capture_table_schema_preserves_legacy_and_rejects_unbounded_or_misplaced_markers() {
    let mut value = serde_json::to_value(rule()).unwrap();
    value["capture"]["sql"] = json!("SELECT id FROM items WHERE name=? AND owner_id=?");
    value["capture"]
        .as_object_mut()
        .unwrap()
        .remove("table_series");
    let legacy: DynamicValueRule = serde_json::from_value(value.clone()).unwrap();
    legacy.validate().unwrap();
    assert_eq!(serde_json::to_value(legacy).unwrap(), value);
    for mode in [
        "bare_wildcard",
        "missing_bounds",
        "missing_marker",
        "literal",
        "fragment",
        "column",
        "alias",
        "large_series",
        "large_width",
    ] {
        let mut value = serde_json::to_value(rule()).unwrap();
        match mode {
            "bare_wildcard" => {
                value["capture"]
                    .as_object_mut()
                    .unwrap()
                    .remove("table_series");
                value["capture"]["table_patterns"] = json!(["*"]);
            }
            "missing_bounds" => {
                value["capture"]
                    .as_object_mut()
                    .unwrap()
                    .remove("table_series");
            }
            "missing_marker" => {
                value["capture"]["sql"] = json!("SELECT id FROM items WHERE name=? AND owner_id=?")
            }
            "literal" => {
                value["capture"]["sql"] =
                    json!("SELECT id FROM items WHERE name='{{table}}' AND owner_id=?")
            }
            "fragment" => {
                value["capture"]["sql"] = json!("SELECT id FROM pre{{table}} WHERE name=?")
            }
            "column" => value["capture"]["sql"] = json!("UPDATE items SET {{table}}=?"),
            "alias" => {
                value["capture"]["sql"] = json!("SELECT id FROM items AS {{table}} WHERE name=?")
            }
            "large_series" => value["capture"]["table_series"]["end"] = json!(4096),
            "large_width" => value["capture"]["table_series"]["width"] = json!(11),
            _ => unreachable!(),
        }
        let invalid: DynamicValueRule = serde_json::from_value(value).unwrap();
        assert!(invalid.validate().is_err(), "{mode}");
    }
}

#[test]
fn mysql_capture_pair_binds_source_table_and_keeps_reference_tables_exact() {
    let rule = rule();
    rule.validate().unwrap();
    let runtime = DynamicValues::new(
        vec![rule],
        BTreeMap::from([("case".into(), "/items".into())]),
    );
    let identity = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "service.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: None,
    };
    let source = "SELECT id FROM `items_0001` WHERE items_0001.name='old-name' AND owner_id=7";
    for (table, qualifier, expected) in [
        ("items_0001", "items_0001", true),
        ("items_0002", "items_0002", false),
        ("items_0001", "items_0002", false),
        ("items_0003", "items_0003", false),
        ("items_1", "items_1", false),
    ] {
        let actual =
            format!("SELECT id FROM {table} WHERE {qualifier}.name='new-name' AND owner_id=7");
        let result = runtime
            .mysql(&MysqlPolicyContext {
                case_id: Some("case"),
                identity: &identity,
                command: "COM_QUERY",
                recorded_sql: Some(source),
                sql: Some(&actual),
                recorded: None,
                actual: None,
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            result.decision.pairs.len(),
            usize::from(expected),
            "{table}/{qualifier}"
        );
        if expected {
            runtime.commit("case", result.decision);
        }
    }
    let source = "UPDATE other_0001 SET name='old-name'";
    let actual = "UPDATE other_0002 SET name='new-name'";
    let result = runtime
        .mysql(&MysqlPolicyContext {
            case_id: Some("case"),
            identity: &identity,
            command: "COM_QUERY",
            recorded_sql: Some(source),
            sql: Some(actual),
            recorded: None,
            actual: None,
        })
        .unwrap()
        .unwrap();
    assert!(result.decision.pairs.is_empty());
    assert_ne!(
        crate::mysql::sql::tokens(result.source_sql.as_deref().unwrap()),
        crate::mysql::sql::tokens(result.actual_sql.as_deref().unwrap())
    );
}

#[test]
fn mysql_capture_audit_cannot_restore_a_binding_from_another_allowed_table() {
    use crate::replay::policy::config::fingerprint;
    let rule = rule();
    let source = |table: &str| json!({"event_type":"mysql_exchange","target_host":"service.test","target_port":3306,"database":"app","username":"user","sql":format!("SELECT id FROM {table} WHERE {table}.name='old-name' AND owner_id=7")});
    let report = json!({"replay_policy":{"dynamic_bindings":[{"case_id":"case","rule_id":"name","source_fingerprint":fingerprint(b"old-name"),"target_fingerprint":fingerprint(b"new-name")}]},
        "matched_queries":[{"case_id":"case","target":{"host":"service.test","port":3306},"database":"app","username":"user","sql":"SELECT id FROM items_0001 WHERE items_0001.name='new-name' AND owner_id=7"}]});
    for table in ["items_0001", "items_0002", "items_0003"] {
        let bytes = serde_json::to_vec(&source(table)).unwrap();
        let runtime = DynamicValues::new(
            vec![rule.clone()],
            BTreeMap::from([("case".into(), "/items".into())]),
        );
        runtime.observe_source("case", &bytes).unwrap();
        assert_eq!(runtime.rule_reports()[0].applicable, table != "items_0003");
        let result = from_report(
            std::slice::from_ref(&rule),
            &report,
            "case",
            "/items",
            &bytes,
            &[],
            &[],
        );
        assert_eq!(result.is_ok(), table == "items_0001", "{table}");
    }
}

#[test]
fn mysql_capture_scope_rejects_range_overlaps_but_allows_other_tables_and_json_fields() {
    let series = rule();
    for (table, expected) in [("items_0002", false), ("items_0003", true)] {
        let mut exact = serde_json::to_value(&series).unwrap();
        exact["id"] = json!("second");
        exact["capture"]["sql"] = json!(format!(
            "SELECT id FROM {table} WHERE {table}.name=? AND owner_id=?"
        ));
        exact["capture"]
            .as_object_mut()
            .unwrap()
            .remove("table_series");
        let exact: DynamicValueRule = serde_json::from_value(exact).unwrap();
        assert_eq!(
            validate(&[series.clone(), exact]).is_ok(),
            expected,
            "{table}"
        );
    }
    let mut first = series.clone();
    let mut second = series;
    second.id = "other-field".into();
    if let DynamicValueCapture::Mysql { json_pointer, .. } = &mut first.capture {
        *json_pointer = Some("/id".into());
    }
    if let DynamicValueCapture::Mysql { json_pointer, .. } = &mut second.capture {
        *json_pointer = Some("/other".into());
    }
    assert!(validate(&[first, second]).is_ok());
}
