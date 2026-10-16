use super::*;

fn table_fixture() -> (
    tempfile::TempDir,
    DynamicValueRuleFeedback,
    DynamicValueMysqlTimeRule,
) {
    let (temp, mut feedback, time) = fixture();
    let mut value = serde_json::to_value(&feedback.rule).unwrap();
    value["capture"]["sql"] = json!(SQL.replace("items", "{{table}}"));
    value["capture"]["tables"] = json!(["items_0009"]);
    value["capture"]["table_patterns"] = json!(["archived_items_*"]);
    value["capture"]["table_series"] = json!({"prefix":"items_","start":0,"end":2,"width":4});
    value["source_evidence"] = json!(
        "ItemStore chooses items_{user_id % 3:04d}, archived_items_* or items_0009 and generates the pending name"
    );
    feedback.rule = serde_json::from_value(value).unwrap();
    let source_path = temp.path().join("case/dependencies.jsonl");
    let mut source: Value = serde_json::from_slice(&fs::read(&source_path).unwrap()).unwrap();
    source["sql"] = json!(
        source["sql"]
            .as_str()
            .unwrap()
            .replace("items", "items_0001")
    );
    write(&source_path, &source);
    let mut report = report(&feedback);
    report["unmatched_queries"][0]["sql"] = json!(SQL.replace("items", "items_0001"));
    write(&feedback.replay_report, &report);
    (temp, feedback, time)
}

#[test]
fn table_companion_inherits_all_bounds_and_joint_plan_keeps_physical_tables_equal() {
    for mode in [
        "valid",
        "cross_table",
        "out_of_range",
        "bad_padding",
        "unselected_owner",
    ] {
        let (temp, feedback, time) = table_fixture();
        let proposed = time.proposed(&feedback.rule).unwrap();
        let mysql = proposed.mysql.as_ref().unwrap();
        assert_eq!(mysql.tables, ["items_0009"]);
        assert_eq!(mysql.table_patterns, ["archived_items_*"]);
        assert_eq!(mysql.table_series.as_ref().unwrap().end, 2);
        assert_eq!(mysql.sql, SQL.replace("items", "{{table}}"));
        let original = fs::read(&feedback.policy_path).unwrap();
        let source_path = temp.path().join("case/dependencies.jsonl");
        let source_bytes = fs::read(&source_path).unwrap();
        let mut actual = report(&feedback);
        match mode {
            "cross_table" => {
                actual["unmatched_queries"][0]["sql"] = json!(SQL.replace("items", "items_0002"))
            }
            "out_of_range" => {
                actual["unmatched_queries"][0]["sql"] = json!(SQL.replace("items", "items_0003"))
            }
            "bad_padding" => {
                actual["unmatched_queries"][0]["sql"] = json!(SQL.replace("items", "items_1"))
            }
            "unselected_owner" => actual["unmatched_queries"][0]["params"][3]["value"] = json!(8),
            _ => {}
        }
        write(&feedback.replay_report, &actual);
        let result = plan_dynamic_value_mysql_time_rule(feedback, time);
        assert_eq!(result.is_ok(), mode == "valid", "{mode}");
        if let Ok(plan) = result {
            let policy_path = plan.policy_path.clone();
            plan.apply().unwrap();
            let loaded = load_replay_policy(&policy_path).unwrap();
            assert_eq!(loaded.document.dependency_rules.len(), 1);
            assert_eq!(loaded.document.dynamic_values.len(), 1);
            assert_eq!(
                serde_json::to_value(&loaded.document.dependency_rules[0]).unwrap(),
                serde_json::to_value(proposed).unwrap()
            );
        } else {
            assert_eq!(
                fs::read(temp.path().join("verification.yaml")).unwrap(),
                original
            );
        }
        assert_eq!(fs::read(&source_path).unwrap(), source_bytes);
    }
}

#[test]
fn table_time_overlap_checks_unobserved_shards_and_disjoint_ranges() {
    let (_temp, feedback, time) = table_fixture();
    let proposed = time.proposed(&feedback.rule).unwrap();
    for (table, expected) in [
        ("items_0002", false),
        ("items_0003", true),
        ("items_0009", false),
        ("archived_items_old", false),
        ("other_items_0001", true),
    ] {
        let mut old = proposed.clone();
        old.id = "existing-time".into();
        let mysql = old.mysql.as_mut().unwrap();
        mysql.sql = SQL.replace("items", table);
        mysql.tables.clear();
        mysql.table_patterns.clear();
        mysql.table_series = None;
        assert_eq!(
            validate_time_overlaps(&proposed, std::slice::from_ref(&old)).is_ok(),
            expected,
            "{table}"
        );
        assert_eq!(
            validate_time_overlaps(&old, std::slice::from_ref(&proposed)).is_ok(),
            expected,
            "reverse {table}"
        );
    }
    let mut old = proposed.clone();
    old.id = "other-range".into();
    let mysql = old.mysql.as_mut().unwrap();
    mysql.tables.clear();
    mysql.table_patterns.clear();
    mysql.table_series.as_mut().unwrap().start = 3;
    mysql.table_series.as_mut().unwrap().end = 6;
    assert!(validate_time_overlaps(&proposed, std::slice::from_ref(&old)).is_ok());
    old.mysql
        .as_mut()
        .unwrap()
        .table_series
        .as_mut()
        .unwrap()
        .start = 2;
    assert!(validate_time_overlaps(&proposed, std::slice::from_ref(&old)).is_err());
}

#[test]
fn table_family_rejects_unobserved_legacy_params_without_misreading_wildcard_verbs() {
    let (_temp, feedback, time) = table_fixture();
    let proposed = time.proposed(&feedback.rule).unwrap();
    for (sql, expected) in [
        ("INSERT INTO items_0002 *", false),
        ("*UPDATE items SET stamp=*", false),
        ("UP*DATE items SET stamp=*", false),
        ("UPDATE items SET stamp=*", true),
        ("SELECT * FROM items_0002", true),
    ] {
        let old:ReplayDependencyRule=serde_json::from_value(json!({"id":"legacy","protocol":"mysql","target":{"host":"db.example.test","port":3306},"mysql":{"database":"app","sql":sql,"params":{"0":{"validate":"non_empty"}}}})).unwrap();
        assert_eq!(
            validate_time_overlaps(&proposed, &[old]).is_ok(),
            expected,
            "{sql}"
        );
    }
}
