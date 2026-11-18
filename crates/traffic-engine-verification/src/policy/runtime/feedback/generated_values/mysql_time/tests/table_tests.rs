use super::*;
fn table_fixture() -> (
    RetiredFixture,
    DynamicValueRuleFeedback,
    DynamicValueMysqlTimeRule,
) {
    let (fixture, mut feedback, time) = fixture();
    let mut value = serde_json::to_value(&feedback.rule).unwrap();
    value["capture"]["sql"] = json!(SQL.replace("items", "{{table}}"));
    value["capture"]["tables"] = json!(["items_0009"]);
    value["capture"]["table_patterns"] = json!(["archived_items_*"]);
    value["capture"]["table_series"] = json!({"prefix":"items_","start":0,"end":2,"width":4});
    feedback.rule = serde_json::from_value(value).unwrap();
    (fixture, feedback, time)
}
#[test]
fn table_companion_keeps_all_declared_physical_table_bounds() {
    let (_fixture, feedback, time) = table_fixture();
    let proposed = time.proposed(&feedback.rule).unwrap();
    let mysql = proposed.mysql.as_ref().unwrap();
    assert_eq!(mysql.tables, ["items_0009"]);
    assert_eq!(mysql.table_patterns, ["archived_items_*"]);
    assert_eq!(mysql.table_series.as_ref().unwrap().end, 2);
    assert_eq!(mysql.sql, SQL.replace("items", "{{table}}"));
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
