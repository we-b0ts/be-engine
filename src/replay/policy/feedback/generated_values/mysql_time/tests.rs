use super::*;
use crate::replay::policy::feedback::tests::RetiredFixture;
use serde_json::json;
mod table_tests;
const SQL: &str = "INSERT INTO items (name, created_at, updated_at, owner_id) VALUES (?, ?, ?, ?)";
fn fixture() -> (
    RetiredFixture,
    DynamicValueRuleFeedback,
    DynamicValueMysqlTimeRule,
) {
    let fixture = RetiredFixture::new();
    let mut feedback = fixture.identity();
    let mut value = serde_json::to_value(&feedback.rule).unwrap();
    value["capture"]["sql"] = json!(SQL);
    value["capture"]["target"] = json!({"host":"db.example.test","port":3306});
    value["targets"] = json!([{"host":"db.example.test","port":3306}]);
    feedback.rule = serde_json::from_value(value).unwrap();
    let time=serde_json::from_value(json!({"id":"item-times","time_values":[{"value_index":1},{"value_index":2}],"source_evidence":"src/items.rs initializes both current UTC times"})).unwrap();
    (fixture, feedback, time)
}
#[test]
fn retired_joint_mysql_plan_cannot_write_either_half_of_a_contract() {
    let (fixture, feedback, time) = fixture();
    fixture.check(|| plan_dynamic_value_mysql_time_rule(feedback, time));
}

#[test]
fn time_admission_rejects_runtime_token_overlap_without_confusing_prefix_templates() {
    let (_temp, feedback, time) = fixture();
    let make = |id: &str, sql: &str, slot: usize| {
        let mut rule = time.proposed(&feedback.rule).unwrap();
        rule.id = id.into();
        let mysql = rule.mysql.as_mut().unwrap();
        mysql.sql = sql.into();
        let field = mysql.sql_values.values().next().unwrap().clone();
        mysql.sql_values = std::collections::BTreeMap::from([(slot, field)]);
        rule
    };
    let short = make("existing", "UPDATE items SET stamp=?", 0);
    let long = make("proposed", "UPDATE items SET stamp=? WHERE id=?", 0);
    assert!(validate_time_overlaps(&long, std::slice::from_ref(&short)).is_ok());
    assert!(validate_time_overlaps(&short, std::slice::from_ref(&long)).is_ok());
    let same = make("existing", "UPDATE items SET stamp=? WHERE id=?", 0);
    assert!(validate_time_overlaps(&long, std::slice::from_ref(&same)).is_err());
    let disjoint = make("existing", "UPDATE items SET stamp=? WHERE id=?", 1);
    assert!(validate_time_overlaps(&long, &[disjoint]).is_ok());
    let mut other_endpoint = same;
    other_endpoint.target.host = Some("unrelated.example.test".into());
    assert!(validate_time_overlaps(&long, &[other_endpoint]).is_ok());
}
