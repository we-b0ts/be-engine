use super::*;
use crate::policy::runtime::feedback::tests::RetiredFixture;
use serde_json::json;
#[test]
fn retired_sql_time_plan_and_pending_apply_cannot_change_policy_or_source() {
    let fixture = RetiredFixture::new();
    let selector:MysqlTimeSelector=serde_json::from_value(json!({"target_host":"db.test","target_port":3306,"database":"app","username":"writer","sql":"UPDATE items SET created=? WHERE id=?","value_index":0})).unwrap();
    fixture.check(|| {
        plan_mysql_time_rule(MysqlTimeRuleFeedback {
            policy_path: fixture.policy.clone(),
            replay_report_path: fixture.evidence.clone(),
            api: "POST /items".into(),
            rule_id: "old-time".into(),
            selector: selector.clone(),
            source_evidence: "src/items.rs records current UTC".into(),
        })
    });
    let plan = MysqlTimeRulePlan {
        report: MysqlTimeRuleReport {
            policy: fixture.policy.clone(),
            policy_fingerprint: "old-plan".into(),
            requested_rule_id: "old-time".into(),
            effective_rule_id: "old-time".into(),
            selector,
            source_evidence: "src/items.rs records current UTC".into(),
            evidence_case_id: "old-case".into(),
            reused_existing: false,
            changed: true,
            applied: false,
            diff: String::new(),
        },
    };
    fixture.check(|| plan.apply());
}

#[test]
fn mysql_time_selector_reads_legacy_single_slot_state() {
    let selector: MysqlTimeSelector = serde_json::from_value(json!({
        "target_host":"db.internal",
        "target_port":3306,
        "database":"app",
        "username":"user",
        "sql":"UPDATE keys SET stamp=? WHERE id=?",
        "value_index":0,
        "tolerance":"5s",
        "offset":"0s",
        "format":"%Y-%m-%d %H:%M:%S%.f",
        "timezone":"+00:00"
    }))
    .unwrap();
    assert_eq!(selector.time_values.len(), 1);
    assert_eq!(selector.time_values[0].value_index, 0);
    assert!(selector.time_values[0].json_pointer.is_none());
    assert!(
        selector.tables.is_empty()
            && selector.table_patterns.is_empty()
            && selector.table_series.is_none()
    );
    let encoded = serde_json::to_value(selector).unwrap();
    assert_eq!(encoded["value_index"], 0);
    assert!(encoded.get("time_values").is_none());
}
