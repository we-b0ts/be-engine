//! Repeat the PREPARE policy checks performed while scanning recorded candidates.
use super::*;
use std::{hint::black_box, time::Instant};

#[test]
#[ignore = "manual release-mode policy matching benchmark"]
fn mysql_policy_matching_benchmark() {
    let mut policy =
        String::from("version: 3\nexpected_response: assertions_only\ndependency_rules:\n");
    for index in 0..5 {
        policy.push_str(&format!(
            "- id: shard-time-{index}\n  protocol: mysql\n  mysql:\n    database: pluto_audit\n    sql: UPDATE {{{{table}}}} SET stamp_{index}=? WHERE {{{{table}}}}.id=?\n    table_series: {{prefix: subtasks_, start: 0, end: 1023, width: 4}}\n    sql_values: {{0: {{time: preserve_relative}}}}\n"
        ));
    }
    let fixture = policy_fixture(&policy);
    let runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    anchor_sql_times(
        &runtime,
        Utc.with_ymd_and_hms(2026, 9, 7, 12, 0, 0).unwrap(),
    );
    let identity = mysql_identity();
    let candidates: Vec<_> = (0..32)
        .map(|id| format!("SELECT id, stamp FROM subtasks_0155 WHERE id={id}"))
        .collect();
    let started = Instant::now();
    let mut matches = 0;
    for _ in 0..100 {
        for recorded in &candidates {
            let context = MysqlPolicyContext {
                request_times: runtime.request_contracts.request_times(CASE_ID),
                case_id: Some(CASE_ID),
                identity: &identity,
                command: "COM_STMT_EXECUTE",
                recorded_sql: Some(recorded),
                sql: Some("SELECT id, stamp FROM subtasks_0155 WHERE id=?"),
                recorded: None,
                actual: None,
            };
            matches += usize::from(black_box(
                runtime.mysql_sql_values_metadata_matches(black_box(&context)),
            ));
        }
    }
    assert_eq!(matches, 0);
    eprintln!(
        "mysql_policy_matching_benchmark: 3200 candidate checks in {:?}",
        started.elapsed()
    );
}
