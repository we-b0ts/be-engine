use super::*;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, DependencyRequestRuleFeedback) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let case = root.join("case");
    fs::create_dir(&case).unwrap();
    fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/lease","timestamp":"2020-01-01T00:00:00Z"}).to_string(),
    )
    .unwrap();
    let sql = "SELECT expires_at FROM leases WHERE id=? FOR UPDATE";
    fs::write(case.join("dependencies.jsonl"),json!({"event_type":"mysql_exchange","target_host":"db.test","target_port":3306,"database":"app","command":"COM_QUERY","sql":sql,"parse_warnings":[],
        "response":{"status":"resultset","columns":[{"name":"expires_at","family":"datetime","sql_type":"DATETIME"}],"rows":[[{"kind":"datetime","value":"2020-01-01 00:05:00"}]]}}).to_string()).unwrap();
    let report = root.join("replay-report.json");
    fs::write(&report,json!({"finalized":true,"complete":true,"replay_policy":{"fingerprint":load_replay_policy(&policy).unwrap().fingerprint},
        "cases":[{"case_id":"case","case_dir":case,"target_request_started_at":"2026-10-12T00:00:00Z"}],
        "matched_queries":[{"case_id":"case","source":"case","target":{"host":"db.test","port":3306},"database":"app","sql":sql}]}).to_string()).unwrap();
    let feedback = DependencyRequestRuleFeedback {
        policy_path: policy,
        replay_report: report,
        rule: json!({"id":"lease-expiry","protocol":"mysql","case":{"method":"POST","path":"/lease"},"target":{"host":"db.test","port":3306},"source_evidence":"lease.py:acquire stores UTC now plus the lease duration",
        "mysql":{"database":"app","sql":sql,"response_time_shift":{"expires_at":{"time":"preserve_relative","format":"mysql_datetime"}}}}),
    };
    (temp, feedback)
}

#[test]
fn mysql_response_shift_plan_requires_current_complete_matched_evidence_and_rechecks_source() {
    let (_temp, feedback) = fixture();
    let plan = super::super::plan_dependency_request_rule(feedback).unwrap();
    assert!(plan.report().requires_fresh_replay);
    assert_eq!(plan.report().matching_cases, 1);
    let source = plan
        .witnesses
        .iter()
        .find(|(path, _)| path.file_name().unwrap() == "dependencies.jsonl")
        .unwrap()
        .0
        .clone();
    fs::write(source, "{}\n").unwrap();
    assert!(plan.apply().is_err());
    let (_temp, feedback) = fixture();
    let policy = feedback.policy_path.clone();
    super::super::plan_dependency_request_rule(feedback)
        .unwrap()
        .apply()
        .unwrap();
    crate::replay::validate_replay_policy(&policy).unwrap();
    let (_temp, feedback) = fixture();
    let mut report: Value =
        serde_json::from_slice(&fs::read(&feedback.replay_report).unwrap()).unwrap();
    report["matched_queries"] = json!([]);
    fs::write(&feedback.replay_report, report.to_string()).unwrap();
    assert!(super::super::plan_dependency_request_rule(feedback).is_err());
}
