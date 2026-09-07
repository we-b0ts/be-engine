use super::*;
use serde_json::{Value, json};

fn fixture() -> (tempfile::TempDir, MysqlTimeRuleFeedback) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    fs::create_dir(&case).unwrap();
    fs::write(
        case.join("request.json"),
        r#"{"method":"GET","uri":"/responses/7"}"#,
    )
    .unwrap();
    let source = json!({"event_type":"mysql_exchange","target_host":"db.internal","target_port":3306,"database":"app","username":"user","command":"COM_QUERY","sql":"UPDATE api_keys SET last_used_at='2020-01-01 00:00:00.123456' WHERE id=7","parse_warnings":[],"response":{"status":"ok","affected_rows":1}});
    fs::write(case.join("dependencies.jsonl"), source.to_string()).unwrap();
    let report = json!({"finalized":true,"started_at":"2026-09-07T12:00:00Z","finalized_at":"2026-09-07T12:00:02Z","cases":[{"case_id":"case-1","case_dir":case}],"unmatched_queries":[{"case_id":"case-1","command":"COM_STMT_EXECUTE","target":{"host":"db.internal","port":3306},"database":"app","username":"user","sql":"UPDATE api_keys SET last_used_at=? WHERE id=?","params":[{"kind":"datetime","value":"2026-09-07 12:00:01.123456"},{"kind":"integer","value":7}]}]});
    let replay_report_path = temp.path().join("replay-report.json");
    fs::write(&replay_report_path, report.to_string()).unwrap();
    let policy_path = temp.path().join("verification.yaml");
    fs::write(&policy_path,"# preserve\nversion: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_settings:\n  comparison:\n    source_match: before_or_after\n").unwrap();
    let feedback = MysqlTimeRuleFeedback {
        policy_path,
        replay_report_path,
        api: "GET /responses/*".into(),
        rule_id: "last-use".into(),
        selector: MysqlTimeSelector {
            target_host: "db.internal".into(),
            target_port: 3306,
            database: "app".into(),
            username: "user".into(),
            sql: "UPDATE api_keys SET last_used_at=? WHERE id=?".into(),
            value_index: 0,
            tolerance: "5s".into(),
            offset: "0s".into(),
            format: "%Y-%m-%d %H:%M:%S%.f".into(),
            timezone: "+00:00".into(),
        },
        source_evidence: "security.py:auth assigns datetime.utcnow() before commit".into(),
    };
    (temp, feedback)
}

#[test]
fn sql_time_plan_validates_evidence_and_preserves_other_policy_sections() {
    let (_temp, feedback) = fixture();
    let path = feedback.policy_path.clone();
    let original = fs::read_to_string(&path).unwrap();
    let plan = plan_mysql_time_rule(feedback.clone()).unwrap();
    assert!(plan.report().changed);
    assert_eq!(plan.report().evidence_case_id, "case-1");
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    let report = plan.apply().unwrap();
    assert!(report.applied);
    let updated = fs::read_to_string(&path).unwrap();
    assert!(updated.starts_with("# preserve\n"));
    assert!(
        updated.ends_with("response_settings:\n  comparison:\n    source_match: before_or_after\n")
    );
    assert!(updated.contains("sql_values:"));
    let repeated = plan_mysql_time_rule(feedback).unwrap();
    assert!(repeated.report().reused_existing);
    assert!(!repeated.report().changed);
    let loaded = load_replay_policy(&path).unwrap();
    assert!(
        loaded.document.dependency_rules[0]
            .mysql
            .as_ref()
            .unwrap()
            .params
            .is_empty()
    );
}

#[test]
fn sql_time_plan_rejects_stale_policy_and_unsupported_evidence() {
    let (_temp, feedback) = fixture();
    let path = feedback.policy_path.clone();
    let plan = plan_mysql_time_rule(feedback).unwrap();
    fs::write(path, "changed").unwrap();
    assert!(plan.apply().is_err());
    for mutation in [
        "unfinished",
        "wrong_id",
        "stale_time",
        "wrong_api",
        "invalid_slot",
        "missing_proof",
        "invalid_source",
        "warnings",
    ] {
        let (temp, mut feedback) = fixture();
        let mut report: Value =
            serde_json::from_slice(&fs::read(&feedback.replay_report_path).unwrap()).unwrap();
        match mutation {
            "unfinished" => report["finalized"] = json!(false),
            "wrong_id" => report["unmatched_queries"][0]["params"][1]["value"] = json!(8),
            "stale_time" => {
                report["unmatched_queries"][0]["params"][0]["value"] = json!("2026-09-07 11:00:00")
            }
            "wrong_api" => feedback.api = "GET /other/*".into(),
            "invalid_slot" => feedback.selector.value_index = 2,
            "missing_proof" => feedback.source_evidence.clear(),
            "invalid_source" | "warnings" => {
                let p = temp.path().join("case/dependencies.jsonl");
                let mut source: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
                if mutation == "warnings" {
                    source["parse_warnings"] = json!(["incomplete capture"]);
                } else {
                    source["sql"] = json!("UPDATE api_keys SET last_used_at='bad' WHERE id=7");
                }
                fs::write(p, source.to_string()).unwrap();
            }
            _ => unreachable!(),
        }
        fs::write(&feedback.replay_report_path, report.to_string()).unwrap();
        assert!(plan_mysql_time_rule(feedback).is_err(), "{mutation}");
    }
}
