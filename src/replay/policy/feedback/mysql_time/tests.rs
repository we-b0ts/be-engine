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
    fs::write(
        &policy_path,
        "# preserve\nversion: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
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
            tables: vec![],
            table_patterns: vec![],
            table_series: None,
            time_values: vec![MysqlTimeValueSelector {
                value_index: 0,
                json_pointer: None,
                tolerance: "5s".into(),
                offset: "0s".into(),
                format: "%Y-%m-%d %H:%M:%S%.f".into(),
                timezone: "+00:00".into(),
            }],
        },
        source_evidence: "security.py:auth assigns datetime.utcnow() before commit".into(),
    };
    (temp, feedback)
}

#[test]
fn select_sql_time_plan_requires_complete_same_case_resultsets() {
    for mutation in [
        "valid",
        "truncated",
        "missing_columns",
        "short_row",
        "missing_rows",
        "client_terminated",
        "stable_filter",
    ] {
        let (temp, mut feedback) = fixture();
        feedback.selector.sql =
            "SELECT count(*) AS total FROM errors WHERE created_at>? AND project_id=?".into();
        feedback.selector.time_values[0].offset = "-24h".into();
        let mut source = json!({
            "event_type":"mysql_exchange", "target_host":"db.internal", "target_port":3306,
            "database":"app", "username":"user", "command":"COM_QUERY",
            "sql":"SELECT count(*) AS total FROM errors WHERE created_at>'2020-01-01 00:00:00' AND project_id=7",
            "parse_warnings":[], "response":{"status":"resultset", "columns":[{"name":"total", "family":"integer","sql_type":"BIGINT"}], "rows":[[{"kind":"integer","value":3}]]}
        });
        match mutation {
            "truncated" => source["response"]["rows_truncated"] = json!(true),
            "missing_columns" => source["response"]["columns"] = json!([]),
            "short_row" => source["response"]["rows"] = json!([[]]),
            "missing_rows" => {
                source["response"].as_object_mut().unwrap().remove("rows");
            }
            "client_terminated" => source["outcome"] = json!("client_terminated"),
            _ => {}
        }
        fs::write(
            temp.path().join("case/dependencies.jsonl"),
            source.to_string(),
        )
        .unwrap();
        let mut report: Value =
            serde_json::from_slice(&fs::read(&feedback.replay_report_path).unwrap()).unwrap();
        report["unmatched_queries"][0]["sql"] = json!(feedback.selector.sql);
        report["unmatched_queries"][0]["params"][0]["value"] = json!("2026-09-06 12:00:01");
        if mutation == "stable_filter" {
            report["unmatched_queries"][0]["params"][1]["value"] = json!(8);
        }
        fs::write(&feedback.replay_report_path, report.to_string()).unwrap();
        let plan = plan_mysql_time_rule(feedback);
        if mutation == "valid" {
            plan.unwrap().apply().unwrap();
        } else {
            assert!(plan.is_err(), "{mutation}");
        }
    }
}

#[test]
fn sql_time_plan_validates_evidence_and_preserves_other_policy_sections() {
    let (_temp, feedback) = fixture();
    let path = feedback.policy_path.clone();
    let original = fs::read_to_string(&path).unwrap();
    let plan = plan_mysql_time_rule(feedback.clone()).unwrap();
    assert!(plan.report().changed);
    assert_eq!(plan.report().source_evidence, feedback.source_evidence);
    assert_eq!(plan.report().evidence_case_id, "case-1");
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    let report = plan.apply().unwrap();
    assert!(report.applied);
    let updated = fs::read_to_string(&path).unwrap();
    assert!(updated.starts_with("# preserve\n"));
    assert!(updated.ends_with(""));
    assert!(updated.contains("sql_values:"));
    assert!(updated.contains("sql_values: {0: {\"time\":\"replay_now\",\"tolerance\":\"5s\"}}"));
    for omitted in [
        "case:",
        "target:",
        "username:",
        "command:",
        "source_evidence:",
        "format:",
        "timezone:",
    ] {
        assert!(!updated.contains(omitted), "{omitted}");
    }
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
fn sql_time_rule_is_reused_across_apis_and_evidence_filters_are_optional() {
    let (temp, mut feedback) = fixture();
    feedback.selector.target_host.clear();
    feedback.selector.username.clear();
    plan_mysql_time_rule(feedback.clone())
        .unwrap()
        .apply()
        .unwrap();
    fs::write(
        temp.path().join("case/request.json"),
        r#"{"method":"POST","uri":"/documents/content"}"#,
    )
    .unwrap();
    feedback.api = "POST /documents/content".into();
    feedback.rule_id = "document-last-use".into();
    let repeated = plan_mysql_time_rule(feedback.clone()).unwrap();
    assert!(repeated.report().reused_existing);
    assert_eq!(repeated.report().effective_rule_id, "last-use");
    assert!(!repeated.report().changed);

    let source_path = temp.path().join("case/dependencies.jsonl");
    let original: Value = serde_json::from_slice(&fs::read(&source_path).unwrap()).unwrap();
    for (field, value) in [
        ("target_host", json!("another-db")),
        ("target_port", json!(3307)),
        ("username", json!("another-user")),
        ("database", json!("another-db")),
    ] {
        let mut source = original.clone();
        source[field] = value;
        fs::write(&source_path, source.to_string()).unwrap();
        assert!(plan_mysql_time_rule(feedback.clone()).is_err(), "{field}");
    }
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
            "invalid_slot" => feedback.selector.time_values[0].value_index = 2,
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

#[test]
fn sql_time_plan_correlates_scalar_and_nested_json_locations_atomically() {
    let (temp, mut feedback) = fixture();
    let source = json!({
        "event_type":"mysql_exchange",
        "target_host":"db.internal",
        "target_port":3306,
        "database":"app",
        "username":"user",
        "command":"COM_QUERY",
        "sql":r#"UPDATE kinds SET json='{"name":"stable","spec":{"observedAt":"2020-01-01T00:00:00+00:00"}}', updated_at='2020-01-01 00:00:00.000000' WHERE id=7"#,
        "parse_warnings":[],
        "response":{"status":"ok","affected_rows":1}
    });
    fs::write(
        temp.path().join("case/dependencies.jsonl"),
        source.to_string(),
    )
    .unwrap();
    let report = json!({
        "finalized":true,
        "started_at":"2026-09-07T12:00:00Z",
        "finalized_at":"2026-09-07T12:00:02Z",
        "cases":[{"case_id":"case-1","case_dir":temp.path().join("case")}],
        "unmatched_queries":[{
            "case_id":"case-1",
            "command":"COM_STMT_EXECUTE",
            "target":{"host":"db.internal","port":3306},
            "database":"app",
            "username":"user",
            "sql":"UPDATE kinds SET json=?, updated_at=? WHERE id=?",
            "params":[
                {"kind":"string","value":r#"{"spec":{"observedAt":"2026-09-07T12:00:01+00:00"},"name":"stable"}"#},
                {"kind":"datetime","value":"2026-09-07 12:00:01.000000"},
                {"kind":"integer","value":7}
            ]
        }]
    });
    fs::write(&feedback.replay_report_path, report.to_string()).unwrap();
    feedback.rule_id = "kind-times".into();
    feedback.selector.sql = "UPDATE kinds SET json=?, updated_at=? WHERE id=?".into();
    feedback.selector.time_values = vec![
        MysqlTimeValueSelector {
            value_index: 0,
            json_pointer: Some("/spec/observedAt".into()),
            tolerance: "5s".into(),
            offset: "0s".into(),
            format: "%+".into(),
            timezone: "+00:00".into(),
        },
        MysqlTimeValueSelector {
            value_index: 1,
            json_pointer: None,
            tolerance: "5s".into(),
            offset: "0s".into(),
            format: "%Y-%m-%d %H:%M:%S%.f".into(),
            timezone: "+00:00".into(),
        },
    ];
    feedback.source_evidence =
        "kind.py:updated_at and service.py:observedAt use current time".into();

    let path = feedback.policy_path.clone();
    plan_mysql_time_rule(feedback.clone())
        .unwrap()
        .apply()
        .unwrap();
    let updated = fs::read_to_string(path).unwrap();
    assert!(updated.contains("/spec/observedAt"));
    assert!(updated.contains("1: {\"time\":\"replay_now\",\"tolerance\":\"5s\"}"));

    let mut changed: Value =
        serde_json::from_slice(&fs::read(&feedback.replay_report_path).unwrap()).unwrap();
    changed["unmatched_queries"][0]["params"][0]["value"] =
        json!(r#"{"spec":{"observedAt":"2026-09-07T12:00:01+00:00"},"name":"changed"}"#);
    fs::write(&feedback.replay_report_path, changed.to_string()).unwrap();
    assert!(plan_mysql_time_rule(feedback).is_err());
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

#[test]
fn table_time_plan_requires_the_same_physical_table_and_persists_template_bounds() {
    for wrong_table in [false, true] {
        let (temp, mut feedback) = fixture();
        feedback.selector.sql = "UPDATE {{table}} SET last_used_at=? WHERE id=?".into();
        feedback.selector.table_patterns = vec!["subtasks_*".into()];
        feedback.source_evidence = "sharding.py:subtask writes route to subtasks_{shard:04d}; updated_at uses datetime.now()".into();
        let path = temp.path().join("case/dependencies.jsonl");
        let original = fs::read_to_string(&path).unwrap();
        fs::write(&path, original.replace("api_keys", "subtasks_0155")).unwrap();
        let report = fs::read_to_string(&feedback.replay_report_path).unwrap();
        fs::write(
            &feedback.replay_report_path,
            report.replace(
                "api_keys",
                if wrong_table {
                    "subtasks_0640"
                } else {
                    "subtasks_0155"
                },
            ),
        )
        .unwrap();
        let plan = plan_mysql_time_rule(feedback.clone());
        if wrong_table {
            assert!(plan.is_err());
            continue;
        }
        let report = plan.unwrap().apply().unwrap();
        let restored: MysqlTimeSelector =
            serde_json::from_value(serde_json::to_value(&report.selector).unwrap()).unwrap();
        assert_eq!(restored, feedback.selector);
        let configured = load_replay_policy(&feedback.policy_path).unwrap();
        let selector = configured.document.dependency_rules[0]
            .mysql
            .as_ref()
            .unwrap();
        assert_eq!(selector.sql, feedback.selector.sql);
        assert_eq!(selector.table_patterns, ["subtasks_*"]);
        assert!(
            plan_mysql_time_rule(feedback)
                .unwrap()
                .report()
                .reused_existing
        );
    }
}
