use super::*;
use serde_json::json;

const SQL: &str = "INSERT INTO items (name, created_at, updated_at, owner_id) VALUES (?, ?, ?, ?)";
const SOURCE_NAME: &str = "task-pending-123e4567e89b42d3a456426614174000";
const TARGET_NAME: &str = "task-pending-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa";

fn write(path: &std::path::Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn fixture() -> (
    tempfile::TempDir,
    DynamicValueRuleFeedback,
    DynamicValueMysqlTimeRule,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let case = root.join("case");
    fs::create_dir(&case).unwrap();
    let policy_path = root.join("verification.yaml");
    fs::write(&policy_path, "# preserved\nversion: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_rules: {}\n").unwrap();
    write(
        &case.join("request.json"),
        &json!({"method":"POST","uri":"/items","timestamp":"2020-01-01T00:00:00Z"}),
    );
    let source = json!({"event_type":"mysql_exchange","target_host":"db.example.test","target_port":3306,"database":"app","username":"user","command":"COM_QUERY",
        "sql":format!("INSERT INTO items (name, created_at, updated_at, owner_id) VALUES ('{SOURCE_NAME}', '2020-01-01 00:00:00.100000', '2020-01-01 00:00:00.200000', 7)"),
        "parse_warnings":[],"response":{"status":"ok","affected_rows":1,"last_insert_id":9}});
    write(&case.join("dependencies.jsonl"), &source);
    let replay_report = root.join("replay.json");
    write(
        &replay_report,
        &json!({"finalized":true,"complete":false,
        "started_at":"2026-09-07T12:00:00Z","finalized_at":"2026-09-07T12:00:02Z",
        "replay_policy":{"fingerprint":load_replay_policy(&policy_path).unwrap().fingerprint},
        "cases":[{"case_id":"case","case_dir":case,"target_request_started_at":"2026-09-07T12:00:00Z"}],
        "unmatched_queries":[{"case_id":"case","command":"COM_STMT_EXECUTE","target":{"host":"db.example.test","port":3306},"database":"app","username":"user","sql":SQL,
            "params":[{"kind":"string","value":TARGET_NAME},{"kind":"datetime","value":"2026-09-07 12:00:01.100000"},{"kind":"datetime","value":"2026-09-07 12:00:01.200000"},{"kind":"integer","value":7}]}]}),
    );
    let rule = serde_json::from_value(json!({"id":"generated-name","api":"/items","targets":[{"host":"db.example.test","port":3306}],
        "capture":{"protocol":"mysql","target":{"host":"db.example.test","port":3306},"database":"app","sql":SQL,"value_index":0},
        "source_evidence":"NameFactory:create generates task-pending-{uuid.uuid4().hex} for each new item"})).unwrap();
    let time = serde_json::from_value(json!({"id":"item-times","time_values":[{"value_index":1},{"value_index":2}],"source_evidence":"ItemModel:created_at and updated_at both default to datetime.now()"})).unwrap();
    (
        temp,
        DynamicValueRuleFeedback {
            policy_path,
            rule,
            replay_report,
        },
        time,
    )
}

fn report(feedback: &DynamicValueRuleFeedback) -> Value {
    serde_json::from_slice(&fs::read(&feedback.replay_report).unwrap()).unwrap()
}

#[test]
fn combined_plan_bootstraps_two_strict_contracts_atomically() {
    let (temp, feedback, time) = fixture();
    let original = fs::read(&feedback.policy_path).unwrap();
    let source = fs::read(temp.path().join("case/dependencies.jsonl")).unwrap();
    assert!(
        plan_dynamic_value_rule(DynamicValueRuleFeedback {
            policy_path: feedback.policy_path.clone(),
            rule: feedback.rule.clone(),
            replay_report: feedback.replay_report.clone()
        })
        .is_err()
    );
    let proposed = time.proposed(&feedback.rule).unwrap();
    let plan = plan_dynamic_value_mysql_time_rule(feedback, time).unwrap();
    assert_eq!(plan.report().kind, "dynamic_value_mysql_time");
    assert_eq!(
        plan.report().added_rule_ids,
        ["generated-name", "item-times"]
    );
    assert!(plan.report().requires_fresh_replay);
    let path = plan.policy_path.clone();
    assert_eq!(
        fs::read(&path).unwrap(),
        original,
        "planning cannot apply half a contract"
    );
    plan.apply().unwrap();
    let loaded = load_replay_policy(&path).unwrap();
    assert_eq!(loaded.document.dynamic_values.len(), 1);
    assert_eq!(loaded.document.dependency_rules.len(), 1);
    assert_eq!(
        serde_json::to_value(&loaded.document.dependency_rules[0]).unwrap(),
        serde_json::to_value(proposed).unwrap()
    );
    let rule = &loaded.document.dependency_rules[0];
    assert_eq!(rule.target.host.as_deref(), Some("db.example.test"));
    assert_eq!(rule.target.port, Some(3306));
    assert_eq!(
        rule.mysql.as_ref().unwrap().database.as_deref(),
        Some("app")
    );
    assert_eq!(rule.mysql.as_ref().unwrap().sql_values.len(), 2);
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .starts_with("# preserved\n")
    );
    assert_eq!(
        fs::read(temp.path().join("case/dependencies.jsonl")).unwrap(),
        source
    );
}

#[test]
fn combined_plan_rejects_unselected_changes_missing_clocks_and_stale_evidence() {
    for mutation in [
        "owner",
        "sql",
        "host",
        "database",
        "username",
        "case",
        "source_time",
        "target_time",
        "time_window",
        "time_type",
        "source_response",
        "warnings",
        "policy",
        "unfinalized",
    ] {
        let (temp, feedback, time) = fixture();
        let original = fs::read(&feedback.policy_path).unwrap();
        let mut report = report(&feedback);
        let source_path = temp.path().join("case/dependencies.jsonl");
        let mut source: Value = serde_json::from_slice(&fs::read(&source_path).unwrap()).unwrap();
        match mutation {
            "owner" => report["unmatched_queries"][0]["params"][3]["value"] = json!(8),
            "sql" => {
                report["unmatched_queries"][0]["sql"] = json!(SQL.replace("items", "other_items"))
            }
            "host" => {
                report["unmatched_queries"][0]["target"]["host"] = json!("other.example.test")
            }
            "database" => report["unmatched_queries"][0]["database"] = json!("other"),
            "username" => report["unmatched_queries"][0]["username"] = json!("other"),
            "case" => report["unmatched_queries"][0]["case_id"] = json!("other"),
            "source_time" => write(
                &temp.path().join("case/request.json"),
                &json!({"method":"POST","uri":"/items"}),
            ),
            "target_time" => {
                report["cases"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("target_request_started_at");
            }
            "time_window" => {
                report["unmatched_queries"][0]["params"][1]["value"] = json!("2026-09-07 12:01:00")
            }
            "time_type" => {
                report["unmatched_queries"][0]["params"][1] =
                    json!({"kind":"integer","value":1788782401_i64})
            }
            "source_response" => source["response"] = json!({"status":"unsupported"}),
            "warnings" => source["parse_warnings"] = json!(["incomplete"]),
            "policy" => report["replay_policy"]["fingerprint"] = json!("stale"),
            "unfinalized" => report["finalized"] = json!(false),
            _ => unreachable!(),
        }
        write(&source_path, &source);
        write(&feedback.replay_report, &report);
        assert!(
            plan_dynamic_value_mysql_time_rule(feedback, time).is_err(),
            "{mutation}"
        );
        assert_eq!(
            fs::read(temp.path().join("verification.yaml")).unwrap(),
            original,
            "{mutation}"
        );
    }
}

#[test]
fn combined_plan_protects_both_contracts_until_apply() {
    for mutation in ["policy", "source", "report", "request"] {
        let (temp, feedback, time) = fixture();
        let path = feedback.policy_path.clone();
        let plan = plan_dynamic_value_mysql_time_rule(feedback, time).unwrap();
        let changed = match mutation {
            "policy" => path.clone(),
            "source" => temp.path().join("case/dependencies.jsonl"),
            "report" => temp.path().join("replay.json"),
            "request" => temp.path().join("case/request.json"),
            _ => unreachable!(),
        };
        let mut bytes = fs::read(&changed).unwrap();
        bytes.push(b' ');
        fs::write(changed, bytes).unwrap();
        let before_apply = fs::read(&path).unwrap();
        assert!(plan.apply().is_err(), "{mutation}");
        assert_eq!(
            fs::read(path).unwrap(),
            before_apply,
            "{mutation}: partial policy applied"
        );
    }
}

#[test]
fn combined_plan_rejects_overlaps_bad_format_and_missing_source_proof() {
    for mutation in [
        "overlap",
        "bad_uuid",
        "time_proof",
        "identity_proof",
        "duplicate_id",
        "invalid_slot",
        "empty_times",
        "non_mysql",
    ] {
        let (_temp, mut feedback, mut time) = fixture();
        match mutation {
            "overlap" => time.time_values[0].value_index = 0,
            "bad_uuid" => feedback.rule.format = Some(crate::DynamicValueFormat::UuidV4),
            "time_proof" => time.source_evidence.clear(), "identity_proof" => feedback.rule.source_evidence.clear(),
            "duplicate_id" => time.id = feedback.rule.id.clone(), "invalid_slot" => time.time_values[0].value_index = 99,
            "empty_times" => time.time_values.clear(),
            "non_mysql" => feedback.rule.capture = serde_json::from_value(json!({"protocol":"redis","target":{"host":"db.example.test","port":3306},"database":0,"command":"SET","key":"key","argument_index":1})).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            plan_dynamic_value_mysql_time_rule(feedback, time).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn combined_plan_handles_nonoverlapping_identity_and_time_in_one_json_slot() {
    for mutation in [
        "valid",
        "stable_member",
        "same_pointer",
        "ancestor",
        "scalar",
    ] {
        let (temp, mut feedback, mut time) = fixture();
        let sql = "INSERT INTO items (payload, owner_id) VALUES (?, ?)";
        if let DynamicValueCapture::Mysql {
            sql: template,
            value_index,
            json_pointer,
            ..
        } = &mut feedback.rule.capture
        {
            *template = sql.into();
            *value_index = 0;
            *json_pointer = Some("/identity/id".into());
        }
        time.time_values = vec![
            serde_json::from_value(
                json!({"value_index":0,"json_pointer":"/created_at","format":"%+"}),
            )
            .unwrap(),
        ];
        let source_payload =
            json!({"identity":{"id":SOURCE_NAME},"created_at":"2020-01-01T00:00:00Z","stable":1});
        let target_payload = json!({"identity":{"id":TARGET_NAME},"created_at":"2026-09-07T12:00:01Z","stable":if mutation=="stable_member"{2}else{1}});
        let source = json!({"event_type":"mysql_exchange","target_host":"db.example.test","target_port":3306,"database":"app","username":"user","command":"COM_STMT_EXECUTE","sql":sql,
            "params":[{"kind":"string","value":source_payload.to_string()},{"kind":"integer","value":7}],"parse_warnings":[],"response":{"status":"ok","affected_rows":1}});
        write(&temp.path().join("case/dependencies.jsonl"), &source);
        let mut report = report(&feedback);
        report["unmatched_queries"][0]["sql"] = json!(sql);
        report["unmatched_queries"][0]["params"] = json!([{"kind":"string","value":target_payload.to_string()},{"kind":"integer","value":7}]);
        write(&feedback.replay_report, &report);
        match mutation {
            "same_pointer" => time.time_values[0].json_pointer = Some("/identity/id".into()),
            "ancestor" => time.time_values[0].json_pointer = Some("/identity".into()),
            "scalar" => time.time_values[0].json_pointer = None,
            _ => {}
        }
        let result = plan_dynamic_value_mysql_time_rule(feedback, time);
        assert_eq!(result.is_ok(), mutation == "valid", "{mutation}");
        if let Ok(plan) = result {
            plan.apply().unwrap();
        }
    }
}

#[test]
fn new_identity_cannot_hide_a_changed_unselected_string_slot() {
    let (temp, mut feedback, time) = fixture();
    let sql = "INSERT INTO items (name, created_at, updated_at, status) VALUES (?, ?, ?, ?)";
    if let DynamicValueCapture::Mysql { sql: template, .. } = &mut feedback.rule.capture {
        *template = sql.into();
    }
    let source = json!({"event_type":"mysql_exchange","target_host":"db.example.test","target_port":3306,"database":"app","username":"user","command":"COM_QUERY",
        "sql":"INSERT INTO items (name, created_at, updated_at, status) VALUES ('a', '2020-01-01 00:00:00.100000', '2020-01-01 00:00:00.200000', 'cat')", "parse_warnings":[], "response":{"status":"ok","affected_rows":1}});
    write(&temp.path().join("case/dependencies.jsonl"), &source);
    let mut report = report(&feedback);
    report["unmatched_queries"][0]["sql"] = json!(sql);
    report["unmatched_queries"][0]["params"][0]["value"] = json!("b");
    report["unmatched_queries"][0]["params"][3] = json!({"kind":"string","value":"cbt"});
    write(&feedback.replay_report, &report);
    assert!(plan_dynamic_value_mysql_time_rule(feedback, time).is_err());
}

#[test]
fn committed_identity_bindings_cannot_be_rebound_or_collapsed_by_joint_planning() {
    for mode in ["consistent", "rebind", "collapse"] {
        let (temp, feedback, time) = fixture();
        let mut loaded = load_replay_policy(&feedback.policy_path).unwrap();
        loaded.document.dynamic_values.push(feedback.rule.clone());
        let original = fs::read_to_string(&feedback.policy_path).unwrap();
        fs::write(
            &feedback.policy_path,
            replace_dependency_rules(&original, &loaded.document).unwrap(),
        )
        .unwrap();
        let source_path = temp.path().join("case/dependencies.jsonl");
        let source: Value = serde_json::from_slice(&fs::read(&source_path).unwrap()).unwrap();
        let mut prior = source.clone();
        prior["sql"] = json!(source["sql"].as_str().unwrap().replace(", 7)", ", 8)"));
        let mut current = source;
        if mode == "collapse" {
            current["sql"] = json!(
                current["sql"]
                    .as_str()
                    .unwrap()
                    .replace(SOURCE_NAME, "task-pending-bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb")
            );
        }
        fs::write(&source_path, format!("{prior}\n{current}\n")).unwrap();
        let mut report = report(&feedback);
        report["replay_policy"]["fingerprint"] = json!(
            load_replay_policy(&feedback.policy_path)
                .unwrap()
                .fingerprint
        );
        report["replay_policy"]["dynamic_bindings"] = json!([{
            "case_id":"case","rule_id":feedback.rule.id,
            "source_fingerprint":fingerprint(SOURCE_NAME.as_bytes()),
            "target_fingerprint":fingerprint(TARGET_NAME.as_bytes()),
        }]);
        let mut matched = report["unmatched_queries"][0].clone();
        matched["params"][1]["value"] = json!("2020-01-01 00:00:00.100000");
        matched["params"][2]["value"] = json!("2020-01-01 00:00:00.200000");
        matched["params"][3]["value"] = json!(8);
        report["matched_queries"] = json!([matched]);
        if mode == "rebind" {
            report["unmatched_queries"][0]["params"][0]["value"] =
                json!("task-pending-cccccccccccc4ccc8ccccccccccccccc");
        }
        write(&feedback.replay_report, &report);
        let result = plan_dynamic_value_mysql_time_rule(feedback, time);
        assert_eq!(result.is_ok(), mode == "consistent", "{mode}");
    }
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

#[test]
fn legacy_parameter_patterns_use_the_real_normalized_witness_and_case_scope() {
    for mode in [
        "overlap",
        "unrelated_sql",
        "unrelated_case",
        "unrelated_endpoint",
    ] {
        let (_temp, feedback, time) = fixture();
        let mut loaded = load_replay_policy(&feedback.policy_path).unwrap();
        let pattern = if mode == "unrelated_sql" {
            "UPDATE unrelated SET value=*".into()
        } else {
            format!(
                "INSERT INTO items (name, created_at, updated_at, owner_id) VALUES ('{SOURCE_NAME}', *, *, *)"
            )
        };
        let mut old: ReplayDependencyRule = serde_json::from_value(json!({
            "id":"old-params","protocol":"mysql","mysql":{"database":"app","command":"COM_QUERY","sql":pattern,"params":{"0":{"validate":"non_empty"}}}
        })).unwrap();
        if mode == "unrelated_case" {
            old.case_selector =
                Some(serde_json::from_value(json!({"method":"POST","path":"/other"})).unwrap());
        }
        if mode == "unrelated_endpoint" {
            old.target.host = Some("other.example.test".into());
        }
        loaded.document.dependency_rules.push(old);
        let original = fs::read_to_string(&feedback.policy_path).unwrap();
        fs::write(
            &feedback.policy_path,
            replace_dependency_rules(&original, &loaded.document).unwrap(),
        )
        .unwrap();
        let mut report = report(&feedback);
        report["replay_policy"]["fingerprint"] = json!(
            load_replay_policy(&feedback.policy_path)
                .unwrap()
                .fingerprint
        );
        report["unmatched_queries"][0]["command"] = json!("COM_QUERY");
        report["unmatched_queries"][0]["sql"] = json!(format!(
            "INSERT INTO items (name, created_at, updated_at, owner_id) VALUES ('{TARGET_NAME}', '2026-09-07 12:00:01.100000', '2026-09-07 12:00:01.200000', 7)"
        ));
        report["unmatched_queries"][0]
            .as_object_mut()
            .unwrap()
            .remove("params");
        write(&feedback.replay_report, &report);
        assert_eq!(
            plan_dynamic_value_mysql_time_rule(feedback, time).is_ok(),
            mode != "overlap",
            "{mode}"
        );
    }
}
