use super::*;
use serde_json::json;

fn event(sql: &str) -> Value {
    json!({
        "event_type":"mysql_exchange", "target_host":"db.internal", "target_port":3306,
        "database":"app", "username":"reader", "command":"COM_QUERY", "sql":sql,
        "connection_id":"00000000-0000-0000-0000-000000000004", "query_sequence":7,
        "outcome":"response", "parse_warnings":[],
        "response":{"status":"resultset", "row_count":1, "rows_truncated":false,
            "columns":[{"name":"id"}], "rows":[[{"kind":"string", "value":"row-payload-not-projected"}]]}
    })
}

#[test]
fn returned_detail_command_exposes_mysql_rule_inputs_without_reading_raw_capture() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp
        .path()
        .join(".traffic-e2e/local/artifacts/run/api/00000000-0000-0000-0000-000000000003");
    std::fs::create_dir_all(&case_dir).unwrap();
    let sql = format!(
        "SELECT {} FROM subtasks_0640 WHERE status='RUNNING' AND created_at>='2026-09-05'",
        (0..30)
            .map(|i| format!("subtasks_0640.field_{i} AS subtasks_0640_field_{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(sql.len() > MAX_PREVIEW_BYTES);
    let mut query_event = event(&sql);
    query_event["server_status_before"] = json!(0);
    query_event["response"]["server_status"] = json!(1);
    let mut other = event("SELECT unrelated FROM other WHERE id=1");
    other["target_host"] = json!("other.internal");
    let raw = format!("{query_event}\n{other}\n");
    let path = super::super::tests::publish(&case_dir, &raw);
    let original = std::fs::read(&path).unwrap();
    let summary = query(RewriteCaseDependenciesOptions {
        target_root: temp.path().to_path_buf(),
        case_dir: case_dir.clone(),
        target_id: None,
    })
    .unwrap();
    let summary = serde_json::to_value(summary).unwrap();
    assert_eq!(summary["targets_total"], 2);
    assert!(!summary.to_string().contains("subtasks"));
    let target = summary["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["target"] == "db.internal:3306")
        .unwrap();
    let argv = target["detail_command"]["argv"].as_array().unwrap();
    let detail = query(RewriteCaseDependenciesOptions {
        target_root: argv[2].as_str().unwrap().into(),
        case_dir: Path::new(target["detail_command"]["cwd"].as_str().unwrap())
            .join(argv[5].as_str().unwrap()),
        target_id: Some(argv[6].as_str().unwrap().to_owned()),
    })
    .unwrap();
    let detail = serde_json::to_value(detail).unwrap();
    assert_eq!(detail["detail_kind"], "mysql");
    assert_eq!(detail["event_count"], 1);
    let exchange = &detail["operations"][0]["representative_exchanges"][0];
    assert_eq!(exchange["database"], "app");
    assert_eq!(exchange["username"], "reader");
    assert_eq!(exchange["sql"]["data"], sql);
    assert_eq!(exchange["sql"]["truncated"], false);
    assert_eq!(
        exchange["sql_fingerprint"],
        crate::config::process_owned_dependencies::mysql::evidence::fingerprint(&sql)
    );
    assert_eq!(exchange["row_count"], 1);
    assert_eq!(exchange["rows_truncated"], false);
    assert_eq!(exchange["column_names"][0]["data"], "id");
    assert_eq!(
        exchange["connection_id"],
        "00000000-0000-0000-0000-000000000004"
    );
    assert_eq!(exchange["query_sequence"], 7);
    assert_eq!(exchange["server_status_before"], 0);
    assert_eq!(exchange["server_status_after"], 1);
    assert_eq!(exchange["capture"]["owner_kind"], "case");
    assert_eq!(
        exchange["capture"]["origin_case_id"],
        "00000000-0000-0000-0000-000000000003"
    );
    assert_eq!(exchange["capture"]["phase"], "runtime");
    assert!(exchange.get("case_dependency_matched_by").is_none());
    assert!(!detail.to_string().contains("row-payload-not-projected"));
    assert!(!detail.to_string().contains("unrelated"));
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn duplicate_locations_do_not_hide_other_queries_and_omissions_are_counted() {
    let mut builder = OperationBuilder::default();
    for sequence in 0..4 {
        let mut e = event("SELECT id FROM tasks WHERE status='RUNNING'");
        e["query_sequence"] = json!(sequence);
        e["connection_id"] = json!(format!("connection-{sequence}"));
        builder.record(&e).unwrap();
    }
    for table in ["tasks_1", "tasks_2", "tasks_3"] {
        builder
            .record(&event(&format!(
                "SELECT id FROM {table} WHERE status='RUNNING'"
            )))
            .unwrap();
    }
    let details = finish(BTreeMap::from([("COM_QUERY".into(), builder)]));
    let op = &details[0];
    assert_eq!(op.count, 7);
    assert_eq!(op.outcomes["response"], 7);
    assert_eq!(op.response_statuses["resultset"], 7);
    assert_eq!(op.representative_exchanges.len(), 3);
    assert_eq!(op.omitted_representative_exchanges, 4);
    assert!(
        op.representative_exchanges[1]
            .sql
            .as_ref()
            .unwrap()
            .data
            .contains("tasks_1")
    );
    assert_eq!(op.representative_exchanges[0].query_sequence, Some(0));
}

#[test]
fn parameters_keep_types_and_null_presence_and_large_facts_are_bounded() {
    let mut e = event(&"查询".repeat(2000));
    let large = "参数".repeat(100);
    let mut params = vec![
        json!({"kind":"integer", "value":42}),
        json!({"kind":"null", "value":null}),
        json!({"kind":"unknown"}),
    ];
    params.extend(vec![
        json!({"kind":"string", "value":large, "raw":{
            "encoding":"utf8", "original_len":large.len(), "truncated":false, "data":large
        }});
        16
    ]);
    e["params"] = json!(params);
    e["response"]["columns"] = json!(vec![json!({"name":large}); 20]);
    e["parse_warnings"] = json!(vec![large.clone(); 5]);
    let mut builder = OperationBuilder::default();
    builder.record(&e).unwrap();
    let sample = &builder.representatives[0];
    let sql = sample.sql.as_ref().unwrap();
    assert!(sql.truncated);
    assert!(sql.data.len() <= MAX_SQL_BYTES);
    assert_eq!(sql.original_len, 12000);
    let params = sample.params.as_ref().unwrap();
    assert_eq!(params.len(), 16);
    assert_eq!(sample.omitted_params, 3);
    assert_eq!(params[0].value, Some(json!(42)));
    assert_eq!(params[1].value, Some(Value::Null));
    assert_eq!(params[2].value, None);
    assert_eq!(params[3].value, None);
    assert!(params[3].value_preview.as_ref().unwrap().truncated);
    assert!(params[3].raw.as_ref().unwrap().truncated);
    assert_eq!(sample.column_names.len(), 16);
    assert_eq!(sample.omitted_columns, 4);
    assert_eq!(sample.parse_warnings.len(), 3);
    assert_eq!(sample.omitted_parse_warnings, 2);
    for preview in sample
        .column_names
        .iter()
        .chain(sample.parse_warnings.iter())
    {
        assert!(preview.truncated && preview.data.len() <= MAX_PREVIEW_BYTES);
    }
    let encoded = serde_json::to_value(sample).unwrap();
    assert!(
        encoded["params"][1]
            .as_object()
            .unwrap()
            .contains_key("value")
    );
    assert!(
        !encoded["params"][2]
            .as_object()
            .unwrap()
            .contains_key("value")
    );
}

#[test]
fn errors_and_missing_metadata_are_preserved_without_inventing_success() {
    let mut e = event("SELECT id FROM missing WHERE id=1");
    e["database"] = Value::Null;
    e["response"] =
        json!({"status":"error", "error_code":1146, "error_message":"Table does not exist"});
    let mut builder = OperationBuilder::default();
    builder.record(&e).unwrap();
    let sample = &builder.representatives[0];
    assert_eq!(sample.database, None);
    assert_eq!(sample.response_status.as_deref(), Some("error"));
    assert_eq!(sample.error_code, Some(1146));
    assert_eq!(
        sample.error_message.as_ref().unwrap().data,
        "Table does not exist"
    );
    assert_eq!(sample.row_count, None);
    assert_eq!(sample.rows_truncated, None);
    let encoded = serde_json::to_value(sample).unwrap();
    assert!(encoded.get("server_status_before").is_none());
    assert!(encoded.get("server_status_after").is_none());
}

#[test]
fn transaction_status_distinguishes_representatives_without_treating_zero_as_missing() {
    let mut builder = OperationBuilder::default();
    for (sequence, before, after) in [(1, 0, 1), (2, 1, 1), (3, 0, 1)] {
        let mut e = event("SELECT id FROM users WHERE id=7");
        e["query_sequence"] = json!(sequence);
        e["server_status_before"] = json!(before);
        e["response"]["server_status"] = json!(after);
        builder.record(&e).unwrap();
    }
    let details = finish(BTreeMap::from([("COM_QUERY".into(), builder)]));
    let op = &details[0];
    assert_eq!(op.count, 3);
    assert_eq!(op.representative_exchanges.len(), 2);
    assert_eq!(op.omitted_representative_exchanges, 1);
    assert_eq!(op.representative_exchanges[0].server_status_before, Some(0));
    assert_eq!(op.representative_exchanges[0].server_status_after, Some(1));
    assert_eq!(op.representative_exchanges[1].server_status_before, Some(1));
    assert_eq!(op.representative_exchanges[1].query_sequence, Some(2));
}

#[test]
fn capture_projection_preserves_task_and_bounds_rule_identities_without_changing_physical_refs() {
    let mut capture = crate::dependency::observation::fixture_capture("process");
    capture.matched_rule_id = Some("task-selector".into());
    capture.matched_rule_ids = (0..20).map(|index| format!("selector-{index}")).collect();
    let mut value = event("SELECT id FROM tasks WHERE status='RUNNING'");
    value["capture"] = serde_json::to_value(capture).unwrap();
    let mut builder = OperationBuilder::default();
    builder.record(&value).unwrap();
    let sample = &builder.representatives[0];
    let detail = sample.capture.as_ref().unwrap();
    assert_eq!(detail.owner_kind, "process");
    assert_eq!(detail.phase, "runtime");
    assert_eq!(detail.process_task.as_deref(), Some("fixture_task"));
    assert_eq!(detail.matched_rule_id.as_deref(), Some("task-selector"));
    assert_eq!(
        detail.matched_rule_ids.len(),
        MAX_ARGUMENTS_PER_REPRESENTATIVE
    );
    assert_eq!(detail.omitted_matched_rule_ids, 4);
    assert_eq!(sample.query_sequence, Some(7));
    assert_eq!(
        sample.connection_id.as_deref(),
        value["connection_id"].as_str()
    );
    value["capture"]["matched_rule_id"] = json!("x".repeat(MAX_PREVIEW_BYTES + 1));
    assert!(OperationBuilder::default().record(&value).is_err());
}
