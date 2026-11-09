use super::*;
use serde_json::json;

fn record(sql: &str, names: &[&str]) -> RecordedMysqlExchange {
    serde_json::from_value(json!({
        "command":"COM_QUERY", "sql":sql,
        "response":{"status":"resultset", "columns":names.iter().map(|name|
            json!({"name":name, "family":"integer", "sql_type":"BIGINT"})).collect::<Vec<_>>(),
            "rows":[names.iter().enumerate().map(|(i, _)| json!({"kind":"integer", "value":i + 10})).collect::<Vec<_>>()],
            "rows_truncated":false}, "parse_warnings":[]
    })).unwrap()
}

fn project(record: &RecordedMysqlExchange, sql: &str) -> Option<RecordedMysqlResponse> {
    query_response(record, "COM_QUERY", sql, None)
}

#[test]
fn projection_reuses_the_source_shape_but_checks_each_recorded_result() {
    let sql = "SELECT id AS old_id, uid AS old_uid FROM tasks WHERE id=7";
    let source = record(sql, &["old_id", "old_uid"]);
    let invalid = record(sql, &["invalid", "old_uid"]);
    let mut query = Query::prepare("COM_QUERY", "SELECT uid FROM tasks WHERE id=7", None).unwrap();
    assert!(query.response(&source).is_some());
    assert!(query.response(&invalid).is_none());
    assert_eq!(query.source_shapes.len(), 1);
    assert!(query.response(&source).is_some());
}

#[test]
fn grouped_projection_reads_each_occurrences_response() {
    let sql = "SELECT id AS old_id, uid AS old_uid FROM tasks WHERE id=7";
    let first = record(sql, &["old_id", "old_uid"]);
    let invalid = record(sql, &["invalid", "old_uid"]);
    let mut later = first.clone();
    later.response.rows[0][1] = mysql_json("integer", json!(73));
    let mut query = Query::prepare("COM_QUERY", "SELECT uid FROM tasks WHERE id=7", None).unwrap();
    let first = query.grouped_response(&first, Some(0)).unwrap();
    assert_eq!(first.rows[0][0].value, Some(json!(11)));
    assert!(query.grouped_response(&invalid, Some(0)).is_none());
    let later = query.grouped_response(&later, Some(0)).unwrap();
    assert_eq!(later.rows[0][0].value, Some(json!(73)));
    assert_eq!(query.source_groups.len(), 1);
}

#[test]
fn projection_candidate_rebuilds_when_a_policy_changes_bound_values() {
    let source = record("SELECT id, uid FROM tasks WHERE id=7", &["id", "uid"]);
    let sql = "SELECT uid FROM tasks WHERE id=?";
    let mut cache = None;
    for (value, expected) in [(7, true), (8, false), (8, false), (7, true)] {
        let params = [mysql_json("integer", json!(value))];
        assert_eq!(
            Candidate::compare(&mut cache, &source, "COM_STMT_EXECUTE", sql, Some(&params))
                .is_some(),
            expected
        );
    }
}

#[test]
fn distinct_requires_the_same_complete_projection_in_all_matching_paths() {
    for filter in ["", " WHERE tenant=7 AND status='approved'"] {
        let source_sql =
            format!("SELECT DISTINCT t.id AS old_id,t.uid AS old_uid FROM tasks t{filter}");
        let source = record(&source_sql, &["old_id", "old_uid"]);
        let mut cache = sql_match::cache::SqlCache::default();
        let compiled = cache.get(&source_sql);
        let bound_source = compiled.bind("COM_QUERY", None);
        let valid = format!("SELECT DISTINCT uid AS owner,id AS task FROM tasks{filter}");
        let mapped = project(&source, &valid).unwrap();
        assert_eq!(mapped.rows[0][0].value, Some(json!(11)));
        assert_eq!(mapped.rows[0][1].value, Some(json!(10)));
        assert_eq!(mapped.columns[0].name, "owner");
        assert_eq!(statement_columns(&source, &valid).unwrap()[1].name, "task");
        for projection in [
            "id",
            "DISTINCT id",
            "id,uid",
            "DISTINCT id,id",
            "DISTINCT id,uid,status",
            "DISTINCT id,1",
            "DISTINCT COUNT(*)",
        ] {
            let target = format!("SELECT {projection} FROM tasks{filter}");
            assert!(project(&source, &target).is_none(), "{target}");
            assert!(statement_columns(&source, &target).is_none(), "{target}");
            if let Some((a, r)) = cache
                .get(&target)
                .bind("COM_QUERY", None)
                .zip(bound_source.as_ref())
            {
                assert!(semantic_response(&source, r, &a).is_none(), "{target}");
                assert!(semantic_columns(&source, r, &a).is_none(), "{target}");
            }
        }
        let ordinary = record(&format!("SELECT id,uid FROM tasks{filter}"), &["id", "uid"]);
        assert!(project(&ordinary, &valid).is_none());
        assert!(statement_columns(&ordinary, &valid).is_none());
    }
}

#[test]
fn distinct_preserves_order_by_column_identity_and_limit() {
    let source = record(
        "SELECT DISTINCT id AS old_id,uid AS old_uid FROM tasks ORDER BY 1 LIMIT 2",
        &["old_id", "old_uid"],
    );
    assert!(
        project(
            &source,
            "SELECT DISTINCT uid,id FROM tasks ORDER BY 2 LIMIT 2"
        )
        .is_some()
    );
    for sql in [
        "SELECT DISTINCT uid,id FROM tasks ORDER BY 1 LIMIT 2",
        "SELECT DISTINCT uid,id FROM tasks ORDER BY 2 DESC LIMIT 2",
        "SELECT DISTINCT uid,id FROM tasks ORDER BY 2 LIMIT 1",
        "SELECT DISTINCT uid,id FROM tasks",
    ] {
        assert!(project(&source, sql).is_none(), "{sql}");
    }
}

#[test]
fn selects_reorders_and_relabels_by_physical_column_without_mutating_record() {
    let record = record(
        "SELECT s.id AS shard_id, s.uid AS shard_uid, s.status AS shard_status FROM subtasks_0640 AS s WHERE s.id=1 ORDER BY s.uid DESC LIMIT 2",
        &["shard_id", "shard_uid", "shard_status"],
    );
    let result = project(&record, "SELECT t.status AS state, id AS task_id FROM subtasks_0640 AS t WHERE id=1 ORDER BY t.uid DESC LIMIT 2").unwrap();
    assert_eq!(
        result
            .columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        ["state", "task_id"]
    );
    assert_eq!(
        result.rows[0]
            .iter()
            .map(|v| v.value.clone().unwrap())
            .collect::<Vec<_>>(),
        [json!(12), json!(10)]
    );
    assert_eq!(result.columns[0].column.as_deref(), Some("status"));
    assert_eq!(result.columns[0].table.as_deref(), Some("subtasks_0640"));
    assert_eq!(result.columns[0].table_alias.as_deref(), Some("t"));
    let payload = column_definition_payload(&result.columns[0]);
    let mut offset = 0;
    let mut fields = Vec::new();
    for _ in 0..6 {
        let length = usize::from(payload[offset]);
        offset += 1;
        fields.push(std::str::from_utf8(&payload[offset..offset + length]).unwrap());
        offset += length;
    }
    assert_eq!(fields, ["def", "", "t", "subtasks_0640", "state", "status"]);
    assert_eq!(record.response.columns.len(), 3);
    assert_eq!(record.response.columns[0].name, "shard_id");
    assert_eq!(record.response.rows[0][0].value, Some(json!(10)));
}

#[test]
fn conditions_values_actual_tables_and_pagination_stay_strict() {
    let source = record(
        "SELECT t.id AS old_id, t.uid AS old_uid FROM tasks t WHERE t.id=1 ORDER BY t.uid DESC LIMIT 2",
        &["old_id", "old_uid"],
    );
    for sql in [
        "SELECT id FROM tasks t WHERE id=2 ORDER BY uid DESC LIMIT 2",
        "SELECT id FROM tasks t WHERE id='1' ORDER BY uid DESC LIMIT 2",
        "SELECT id FROM other t WHERE id=1 ORDER BY uid DESC LIMIT 2",
        "SELECT id FROM tasks t WHERE id=1 ORDER BY uid ASC LIMIT 2",
        "SELECT id FROM tasks t WHERE id=1 ORDER BY uid DESC LIMIT 3",
        "SELECT id FROM tasks t WHERE id=1 ORDER BY uid DESC LIMIT 2 OFFSET 1",
        "SELECT missing FROM tasks t WHERE id=1 ORDER BY uid DESC LIMIT 2",
    ] {
        assert!(project(&source, sql).is_none(), "{sql}");
    }
}

#[test]
fn count_and_constants_match_the_same_expression_with_different_aliases() {
    let source = record(
        "SELECT COUNT(*) AS n FROM tasks WHERE status='RUNNING'",
        &["n"],
    );
    for sql in [
        "SELECT count(*) AS total FROM tasks WHERE status='RUNNING'",
        "SELECT COUNT(*) FROM tasks WHERE status='RUNNING'",
    ] {
        let result = project(&source, sql).unwrap();
        assert_eq!(result.rows[0][0].value, Some(json!(10)));
        assert_eq!(result.columns[0].column.as_deref(), Some(""));
        assert_eq!(result.columns[0].table, None);
        assert_eq!(
            result.columns[0].name,
            if sql.contains("total") {
                "total"
            } else {
                "COUNT(*)"
            }
        );
    }
    for sql in [
        "SELECT id FROM tasks WHERE status='RUNNING'",
        "SELECT COUNT(id) FROM tasks WHERE status='RUNNING'",
        "SELECT 1 FROM tasks WHERE status='RUNNING'",
        "SELECT SUM(id) FROM tasks WHERE status='RUNNING'",
    ] {
        assert!(project(&source, sql).is_none(), "{sql}");
    }
    let source = record(
        "SELECT 1 AS exists_flag FROM tasks WHERE id=1",
        &["exists_flag"],
    );
    assert_eq!(
        project(&source, "SELECT 1 FROM tasks WHERE id=1")
            .unwrap()
            .columns[0]
            .name,
        "1"
    );
    assert!(project(&source, "SELECT 2 FROM tasks WHERE id=1").is_none());
    assert!(project(&source, "SELECT '1' FROM tasks WHERE id=1").is_none());
    let source = record("SELECT 1 AS ping", &["ping"]);
    assert!(project(&source, "SELECT 1 AS pong").is_some());
    for sql in [
        "SELECT 1.0 AS pong",
        "SELECT 1e0 AS pong",
        "SELECT TRUE AS pong",
    ] {
        assert!(project(&source, sql).is_none(), "{sql}");
    }
}

#[test]
fn constants_cannot_be_dropped_or_added_while_plain_columns_can() {
    let source = record(
        "SELECT id, 1 AS marker, uid FROM tasks WHERE id=1",
        &["id", "marker", "uid"],
    );
    assert!(project(&source, "SELECT 1 AS present, uid FROM tasks WHERE id=1").is_some());
    for sql in [
        "SELECT uid FROM tasks WHERE id=1",
        "SELECT 2, uid FROM tasks WHERE id=1",
        "SELECT 1, 1, uid FROM tasks WHERE id=1",
    ] {
        assert!(project(&source, sql).is_none(), "{sql}");
    }
}

#[test]
fn alias_or_ordinal_ordering_is_resolved_before_comparing_queries() {
    let source = record(
        "SELECT id AS sort_key, uid FROM tasks ORDER BY sort_key",
        &["sort_key", "uid"],
    );
    assert!(
        project(
            &source,
            "SELECT uid, id AS renamed FROM tasks ORDER BY renamed"
        )
        .is_some()
    );
    assert!(
        project(
            &source,
            "SELECT uid AS sort_key, id FROM tasks ORDER BY sort_key"
        )
        .is_none()
    );
    let source = record("SELECT id, uid FROM tasks ORDER BY 1", &["id", "uid"]);
    assert!(project(&source, "SELECT uid, id FROM tasks ORDER BY 1").is_none());
    assert!(project(&source, "SELECT uid, id FROM tasks ORDER BY 2").is_some());
    assert!(project(&source, "SELECT uid, id FROM tasks ORDER BY 2.0").is_none());
    assert!(
        query_response(
            &source,
            "COM_STMT_EXECUTE",
            "SELECT uid, id FROM tasks ORDER BY ?",
            Some(&[mysql_json("integer", json!(2))]),
        )
        .is_none()
    );
    let source = record(
        "SELECT id AS uid, uid AS id FROM tasks ORDER BY id",
        &["uid", "id"],
    );
    assert!(project(&source, "SELECT id, uid FROM tasks ORDER BY id").is_none());
}

#[test]
fn advanced_sql_and_ambiguous_or_incomplete_evidence_do_not_gain_matches() {
    for (sql, names) in [
        ("SELECT DISTINCT id, uid FROM tasks", vec!["id", "uid"]),
        ("SELECT DISTINCTROW id, uid FROM tasks", vec!["id", "uid"]),
        (
            "SELECT id, CURRENT_TIMESTAMP FROM tasks",
            vec!["id", "CURRENT_TIMESTAMP"],
        ),
        (
            "SELECT id, COUNT(*) AS n FROM tasks GROUP BY id",
            vec!["id", "n"],
        ),
        (
            "SELECT t.id, u.uid FROM tasks t JOIN users u ON t.uid=u.uid",
            vec!["id", "uid"],
        ),
        (
            "SELECT id, uid FROM tasks WHERE EXISTS (SELECT 1 FROM users)",
            vec!["id", "uid"],
        ),
        ("SELECT id, uid FROM tasks FOR UPDATE", vec!["id", "uid"]),
        ("SELECT id AS a, id AS b FROM tasks", vec!["a", "b"]),
        ("SELECT * FROM tasks", vec!["id", "uid"]),
    ] {
        let source = record(sql, &names);
        assert!(project(&source, "SELECT id FROM tasks").is_none(), "{sql}");
    }
    for mutation in [
        "columns",
        "rows",
        "truncated",
        "warning",
        "origin",
        "label",
        "error",
    ] {
        let mut source = record("SELECT id, uid FROM tasks", &["id", "uid"]);
        match mutation {
            "columns" => {
                source.response.columns.pop();
            }
            "rows" => {
                source.response.rows[0].pop();
            }
            "truncated" => source.response.rows_truncated = true,
            "warning" => source.parse_warnings.push("parse failed".into()),
            "origin" => source.response.columns[0].column = Some("other".into()),
            "label" => source.response.columns[0].name = "other".into(),
            "error" => source.response.status = "error".into(),
            _ => unreachable!(),
        }
        assert!(
            project(&source, "SELECT id AS result FROM tasks").is_none(),
            "{mutation}"
        );
    }
}

#[test]
fn prepared_metadata_and_execute_share_the_same_column_mapping() {
    let source = record(
        "SELECT id AS tasks_id, uid AS tasks_uid FROM tasks WHERE id=1",
        &["tasks_id", "tasks_uid"],
    );
    let sql = "SELECT uid AS owner FROM tasks WHERE id=?";
    let metadata = statement_columns(&source, sql).unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].name, "owner");
    let result = query_response(
        &source,
        "COM_STMT_EXECUTE",
        sql,
        Some(&[mysql_json("integer", json!(1))]),
    )
    .unwrap();
    assert_eq!(result.columns[0].name, metadata[0].name);
    assert_eq!(result.rows[0][0].value, Some(json!(11)));
    assert!(
        query_response(
            &source,
            "COM_STMT_EXECUTE",
            sql,
            Some(&[mysql_json("integer", json!(2))])
        )
        .is_none()
    );
    let mut source = source;
    source.command = "COM_STMT_EXECUTE".into();
    source.sql = Some("SELECT id AS tasks_id, uid AS tasks_uid FROM tasks WHERE id=?".into());
    source.params = Some(vec![mysql_json("integer", json!(1))]);
    assert!(project(&source, "SELECT uid AS owner FROM tasks WHERE id=1").is_some());
    assert!(project(&source, "SELECT uid AS owner FROM tasks WHERE id=2").is_none());
}

#[test]
fn expression_labels_preserve_original_spelling_and_quoted_aliases() {
    let source = record("SELECT COUNT( * ) FROM tasks", &["COUNT( * )"]);
    assert_eq!(
        project(&source, "SELECT CoUnT(*) FROM tasks")
            .unwrap()
            .columns[0]
            .name,
        "CoUnT(*)"
    );
    let source = record("SELECT `id` AS 'old label' FROM `tasks`", &["old label"]);
    assert_eq!(
        project(&source, "SELECT tasks.id AS `new label` FROM tasks")
            .unwrap()
            .columns[0]
            .name,
        "new label"
    );
    let source = record("SELECT count AS counter, id FROM tasks", &["counter", "id"]);
    assert!(project(&source, "SELECT id FROM tasks").is_some());
}
