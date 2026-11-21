//! Native maintenance and session responses used by dependency drivers.
use crate::maintenance::{MysqlMaintenanceQuery, classify_mysql_maintenance_query};
use crate::recorded::RecordedMysqlResponse;
use crate::session_setup::is_mysql_session_setup_sql;
use crate::values::normalize_sql;
use crate::values::{integer_column, mysql_json, string_column};
use serde_json::Value;

pub fn builtin_response<E>(sql: &str, database: Option<&str>) -> Option<RecordedMysqlResponse<E>> {
    if let Some(maintenance) = classify_mysql_maintenance_query(sql) {
        return Some(match maintenance {
            MysqlMaintenanceQuery::C3p0TableProbe => RecordedMysqlResponse {
                wire_prefix: Vec::new(),
                evidence: None,
                row_shape: None,
                server_status: None,
                rows_truncated: false,
                status: "error".to_string(),
                error_code: Some(1102),
                error_message: Some("Incorrect database name ''".to_string()),
                affected_rows: None,
                last_insert_id: None,
                columns: Vec::new(),
                rows: Vec::new(),
            },
            MysqlMaintenanceQuery::SelectOne => single_integer_result("1", 1),
            MysqlMaintenanceQuery::SelectTwo => single_integer_result("2", 2),
        });
    }

    let normalized = normalize_sql(sql);
    if is_builtin_ok(&normalized) {
        return Some(RecordedMysqlResponse {
            wire_prefix: Vec::new(),
            evidence: None,
            row_shape: None,
            server_status: None,
            rows_truncated: false,
            status: "ok".to_string(),
            error_code: None,
            error_message: None,
            affected_rows: Some(0),
            last_insert_id: Some(0),
            columns: Vec::new(),
            rows: Vec::new(),
        });
    }
    if normalized == "select database()" {
        return Some(single_string_result("DATABASE()", database.unwrap_or("")));
    }
    if matches!(
        normalized.as_str(),
        "select version()" | "select @@ version"
    ) {
        return Some(single_string_result(
            "VERSION()",
            "8.0.0-traffic-recorder-replay",
        ));
    }
    if normalized == "show warnings" {
        return Some(RecordedMysqlResponse {
            wire_prefix: Vec::new(),
            evidence: None,
            row_shape: None,
            server_status: None,
            rows_truncated: false,
            status: "resultset".to_string(),
            error_code: None,
            error_message: None,
            affected_rows: None,
            last_insert_id: None,
            columns: vec![
                string_column("Level"),
                integer_column("Code"),
                string_column("Message"),
            ],
            rows: Vec::new(),
        });
    }
    if normalized == "show variables" {
        return Some(RecordedMysqlResponse {
            wire_prefix: Vec::new(),
            evidence: None,
            row_shape: None,
            server_status: None,
            rows_truncated: false,
            status: "resultset".to_string(),
            error_code: None,
            error_message: None,
            affected_rows: None,
            last_insert_id: None,
            columns: vec![string_column("Variable_name"), string_column("Value")],
            rows: Vec::new(),
        });
    }
    None
}

pub fn is_builtin_ok(normalized_sql: &str) -> bool {
    is_mysql_session_setup_sql(normalized_sql)
        || crate::autocommit::assignment(normalized_sql).is_some()
        || matches!(
            normalized_sql,
            "begin" | "start transaction" | "commit" | "rollback"
        )
}

pub fn single_string_result<E>(name: &str, value: &str) -> RecordedMysqlResponse<E> {
    RecordedMysqlResponse {
        wire_prefix: Vec::new(),
        evidence: None,
        row_shape: None,
        server_status: None,
        rows_truncated: false,
        status: "resultset".to_string(),
        error_code: None,
        error_message: None,
        affected_rows: None,
        last_insert_id: None,
        columns: vec![string_column(name)],
        rows: vec![vec![mysql_json("string", Value::String(value.to_string()))]],
    }
}

fn single_integer_result<E>(name: &str, value: i64) -> RecordedMysqlResponse<E> {
    RecordedMysqlResponse {
        wire_prefix: Vec::new(),
        evidence: None,
        row_shape: None,
        server_status: None,
        rows_truncated: false,
        status: "resultset".to_string(),
        error_code: None,
        error_message: None,
        affected_rows: None,
        last_insert_id: None,
        columns: vec![integer_column(name)],
        rows: vec![vec![mysql_json("integer", Value::Number(value.into()))]],
    }
}
