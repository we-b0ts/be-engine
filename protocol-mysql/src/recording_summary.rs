use crate::capture::is_debug_only_mysql_exchange_value;
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use traffic_protocol::observation::RecordingSummary;
use traffic_protocol::observation::termination;
#[derive(Debug, Default, Serialize)]
pub(crate) struct MysqlDependencySummary {
    connections: usize,
    connection_errors: usize,
    tls_rejected: usize,
    routes: BTreeMap<String, usize>,
    target_hosts: BTreeMap<String, usize>,
    target_addrs: BTreeMap<String, usize>,
    databases: BTreeMap<String, usize>,
    users: BTreeMap<String, usize>,
    upstreams: BTreeMap<String, usize>,
    tls_rejection_reasons: BTreeMap<String, usize>,
    semantic_exchanges: usize,
    executed: MysqlOperationCounts,
    failed: MysqlFailureCounts,
    resultsets: usize,
    errors: usize,
    rows_returned: usize,
    affected_rows: u64,
    tables: BTreeMap<String, MysqlTableSummary>,
    dependencies: BTreeMap<String, MysqlDependencyIdentitySummary>,
    statements: Vec<MysqlStatementSummary>,
}

impl MysqlDependencySummary {
    fn has_activity(&self) -> bool {
        self.connections > 0 || self.tls_rejected > 0 || self.semantic_exchanges > 0
    }
}

#[derive(Debug, Default, Serialize)]
struct MysqlOperationCounts {
    total: usize,
    crud: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Serialize)]
struct MysqlFailureCounts {
    total: usize,
    by_phase: BTreeMap<String, usize>,
    crud: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Serialize)]
struct MysqlTableSummary {
    executed: BTreeMap<String, usize>,
    failed: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Serialize)]
struct MysqlDependencyIdentitySummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_port: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    executed: BTreeMap<String, usize>,
    failed: BTreeMap<String, usize>,
    tables: BTreeMap<String, MysqlTableSummary>,
}

#[derive(Debug, Serialize)]
struct MysqlStatementSummary {
    query_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_port: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    command: Option<String>,
    phase: String,
    operation: String,
    tables: Vec<String>,
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    row_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affected_rows: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

fn record_mysql_connection_summary(summary: &mut MysqlDependencySummary, value: &Value) {
    summary.connections += 1;
    if let Some(route) = json_str(value, "route_name") {
        *summary.routes.entry(route.to_string()).or_default() += 1;
    }
    if let Some(target_host) = json_str(value, "target_host") {
        *summary
            .target_hosts
            .entry(target_host.to_string())
            .or_default() += 1;
    }
    if let Some(target_addr) = json_str(value, "target_addr") {
        *summary
            .target_addrs
            .entry(target_addr.to_string())
            .or_default() += 1;
    }
    if let Some(database) = json_str(value, "database") {
        *summary.databases.entry(database.to_string()).or_default() += 1;
    }
    if let Some(username) = json_str(value, "username") {
        *summary.users.entry(username.to_string()).or_default() += 1;
    }
    if let Some(upstream) = json_str(value, "upstream_addr") {
        *summary.upstreams.entry(upstream.to_string()).or_default() += 1;
    }
    if value.get("error").is_some_and(|error| !error.is_null()) {
        summary.connection_errors += 1;
    }
}

fn record_mysql_tls_rejected_summary(summary: &mut MysqlDependencySummary, value: &Value) {
    summary.tls_rejected += 1;
    if let Some(route) = json_str(value, "route_name") {
        *summary.routes.entry(route.to_string()).or_default() += 1;
    }
    if let Some(target_host) = json_str(value, "target_host") {
        *summary
            .target_hosts
            .entry(target_host.to_string())
            .or_default() += 1;
    }
    if let Some(target_addr) = json_str(value, "target_addr") {
        *summary
            .target_addrs
            .entry(target_addr.to_string())
            .or_default() += 1;
    }
    if let Some(upstream) = json_str(value, "upstream_addr") {
        *summary.upstreams.entry(upstream.to_string()).or_default() += 1;
    }
    if let Some(reason) = json_str(value, "reason") {
        *summary
            .tls_rejection_reasons
            .entry(reason.to_string())
            .or_default() += 1;
    }
}

fn record_mysql_summary(summary: &mut MysqlDependencySummary, value: &Value) {
    if is_debug_only_mysql_exchange_value(value) {
        return;
    }
    summary.semantic_exchanges += 1;
    let command = json_str(value, "command").map(ToOwned::to_owned);
    let phase = mysql_phase(command.as_deref()).to_string();
    let response = value.get("response").unwrap_or(&Value::Null);
    let status = json_str(response, "status").map(ToOwned::to_owned);
    let operation = json_str(value, "sql")
        .map(mysql_operation)
        .unwrap_or_else(|| "unknown".to_string());
    let tables = json_str(value, "sql")
        .map(extract_mysql_tables)
        .unwrap_or_else(|| mysql_tables_from_columns(response));
    let row_count = json_usize(response, "row_count");
    let affected_rows = json_u64(response, "affected_rows");
    let error_code = json_u64(response, "error_code");
    let error_message = json_str(response, "error_message").map(ToOwned::to_owned);
    let target_host = json_str(value, "target_host").map(ToOwned::to_owned);
    let target_port = json_u64(value, "target_port");
    let database = json_str(value, "database").map(ToOwned::to_owned);
    let username = json_str(value, "username").map(ToOwned::to_owned);
    let failed = termination::client_terminated(value)
        || termination::server_terminated(value)
        || status
            .as_deref()
            .is_some_and(|status| matches!(status, "error" | "incomplete" | "client_terminated"))
        || error_code.is_some()
        || error_message.is_some();

    if failed {
        summary.failed.total += 1;
        *summary.failed.by_phase.entry(phase.clone()).or_default() += 1;
        *summary.failed.crud.entry(operation.clone()).or_default() += 1;
    } else {
        summary.executed.total += 1;
        *summary.executed.crud.entry(operation.clone()).or_default() += 1;
        if status.as_deref() == Some("resultset") {
            summary.resultsets += 1;
        }
        summary.rows_returned += row_count.unwrap_or(0);
        summary.affected_rows += affected_rows.unwrap_or(0);
    }

    if status.as_deref() == Some("error") {
        summary.errors += 1;
    }

    for table in &tables {
        let table_summary = summary.tables.entry(table.clone()).or_default();
        let target = if failed {
            &mut table_summary.failed
        } else {
            &mut table_summary.executed
        };
        *target.entry(operation.clone()).or_default() += 1;
    }

    let identity_key = mysql_dependency_identity_key(
        target_host.as_deref(),
        target_port,
        database.as_deref(),
        username.as_deref(),
    );
    let identity_summary = summary.dependencies.entry(identity_key).or_insert_with(|| {
        MysqlDependencyIdentitySummary {
            target_host: target_host.clone(),
            target_port,
            database: database.clone(),
            username: username.clone(),
            ..MysqlDependencyIdentitySummary::default()
        }
    });
    let identity_counts = if failed {
        &mut identity_summary.failed
    } else {
        &mut identity_summary.executed
    };
    *identity_counts.entry(operation.clone()).or_default() += 1;
    for table in &tables {
        let table_summary = identity_summary.tables.entry(table.clone()).or_default();
        let target = if failed {
            &mut table_summary.failed
        } else {
            &mut table_summary.executed
        };
        *target.entry(operation.clone()).or_default() += 1;
    }

    summary.statements.push(MysqlStatementSummary {
        query_sequence: json_u64(value, "query_sequence"),
        target_host,
        target_port,
        database,
        username,
        command,
        phase,
        operation,
        tables,
        status,
        row_count,
        affected_rows,
        error_code,
        error_message,
    });
}

fn mysql_dependency_identity_key(
    target_host: Option<&str>,
    target_port: Option<u64>,
    database: Option<&str>,
    username: Option<&str>,
) -> String {
    format!(
        "{}:{}|db={}|user={}",
        target_host.unwrap_or("<unknown-host>"),
        target_port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "<unknown-port>".to_string()),
        database.unwrap_or("<unknown-db>"),
        username.unwrap_or("<unknown-user>")
    )
}

fn mysql_phase(command: Option<&str>) -> &'static str {
    match command {
        Some("COM_STMT_PREPARE") => "prepare",
        Some("COM_STMT_EXECUTE") => "execute",
        Some("COM_QUERY") => "query",
        Some(_) => "other",
        None => "unknown",
    }
}

fn mysql_operation(sql: &str) -> String {
    let normalized = sql.trim_start();
    let keyword = normalized
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .find(|token| !token.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    match keyword.as_str() {
        "select" | "insert" | "update" | "delete" => keyword,
        _ => "other".to_string(),
    }
}

fn extract_mysql_tables(sql: &str) -> Vec<String> {
    let tokens = mysql_tokens(sql);
    let mut tables = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        let token_lower = token.to_ascii_lowercase();
        let captures_next = matches!(token_lower.as_str(), "from" | "join" | "into" | "update");
        if !captures_next {
            continue;
        }
        let Some(candidate) = tokens.get(index + 1) else {
            continue;
        };
        if let Some(table) = clean_mysql_table_name(candidate) {
            tables.insert(table);
        }
    }
    tables.into_iter().collect()
}

fn mysql_tokens(sql: &str) -> Vec<String> {
    let mut normalized = String::with_capacity(sql.len());
    for ch in sql.chars() {
        if matches!(ch, '(' | ')' | ',' | ';' | '\n' | '\r' | '\t') {
            normalized.push(' ');
        } else {
            normalized.push(ch);
        }
    }
    normalized
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect()
}

fn clean_mysql_table_name(token: &str) -> Option<String> {
    let token = token
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'');
    if token.is_empty()
        || token.starts_with('?')
        || matches!(
            token.to_ascii_lowercase().as_str(),
            "select" | "where" | "set" | "values" | "on" | "limit"
        )
    {
        return None;
    }
    let table = token
        .rsplit('.')
        .next()
        .unwrap_or(token)
        .trim_matches('`')
        .to_string();
    (!table.is_empty()).then_some(table)
}

fn mysql_tables_from_columns(response: &Value) -> Vec<String> {
    let mut tables = BTreeSet::new();
    if let Some(columns) = response.get("columns").and_then(Value::as_array) {
        for column in columns {
            if let Some(table) = json_str(column, "table")
                && !table.is_empty()
            {
                tables.insert(table.to_string());
            }
        }
    }
    tables.into_iter().collect()
}

fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn json_usize(value: &Value, key: &str) -> Option<usize> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

impl RecordingSummary for MysqlDependencySummary {
    fn observe(&mut self, value: &Value) {
        match value["event_type"].as_str() {
            Some("mysql_connection") => record_mysql_connection_summary(self, value),
            Some("mysql_tls_rejected") => record_mysql_tls_rejected_summary(self, value),
            Some("mysql_exchange") => record_mysql_summary(self, value),
            _ => {}
        }
    }
    fn finish(self: Box<Self>) -> Result<BTreeMap<String, Value>> {
        let mut fields = BTreeMap::new();
        if self.has_activity() {
            fields.insert("mysql".into(), serde_json::to_value(self)?);
        }
        Ok(fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::is_successful_mysql_session_setup;
    #[test]
    fn extracts_mysql_tables_from_common_crud_sql() {
        assert_eq!(
            extract_mysql_tables(
                "SELECT T0.`id`, T1.`name` FROM `user_appkey` T0 INNER JOIN `user` T1 ON T1.`id` = T0.`user_id`"
            ),
            vec!["user".to_string(), "user_appkey".to_string()]
        );
        assert_eq!(
            extract_mysql_tables("INSERT INTO request_log_202607 (uuid) VALUES (?)"),
            vec!["request_log_202607".to_string()]
        );
        assert_eq!(
            extract_mysql_tables("UPDATE `request_log_202607` SET response_status=? WHERE uuid=?"),
            vec!["request_log_202607".to_string()]
        );
    }

    #[test]
    fn recognizes_bounded_mysql_connector_initialization_queries() {
        let connector_comment = "/* mysql-connector-java-5.1.10 ( Revision: ${svn.Revision} ) */";
        for sql in [
            "SHOW COLLATION",
            "SHOW WARNINGS",
            "SELECT @@session.tx_isolation",
            &format!("{connector_comment}SELECT @@session.auto_increment_increment"),
            &format!(
                "{connector_comment}SHOW VARIABLES WHERE Variable_name = 'character_set_client' \
                 OR Variable_name = 'transaction_isolation' \
                 OR Variable_name = 'max_allowed_packet'"
            ),
        ] {
            assert!(
                is_successful_mysql_session_setup("COM_QUERY", Some(sql), "resultset", 9),
                "{sql}"
            );
            assert!(
                !is_successful_mysql_session_setup("COM_QUERY", Some(sql), "resultset", 10),
                "{sql}"
            );
        }
        assert!(!is_successful_mysql_session_setup(
            "COM_QUERY",
            Some("SET autocommit=1"),
            "ok",
            20
        ));
        for sql in [
            "SET sql_mode='NO_AUTO_CREATE_USER,STRICT_TRANS_TABLES'",
            "SET sql_mode = 'STRICT_TRANS_TABLES'",
        ] {
            assert!(is_successful_mysql_session_setup(
                "COM_QUERY",
                Some(sql),
                "ok",
                20
            ));
        }
        assert!(!is_successful_mysql_session_setup(
            "COM_QUERY",
            Some("SET sql_mode_override = 'STRICT_TRANS_TABLES'"),
            "ok",
            20
        ));
        assert!(!is_successful_mysql_session_setup(
            "COM_QUERY",
            Some("SELECT 3"),
            "resultset",
            1
        ));
    }
}
