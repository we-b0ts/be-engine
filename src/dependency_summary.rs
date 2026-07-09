use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::recorder::RecorderEvent;

pub(crate) fn should_append_case_dependency(event: &RecorderEvent) -> bool {
    !matches!(event, RecorderEvent::MysqlExchange(exchange) if is_debug_only_mysql_exchange(exchange))
}

pub(crate) async fn write_case_dependency_summary(dir: &Path) -> Result<()> {
    write_dependency_summary(dir, "dependencies.jsonl", "dependencies-summary.json").await
}

pub(crate) async fn write_bootstrap_dependency_summary(dir: &Path) -> Result<()> {
    write_dependency_summary(
        dir,
        "bootstrap-dependencies.jsonl",
        "bootstrap-dependencies-summary.json",
    )
    .await
}

async fn write_dependency_summary(
    dir: &Path,
    dependencies_filename: &str,
    summary_filename: &str,
) -> Result<()> {
    let dependencies_path = dir.join(dependencies_filename);
    let raw = match tokio::fs::read_to_string(&dependencies_path).await {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to read dependencies file {}",
                    dependencies_path.display()
                )
            });
        }
    };
    let summary = build_dependency_summary(&raw);
    let mut payload =
        serde_json::to_vec_pretty(&summary).context("failed to serialize dependency summary")?;
    payload.push(b'\n');
    let summary_path = dir.join(summary_filename);
    tokio::fs::write(&summary_path, payload)
        .await
        .with_context(|| {
            format!(
                "failed to write dependency summary {}",
                summary_path.display()
            )
        })
}

#[derive(Debug, Serialize)]
struct DependencySummary {
    version: u8,
    source: &'static str,
    total_events: usize,
    event_types: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parse_errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mysql: Option<MysqlDependencySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http: Option<HttpDependencySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_gateway: Option<TcpGatewayDependencySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_errors: Option<ProxyErrorSummary>,
}

#[derive(Default)]
struct DependencySummaryBuilder {
    total_events: usize,
    event_types: BTreeMap<String, usize>,
    parse_errors: Vec<String>,
    mysql: MysqlDependencySummary,
    http: HttpDependencySummary,
    tcp_gateway: TcpGatewayDependencySummary,
    proxy_errors: ProxyErrorSummary,
}

impl DependencySummaryBuilder {
    fn finish(self) -> DependencySummary {
        DependencySummary {
            version: 1,
            source: "dependencies.jsonl",
            total_events: self.total_events,
            event_types: self.event_types,
            parse_errors: self.parse_errors,
            mysql: self.mysql.has_activity().then_some(self.mysql),
            http: (self.http.calls > 0).then_some(self.http),
            tcp_gateway: (self.tcp_gateway.connections > 0).then_some(self.tcp_gateway),
            proxy_errors: (self.proxy_errors.total > 0).then_some(self.proxy_errors),
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct MysqlDependencySummary {
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

#[derive(Debug, Default, Serialize)]
struct HttpDependencySummary {
    calls: usize,
    methods: BTreeMap<String, usize>,
    authorities: BTreeMap<String, usize>,
    status_codes: BTreeMap<String, usize>,
    errors: usize,
}

#[derive(Debug, Default, Serialize)]
struct TcpGatewayDependencySummary {
    connections: usize,
    domains: BTreeMap<String, usize>,
    upstreams: BTreeMap<String, usize>,
    errors: usize,
}

#[derive(Debug, Default, Serialize)]
struct ProxyErrorSummary {
    total: usize,
    protocols: BTreeMap<String, usize>,
    targets: BTreeMap<String, usize>,
}

fn build_dependency_summary(raw_jsonl: &str) -> DependencySummary {
    let mut builder = DependencySummaryBuilder::default();
    for (line_index, line) in raw_jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(err) => {
                builder
                    .parse_errors
                    .push(format!("line {}: {err}", line_index + 1));
                continue;
            }
        };
        let event_type = value
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        if event_type == "mysql_exchange" && is_debug_only_mysql_exchange_value(&value) {
            continue;
        }
        builder.total_events += 1;
        *builder.event_types.entry(event_type.clone()).or_default() += 1;
        match event_type.as_str() {
            "mysql_connection" => record_mysql_connection_summary(&mut builder.mysql, &value),
            "mysql_exchange" => record_mysql_summary(&mut builder.mysql, &value),
            "mysql_tls_rejected" => record_mysql_tls_rejected_summary(&mut builder.mysql, &value),
            "http_exchange" => record_http_summary(&mut builder.http, &value),
            "tcp_gateway_connection" => {
                record_tcp_gateway_summary(&mut builder.tcp_gateway, &value);
            }
            "proxy_error" => record_proxy_error_summary(&mut builder.proxy_errors, &value),
            _ => {}
        }
    }
    builder.finish()
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
    let failed = status
        .as_deref()
        .is_some_and(|status| status == "error" || status == "incomplete")
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

fn record_http_summary(summary: &mut HttpDependencySummary, value: &Value) {
    summary.calls += 1;
    if let Some(method) = json_str(value, "method") {
        *summary
            .methods
            .entry(method.to_ascii_uppercase())
            .or_default() += 1;
    }
    if let Some(authority) = json_str(value, "authority") {
        *summary
            .authorities
            .entry(authority.to_string())
            .or_default() += 1;
    }
    if let Some(status) = json_u64(value, "response_status") {
        *summary.status_codes.entry(status.to_string()).or_default() += 1;
    }
    if value.get("error").is_some_and(|error| !error.is_null()) {
        summary.errors += 1;
    }
}

fn record_tcp_gateway_summary(summary: &mut TcpGatewayDependencySummary, value: &Value) {
    summary.connections += 1;
    if let Some(domain) = json_str(value, "domain") {
        *summary.domains.entry(domain.to_string()).or_default() += 1;
    }
    if let Some(upstream) = json_str(value, "upstream_addr") {
        *summary.upstreams.entry(upstream.to_string()).or_default() += 1;
    }
    if value.get("error").is_some_and(|error| !error.is_null()) {
        summary.errors += 1;
    }
}

fn record_proxy_error_summary(summary: &mut ProxyErrorSummary, value: &Value) {
    summary.total += 1;
    if let Some(protocol) = json_str(value, "protocol") {
        *summary.protocols.entry(protocol.to_string()).or_default() += 1;
    }
    if let Some(target) = json_str(value, "target") {
        *summary.targets.entry(target.to_string()).or_default() += 1;
    }
}

fn is_debug_only_mysql_exchange(exchange: &crate::recorder_event::MysqlExchangeEvent) -> bool {
    is_successful_stmt_prepare(exchange)
        || is_successful_mysql_session_setup(
            exchange.command.as_str(),
            exchange.sql.as_deref(),
            exchange.response.status.as_str(),
        )
}

fn is_successful_stmt_prepare(exchange: &crate::recorder_event::MysqlExchangeEvent) -> bool {
    exchange.command == "COM_STMT_PREPARE" && exchange.response.status == "stmt_prepare"
}

fn is_debug_only_mysql_exchange_value(value: &Value) -> bool {
    is_successful_stmt_prepare_value(value)
        || is_successful_mysql_session_setup(
            json_str(value, "command").unwrap_or_default(),
            json_str(value, "sql"),
            value
                .get("response")
                .and_then(|response| json_str(response, "status"))
                .unwrap_or_default(),
        )
}

fn is_successful_stmt_prepare_value(value: &Value) -> bool {
    json_str(value, "command") == Some("COM_STMT_PREPARE")
        && value
            .get("response")
            .and_then(|response| json_str(response, "status"))
            == Some("stmt_prepare")
}

fn is_successful_mysql_session_setup(command: &str, sql: Option<&str>, status: &str) -> bool {
    command == "COM_QUERY" && status == "ok" && sql.is_some_and(is_mysql_session_setup_sql)
}

fn is_mysql_session_setup_sql(sql: &str) -> bool {
    let normalized = normalize_mysql_control_sql(sql);
    normalized.starts_with("set names ")
        || normalized.starts_with("set character set ")
        || normalized.starts_with("set character_set_client ")
        || normalized.starts_with("set character_set_connection ")
        || normalized.starts_with("set character_set_results ")
        || normalized.starts_with("set collation_connection ")
        || normalized.starts_with("set time_zone ")
        || normalized.starts_with("set sql_mode ")
}

fn normalize_mysql_control_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut last_was_space = false;
    for ch in sql.chars() {
        let ch = if ch == '`' { continue } else { ch };
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(ch.to_ascii_lowercase());
            last_was_space = false;
        }
    }
    out.trim().to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn dependency_summary_omits_successful_stmt_prepare_lines() {
        let raw = r#"{"event_type":"mysql_exchange","command":"COM_STMT_PREPARE","response":{"status":"stmt_prepare"}}
{"event_type":"mysql_exchange","command":"COM_STMT_EXECUTE","sql":"SELECT * FROM `user`","response":{"status":"resultset","row_count":0,"columns":[]}}"#;
        let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

        assert_eq!(summary["total_events"], 1);
        assert_eq!(summary["event_types"]["mysql_exchange"], 1);
        assert_eq!(summary["mysql"]["semantic_exchanges"], 1);
        assert_eq!(summary["mysql"]["executed"]["crud"]["select"], 1);
    }

    #[test]
    fn dependency_summary_omits_successful_mysql_session_setup_lines() {
        let raw = r#"{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SET NAMES utf8","response":{"status":"ok","affected_rows":0,"last_insert_id":0}}
{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SET @tenant_id = 1","response":{"status":"ok","affected_rows":0,"last_insert_id":0}}
{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SELECT * FROM `user`","response":{"status":"resultset","row_count":0,"columns":[]}}"#;
        let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

        assert_eq!(summary["total_events"], 2);
        assert_eq!(summary["event_types"]["mysql_exchange"], 2);
        assert_eq!(summary["mysql"]["semantic_exchanges"], 2);
        assert_eq!(summary["mysql"]["executed"]["crud"]["select"], 1);
        assert_eq!(summary["mysql"]["executed"]["crud"]["other"], 1);
    }

    #[test]
    fn dependency_summary_includes_mysql_connection_and_tls_rejection() {
        let raw = r#"{"event_type":"mysql_connection","route_name":"pluto","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","username":"root","database":"pluto","upstream_addr":"127.0.0.1:3306","error":null}
{"event_type":"mysql_tls_rejected","route_name":"pluto","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","upstream_addr":"127.0.0.1:3306","reason":"CLIENT_SSL is unsupported"}"#;
        let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

        assert_eq!(summary["total_events"], 2);
        assert_eq!(summary["event_types"]["mysql_connection"], 1);
        assert_eq!(summary["event_types"]["mysql_tls_rejected"], 1);
        assert_eq!(summary["mysql"]["connections"], 1);
        assert_eq!(summary["mysql"]["tls_rejected"], 1);
        assert_eq!(summary["mysql"]["routes"]["pluto"], 2);
        assert_eq!(summary["mysql"]["target_hosts"]["mysql.internal"], 2);
        assert_eq!(summary["mysql"]["target_addrs"]["mysql.internal:3306"], 2);
        assert_eq!(summary["mysql"]["databases"]["pluto"], 1);
        assert_eq!(summary["mysql"]["users"]["root"], 1);
        assert_eq!(summary["mysql"]["upstreams"]["127.0.0.1:3306"], 2);
        assert_eq!(
            summary["mysql"]["tls_rejection_reasons"]["CLIENT_SSL is unsupported"],
            1
        );
    }
}
