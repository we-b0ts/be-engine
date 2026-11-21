//! Native MySQL observation/control classification.
use crate::maintenance::is_mysql_maintenance_exchange;
use serde_json::Value;
use traffic_model::DependencyExchangeOutcome;

fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}
fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}
fn outcome(value: &Value) -> Option<DependencyExchangeOutcome> {
    serde_json::from_value(value.get("outcome")?.clone()).ok()
}

pub fn is_debug_only_mysql_exchange(exchange: &crate::events::MysqlExchangeEvent) -> bool {
    if exchange.outcome != DependencyExchangeOutcome::Response {
        return false;
    }
    (is_mysql_maintenance_exchange(exchange.command.as_str(), exchange.sql.as_deref())
        && (exchange.command != "COM_PING" || exchange.response.status == "ok"))
        || is_successful_stmt_prepare(exchange)
        || is_successful_mysql_session_setup(
            exchange.command.as_str(),
            exchange.sql.as_deref(),
            exchange.response.status.as_str(),
            exchange.query_sequence,
        )
}

fn is_successful_stmt_prepare(exchange: &crate::events::MysqlExchangeEvent) -> bool {
    exchange.command == "COM_STMT_PREPARE" && exchange.response.status == "stmt_prepare"
}

pub fn is_debug_only_mysql_exchange_value(value: &Value) -> bool {
    if outcome(value).is_some_and(|outcome| outcome != DependencyExchangeOutcome::Response) {
        return false;
    }
    (is_mysql_maintenance_exchange(
        json_str(value, "command").unwrap_or_default(),
        json_str(value, "sql"),
    ) && (value["command"] != "COM_PING" || value["response"]["status"] == "ok"))
        || is_successful_stmt_prepare_value(value)
        || is_successful_mysql_session_setup(
            json_str(value, "command").unwrap_or_default(),
            json_str(value, "sql"),
            value
                .get("response")
                .and_then(|response| json_str(response, "status"))
                .unwrap_or_default(),
            json_u64(value, "query_sequence").unwrap_or_default(),
        )
}

fn is_successful_stmt_prepare_value(value: &Value) -> bool {
    json_str(value, "command") == Some("COM_STMT_PREPARE")
        && value
            .get("response")
            .and_then(|response| json_str(response, "status"))
            == Some("stmt_prepare")
}

pub fn is_successful_mysql_session_setup(
    command: &str,
    sql: Option<&str>,
    status: &str,
    query_sequence: u64,
) -> bool {
    command == "COM_QUERY"
        && matches!(status, "ok" | "resultset")
        && sql.is_some_and(|sql| {
            is_mysql_session_setup_sql(sql)
                || (query_sequence <= 9 && is_mysql_connector_initialization_sql(sql))
        })
}

fn is_mysql_session_setup_sql(sql: &str) -> bool {
    let normalized = normalize_mysql_control_sql(sql);
    // Preserve transaction controls, including compound/unsupported SET forms.
    // Replay needs the full exchange and surrounding session evidence.
    if normalized.contains("autocommit")
        && crate::sql::tokens(sql).is_none_or(|tokens| {
            tokens.iter().any(|token| token.is("autocommit")
                || matches!(token, crate::sql::Token::Identifier(name) if name.eq_ignore_ascii_case("autocommit")))
        })
    {
        return false;
    }
    normalized.starts_with("set names ")
        || normalized.starts_with("set character set ")
        || normalized.starts_with("set character_set_client ")
        || normalized.starts_with("set character_set_connection ")
        || normalized.starts_with("set character_set_results ")
        || normalized.starts_with("set collation_connection ")
        || normalized.starts_with("set time_zone ")
        || is_mysql_set_assignment(&normalized, "sql_mode")
}

fn is_mysql_set_assignment(sql: &str, variable: &str) -> bool {
    sql.strip_prefix("set ")
        .and_then(|remainder| remainder.strip_prefix(variable))
        .and_then(|remainder| remainder.chars().next())
        .is_some_and(|separator| separator == '=' || separator.is_whitespace())
}

fn is_mysql_connector_initialization_sql(sql: &str) -> bool {
    let normalized = normalize_mysql_control_sql(sql);
    let normalized = strip_leading_mysql_comment(&normalized);
    normalized == "show collation"
        || normalized == "show warnings"
        || matches!(
            normalized,
            "select @@session.auto_increment_increment"
                | "select @@session.tx_isolation"
                | "select @@session.transaction_isolation"
        )
        || (normalized.starts_with("show variables where ")
            && normalized.contains("variable_name")
            && normalized.contains("character_set_client")
            && normalized.contains("transaction_isolation")
            && normalized.contains("max_allowed_packet"))
}

fn strip_leading_mysql_comment(sql: &str) -> &str {
    let Some(comment) = sql.strip_prefix("/*") else {
        return sql;
    };
    comment
        .split_once("*/")
        .map(|(_, remainder)| remainder.trim_start())
        .unwrap_or(sql)
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
