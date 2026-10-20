//! Borrowed request-side facts reuse the configured protocol selector contracts.
use serde_json::{Value, json};
use uuid::Uuid;

use crate::config::BackgroundDependencyRuleConfig;
use crate::recorder::MysqlExchangeEvent;

#[derive(Clone, Copy)]
pub(crate) enum DependencyRequest<'a> {
    Redis {
        target_port: u16,
        command: &'a str,
        args: &'a [Vec<u8>],
    },
    Mysql {
        connection_id: Uuid,
        target_host: Option<&'a str>,
        target_port: Option<u16>,
        database: Option<&'a str>,
        username: Option<&'a str>,
        command: &'a str,
        sql: Option<&'a str>,
    },
}

pub(super) fn identity(
    rule: &BackgroundDependencyRuleConfig,
    request: &DependencyRequest<'_>,
) -> Option<String> {
    match request {
        DependencyRequest::Redis {
            target_port,
            command,
            args,
        } => crate::config::api_trigger::redis_identity(rule, *target_port, command, args),
        DependencyRequest::Mysql {
            target_host,
            target_port,
            database,
            username,
            command,
            sql,
            ..
        } => crate::config::api_trigger::mysql::identity(
            rule,
            &json!({
                "event_type": "mysql_exchange",
                "target_host": target_host,
                "target_port": target_port,
                "database": database,
                "username": username,
                "command": command,
                "sql": sql,
            }),
        ),
    }
}

pub(super) fn mysql_request(exchange: &MysqlExchangeEvent) -> DependencyRequest<'_> {
    DependencyRequest::Mysql {
        connection_id: exchange.connection_id,
        target_host: exchange.target_host.as_deref(),
        target_port: exchange.target_port,
        database: exchange.database.as_deref(),
        username: exchange.username.as_deref(),
        command: &exchange.command,
        sql: exchange.sql.as_deref(),
    }
}

pub(super) fn capture_value(exchange: &MysqlExchangeEvent) -> Value {
    // INSERT capture never requires response rows or any other payload oracle.
    json!({
        "event_type": "mysql_exchange",
        "target_host": exchange.target_host,
        "target_port": exchange.target_port,
        "database": exchange.database,
        "username": exchange.username,
        "command": exchange.command,
        "sql": exchange.sql,
        "outcome": exchange.outcome,
        "parse_warnings": exchange.parse_warnings,
        "response": {
            "status": exchange.response.status,
            "affected_rows": exchange.response.affected_rows,
        },
    })
}
