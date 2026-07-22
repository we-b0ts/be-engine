use std::collections::HashMap;
use std::time::Instant;

use chrono::Utc;
use serde_json::{Number, Value};
use uuid::Uuid;

use crate::DependencyExchangeOutcome;
use crate::mysql::wire::{ClientCommand, MysqlPacket};
use crate::recorder::{
    MysqlColumn, MysqlExchangeEvent, MysqlExchangeResponse, MysqlResponseEvent, MysqlValue,
    ProcessInfo, capture_body,
};

mod decode;
#[cfg(test)]
mod tests;

use decode::*;

const MYSQL_TYPE_DECIMAL: u8 = 0;
const MYSQL_TYPE_TINY: u8 = 1;
const MYSQL_TYPE_SHORT: u8 = 2;
const MYSQL_TYPE_LONG: u8 = 3;
const MYSQL_TYPE_FLOAT: u8 = 4;
const MYSQL_TYPE_DOUBLE: u8 = 5;
const MYSQL_TYPE_NULL: u8 = 6;
const MYSQL_TYPE_TIMESTAMP: u8 = 7;
const MYSQL_TYPE_LONGLONG: u8 = 8;
const MYSQL_TYPE_INT24: u8 = 9;
const MYSQL_TYPE_DATE: u8 = 10;
const MYSQL_TYPE_TIME: u8 = 11;
const MYSQL_TYPE_DATETIME: u8 = 12;
const MYSQL_TYPE_YEAR: u8 = 13;
const MYSQL_TYPE_NEWDATE: u8 = 14;
const MYSQL_TYPE_VARCHAR: u8 = 15;
const MYSQL_TYPE_BIT: u8 = 16;
const MYSQL_TYPE_JSON: u8 = 245;
const MYSQL_TYPE_NEWDECIMAL: u8 = 246;
const MYSQL_TYPE_ENUM: u8 = 247;
const MYSQL_TYPE_SET: u8 = 248;
const MYSQL_TYPE_TINY_BLOB: u8 = 249;
const MYSQL_TYPE_MEDIUM_BLOB: u8 = 250;
const MYSQL_TYPE_LONG_BLOB: u8 = 251;
const MYSQL_TYPE_BLOB: u8 = 252;
const MYSQL_TYPE_VAR_STRING: u8 = 253;
const MYSQL_TYPE_STRING: u8 = 254;
const MYSQL_TYPE_GEOMETRY: u8 = 255;

const MYSQL_FLAG_NOT_NULL: u16 = 0x0001;
const MYSQL_FLAG_UNSIGNED: u16 = 0x0020;
const MYSQL_FLAG_BINARY: u16 = 0x0080;

const MYSQL_CHARSET_BINARY: u16 = 63;

#[derive(Debug, Clone)]
pub(crate) struct MysqlSemanticTracker {
    statements: HashMap<u32, PreparedStatement>,
    active: Option<ActiveExchange>,
    max_value_bytes: usize,
    context: MysqlExchangeContext,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MysqlExchangeContext {
    pub route_name: Option<String>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub target_addr: Option<String>,
    pub upstream_addr: Option<String>,
    pub username: Option<String>,
    pub database: Option<String>,
}

#[derive(Debug, Clone)]
struct PreparedStatement {
    statement_id: u32,
    sql: String,
    param_count: usize,
    _params: Vec<MysqlColumn>,
    _columns: Vec<MysqlColumn>,
    last_param_types: Vec<BoundParamType>,
}

#[derive(Debug, Clone)]
struct BoundParamType {
    type_code: u8,
    unsigned: bool,
}

#[derive(Debug, Clone)]
struct ActiveExchange {
    connection_id: Uuid,
    query_sequence: u64,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    command: String,
    sql: Option<String>,
    statement_id: Option<u32>,
    params: Option<Vec<MysqlValue>>,
    started: Instant,
    packets: Vec<MysqlPacket>,
    parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowProtocol {
    Text,
    Binary,
}

impl MysqlSemanticTracker {
    pub(crate) fn new(max_value_bytes: usize, context: MysqlExchangeContext) -> Self {
        Self {
            statements: HashMap::new(),
            active: None,
            max_value_bytes,
            context,
        }
    }

    pub(crate) fn start_query(
        &mut self,
        connection_id: Uuid,
        query_sequence: u64,
        command: &ClientCommand,
        packet: &MysqlPacket,
        client_addr: Option<String>,
        client_process: Option<ProcessInfo>,
    ) -> Option<MysqlExchangeEvent> {
        let previous = self.finish_active("incomplete", None, None, None);
        let (statement_id, params, sql, mut parse_warnings) =
            self.parse_client_input(command, packet);
        self.active = Some(ActiveExchange {
            connection_id,
            query_sequence,
            client_addr,
            client_process,
            command: command.command_name.clone(),
            sql: sql.or_else(|| command.query.clone()),
            statement_id,
            params,
            started: Instant::now(),
            packets: Vec::new(),
            parse_warnings: {
                parse_warnings.shrink_to_fit();
                parse_warnings
            },
        });
        previous
    }

    pub(crate) fn observe_no_response_command(
        &mut self,
        command: &ClientCommand,
        packet: &MysqlPacket,
    ) -> Option<MysqlExchangeEvent> {
        let previous = self.finish_active("incomplete", None, None, None);
        if command.command_name == "COM_STMT_CLOSE"
            && let Some(statement_id) = read_u32_le(&packet.payload, 1)
        {
            self.statements.remove(&statement_id);
        }
        previous
    }

    pub(crate) fn observe_packet(&mut self, packet: &MysqlPacket) {
        if let Some(active) = &mut self.active {
            active.packets.push(packet.clone());
        }
    }

    pub(crate) fn database(&self) -> Option<&str> {
        self.context.database.as_deref()
    }

    pub(crate) fn prepared_sql_for_packet(&self, packet: &MysqlPacket) -> Option<&str> {
        let statement_id = read_u32_le(&packet.payload, 1)?;
        self.statements
            .get(&statement_id)
            .map(|statement| statement.sql.as_str())
    }

    pub(crate) fn finish_from_response(
        &mut self,
        response: &MysqlResponseEvent,
    ) -> Option<MysqlExchangeEvent> {
        let confirmed_database = (response.status == "ok")
            .then_some(self.active.as_ref())
            .flatten()
            .filter(|active| active.command == "COM_INIT_DB")
            .and_then(|active| active.sql.clone());
        let exchange = self.finish_active(
            &response.status,
            response.error_code,
            response.error_message.clone(),
            Some(response.duration_ms),
        );
        if let Some(database) = confirmed_database {
            self.context.database = Some(database);
        }
        exchange
    }

    pub(crate) fn finish_active(
        &mut self,
        fallback_status: &str,
        error_code: Option<u16>,
        error_message: Option<String>,
        duration_ms: Option<u128>,
    ) -> Option<MysqlExchangeEvent> {
        let mut active = self.active.take()?;
        let status = fallback_status.to_string();
        let response = self.parse_response(&mut active, &status, error_code, error_message);
        Some(MysqlExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: active.connection_id,
            query_sequence: active.query_sequence,
            timestamp: Utc::now(),
            client_addr: active.client_addr,
            client_process: active.client_process,
            route_name: self.context.route_name.clone(),
            target_host: self.context.target_host.clone(),
            target_port: self.context.target_port,
            target_addr: self.context.target_addr.clone(),
            upstream_addr: self.context.upstream_addr.clone(),
            username: self.context.username.clone(),
            database: self.context.database.clone(),
            command: active.command,
            sql: active.sql,
            statement_id: active.statement_id,
            params: active.params,
            response,
            outcome: if fallback_status == "client_terminated" {
                DependencyExchangeOutcome::ClientTerminated
            } else {
                DependencyExchangeOutcome::Response
            },
            duration_ms: duration_ms.unwrap_or_else(|| active.started.elapsed().as_millis()),
            parse_warnings: active.parse_warnings,
        })
    }

    fn parse_client_input(
        &mut self,
        command: &ClientCommand,
        packet: &MysqlPacket,
    ) -> (
        Option<u32>,
        Option<Vec<MysqlValue>>,
        Option<String>,
        Vec<String>,
    ) {
        if command.command_name != "COM_STMT_EXECUTE" {
            return (None, None, command.query.clone(), Vec::new());
        }

        let Some(statement_id) = read_u32_le(&packet.payload, 1) else {
            return (
                None,
                None,
                None,
                vec!["failed to parse COM_STMT_EXECUTE statement id".to_string()],
            );
        };
        let Some(statement) = self.statements.get(&statement_id).cloned() else {
            return (
                Some(statement_id),
                None,
                None,
                vec![format!(
                    "statement {statement_id} was executed before this recorder saw its prepare"
                )],
            );
        };
        let (params, param_types, warnings) =
            parse_stmt_execute_params(&packet.payload, &statement, self.max_value_bytes);
        if let Some(param_types) = param_types
            && let Some(statement) = self.statements.get_mut(&statement_id)
        {
            statement.last_param_types = param_types;
        }
        (
            Some(statement_id),
            params,
            Some(statement.sql.clone()),
            warnings,
        )
    }

    fn parse_response(
        &mut self,
        active: &mut ActiveExchange,
        status: &str,
        error_code: Option<u16>,
        error_message: Option<String>,
    ) -> MysqlExchangeResponse {
        let mut response = MysqlExchangeResponse {
            status: status.to_string(),
            error_code,
            error_message,
            affected_rows: None,
            last_insert_id: None,
            columns: Vec::new(),
            rows: Vec::new(),
            row_count: 0,
            rows_truncated: false,
        };

        if active.packets.is_empty() {
            if status != "client_terminated" {
                active
                    .parse_warnings
                    .push("no server response packets were captured".to_string());
            }
            return response;
        }

        match status {
            "ok" => {
                if let Some(ok) = parse_ok_packet(&active.packets[0].payload) {
                    response.affected_rows = Some(ok.affected_rows);
                    response.last_insert_id = Some(ok.last_insert_id);
                }
            }
            "stmt_prepare" => {
                self.parse_prepare_response(active, &mut response);
            }
            "resultset" => {
                let protocol = if active.command == "COM_STMT_EXECUTE" {
                    RowProtocol::Binary
                } else {
                    RowProtocol::Text
                };
                parse_resultset_response(
                    &active.packets,
                    protocol,
                    self.max_value_bytes,
                    &mut response,
                    &mut active.parse_warnings,
                );
            }
            "error" | "eof" | "incomplete" | "client_terminated" => {}
            _ => {
                active
                    .parse_warnings
                    .push(format!("unhandled MySQL response status {status}"));
            }
        }

        response
    }

    fn parse_prepare_response(
        &mut self,
        active: &mut ActiveExchange,
        response: &mut MysqlExchangeResponse,
    ) {
        let Some(ok) = parse_stmt_prepare_ok(&active.packets[0].payload) else {
            active
                .parse_warnings
                .push("failed to parse COM_STMT_PREPARE OK packet".to_string());
            return;
        };
        active.statement_id = Some(ok.statement_id);
        let mut index = 1;
        let mut params = Vec::new();
        for _ in 0..ok.num_params {
            let Some(packet) = active.packets.get(index) else {
                active
                    .parse_warnings
                    .push("COM_STMT_PREPARE parameter metadata ended early".to_string());
                break;
            };
            match parse_column_definition(&packet.payload) {
                Some(column) => params.push(column),
                None => active
                    .parse_warnings
                    .push("failed to parse COM_STMT_PREPARE parameter column".to_string()),
            }
            index += 1;
        }
        if ok.num_params > 0 && active.packets.get(index).is_some_and(is_eof_packet) {
            index += 1;
        }

        let mut columns = Vec::new();
        for _ in 0..ok.num_columns {
            let Some(packet) = active.packets.get(index) else {
                active
                    .parse_warnings
                    .push("COM_STMT_PREPARE result metadata ended early".to_string());
                break;
            };
            match parse_column_definition(&packet.payload) {
                Some(column) => columns.push(column),
                None => active
                    .parse_warnings
                    .push("failed to parse COM_STMT_PREPARE result column".to_string()),
            }
            index += 1;
        }

        response.columns = columns.clone();
        if let Some(sql) = &active.sql {
            self.statements.insert(
                ok.statement_id,
                PreparedStatement {
                    statement_id: ok.statement_id,
                    sql: sql.clone(),
                    param_count: ok.num_params as usize,
                    _params: params,
                    _columns: columns,
                    last_param_types: Vec::new(),
                },
            );
        }
    }
}
