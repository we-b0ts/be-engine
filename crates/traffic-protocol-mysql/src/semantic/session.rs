//! Native prepared statements and response semantics, independent of capture lifetime.
use super::*;
use crate::{ClientCommand, MysqlPacket};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SemanticRequest {
    pub command: String,
    pub sql: Option<String>,
    pub statement_id: Option<u32>,
    pub params: Option<Vec<MysqlValue>>,
    pub packets: Vec<MysqlPacket>,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SemanticSession {
    statements: HashMap<u32, PreparedStatement>,
    max_value_bytes: usize,
    last_status: Option<(Uuid, u64, u16)>,
}

impl SemanticSession {
    pub fn new(max_value_bytes: usize) -> Self {
        Self {
            statements: HashMap::new(),
            max_value_bytes,
            last_status: None,
        }
    }
    pub fn start_request(
        &mut self,
        command: &ClientCommand,
        packet: &MysqlPacket,
    ) -> SemanticRequest {
        let (statement_id, params, sql, mut parse_warnings) =
            self.parse_client_input(command, packet);
        parse_warnings.shrink_to_fit();
        SemanticRequest {
            command: command.command_name.clone(),
            sql: sql.or_else(|| command.query.clone()),
            statement_id,
            params,
            packets: Vec::new(),
            parse_warnings,
        }
    }
    pub fn observe_no_response(&mut self, command: &ClientCommand, packet: &MysqlPacket) {
        self.last_status = None;
        if command.command_name == "COM_STMT_CLOSE"
            && let Some(statement_id) = read_u32_le(&packet.payload, 1)
        {
            self.statements.remove(&statement_id);
        }
    }
    pub fn prepared_sql(&self, statement_id: u32) -> Option<&str> {
        self.statements
            .get(&statement_id)
            .map(|statement| statement.sql.as_str())
    }
    pub fn prepared_sql_for_packet(&self, packet: &MysqlPacket) -> Option<&str> {
        self.prepared_sql(read_u32_le(&packet.payload, 1)?)
    }
    pub fn confirm_status(
        &mut self,
        connection_id: Uuid,
        query_sequence: u64,
        request: &SemanticRequest,
        response: &MysqlExchangeResponse,
    ) -> Option<u16> {
        let previous = self.last_status.and_then(|(connection, sequence, flags)| {
            (connection == connection_id && sequence.checked_add(1) == Some(query_sequence))
                .then_some(flags)
        });
        let confirmed = if request.parse_warnings.is_empty()
            && response.error_code.is_none()
            && response.error_message.is_none()
        {
            match response.status.as_str() {
                "ok" | "resultset" => response.server_status.filter(|flags| flags & 8 == 0),
                "stmt_prepare" if request.command == "COM_STMT_PREPARE" => previous,
                _ => None,
            }
        } else {
            None
        };
        self.last_status = confirmed.map(|flags| (connection_id, query_sequence, flags));
        previous
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

    pub fn parse_response(
        &mut self,
        active: &mut SemanticRequest,
        status: &str,
        error_code: Option<u16>,
        error_message: Option<String>,
    ) -> MysqlExchangeResponse {
        let mut response = MysqlExchangeResponse {
            wire_prefix: Vec::new(),
            server_status: None,
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
            if !matches!(status, "client_terminated" | "server_terminated") {
                active
                    .parse_warnings
                    .push("no server response packets were captured".to_string());
            }
            return response;
        }

        match status {
            "ok" => {
                if let Some(ok) = parse_ok_packet(&active.packets[0].payload) {
                    response.server_status = ok.server_status;
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
            "error" | "eof" | "incomplete" | "client_terminated" | "server_terminated" => {}
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
        active: &mut SemanticRequest,
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
                    parameters: params,
                    columns,
                    last_param_types: Vec::new(),
                },
            );
        }
    }
}
