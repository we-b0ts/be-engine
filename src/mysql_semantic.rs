use std::collections::HashMap;
use std::time::Instant;

use chrono::Utc;
use serde_json::{Number, Value};
use uuid::Uuid;

use crate::mysql_protocol::{ClientCommand, MysqlPacket};
use crate::recorder::{
    MysqlColumn, MysqlExchangeEvent, MysqlExchangeResponse, MysqlResponseEvent, MysqlValue,
    ProcessInfo, capture_body,
};

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

    pub(crate) fn observe_packet(&mut self, packet: &MysqlPacket) {
        if let Some(active) = &mut self.active {
            active.packets.push(packet.clone());
        }
    }

    pub(crate) fn set_database(&mut self, database: Option<String>) {
        self.context.database = database;
    }

    pub(crate) fn finish_from_response(
        &mut self,
        response: &MysqlResponseEvent,
    ) -> Option<MysqlExchangeEvent> {
        self.finish_active(
            &response.status,
            response.error_code,
            response.error_message.clone(),
            Some(response.duration_ms),
        )
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
            active
                .parse_warnings
                .push("no server response packets were captured".to_string());
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
            "error" | "eof" | "incomplete" => {}
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

#[derive(Debug, Clone, Copy)]
struct OkPacket {
    affected_rows: u64,
    last_insert_id: u64,
}

#[derive(Debug, Clone, Copy)]
struct PrepareOkPacket {
    statement_id: u32,
    num_columns: u16,
    num_params: u16,
}

fn parse_stmt_execute_params(
    payload: &[u8],
    statement: &PreparedStatement,
    max_value_bytes: usize,
) -> (
    Option<Vec<MysqlValue>>,
    Option<Vec<BoundParamType>>,
    Vec<String>,
) {
    let mut warnings = Vec::new();
    let param_count = statement.param_count;
    if param_count == 0 {
        return (Some(Vec::new()), Some(Vec::new()), warnings);
    }
    if payload.len() < 11 {
        return (
            None,
            None,
            vec!["COM_STMT_EXECUTE packet too short for parameter metadata".to_string()],
        );
    }
    let bitmap_offset = 10;
    let bitmap_len = param_count.div_ceil(8);
    let Some(null_bitmap) = payload.get(bitmap_offset..bitmap_offset + bitmap_len) else {
        return (
            None,
            None,
            vec!["COM_STMT_EXECUTE packet missing parameter null bitmap".to_string()],
        );
    };
    let mut offset = bitmap_offset + bitmap_len;
    let Some(new_params_bound_flag) = payload.get(offset).copied() else {
        return (
            None,
            None,
            vec!["COM_STMT_EXECUTE packet missing new-params-bound flag".to_string()],
        );
    };
    offset += 1;

    let mut param_types = if new_params_bound_flag == 1 {
        let mut param_types = Vec::with_capacity(param_count);
        for _ in 0..param_count {
            let Some(type_code) = payload.get(offset).copied() else {
                warnings.push("COM_STMT_EXECUTE packet ended inside parameter types".to_string());
                return (None, None, warnings);
            };
            let Some(flags) = payload.get(offset + 1).copied() else {
                warnings.push("COM_STMT_EXECUTE packet ended inside parameter flags".to_string());
                return (None, None, warnings);
            };
            param_types.push(BoundParamType {
                type_code,
                unsigned: flags & 0x80 != 0,
            });
            offset += 2;
        }
        Some(param_types)
    } else if statement.last_param_types.len() == param_count {
        Some(statement.last_param_types.clone())
    } else {
        warnings.push(format!(
            "COM_STMT_EXECUTE for statement {} reused parameter types that were not captured",
            statement.statement_id
        ));
        None
    };

    let Some(types) = param_types.as_ref() else {
        return (None, None, warnings);
    };
    let mut params = Vec::with_capacity(param_count);
    for (index, param_type) in types.iter().enumerate() {
        if null_bitmap_bit(null_bitmap, index) {
            params.push(mysql_null());
            continue;
        }
        match parse_binary_value(
            payload,
            offset,
            param_type.type_code,
            param_type.unsigned,
            false,
            max_value_bytes,
        ) {
            Some((value, next)) => {
                params.push(value);
                offset = next;
            }
            None => {
                warnings.push(format!(
                    "failed to parse COM_STMT_EXECUTE parameter {index}"
                ));
                params.push(mysql_raw(
                    payload.get(offset..).unwrap_or_default(),
                    max_value_bytes,
                ));
                offset = payload.len();
            }
        }
    }
    if let Some(types) = &mut param_types {
        types.shrink_to_fit();
    }
    (Some(params), param_types, warnings)
}

fn parse_resultset_response(
    packets: &[MysqlPacket],
    protocol: RowProtocol,
    max_value_bytes: usize,
    response: &mut MysqlExchangeResponse,
    warnings: &mut Vec<String>,
) {
    let Some((column_count, _)) = read_lenenc_int(&packets[0].payload, 0) else {
        warnings.push("failed to parse resultset column count".to_string());
        return;
    };
    let column_count = column_count as usize;
    let mut index = 1;
    let mut columns = Vec::with_capacity(column_count);
    for _ in 0..column_count {
        let Some(packet) = packets.get(index) else {
            warnings.push("resultset column definitions ended early".to_string());
            break;
        };
        match parse_column_definition(&packet.payload) {
            Some(column) => columns.push(column),
            None => warnings.push("failed to parse resultset column definition".to_string()),
        }
        index += 1;
    }
    if packets.get(index).is_some_and(is_eof_packet) {
        index += 1;
    }

    let mut rows = Vec::new();
    while let Some(packet) = packets.get(index) {
        if is_eof_packet(packet) {
            break;
        }
        let row = match protocol {
            RowProtocol::Text => parse_text_row(&packet.payload, &columns, max_value_bytes),
            RowProtocol::Binary => parse_binary_row(&packet.payload, &columns, max_value_bytes),
        };
        match row {
            Some(row) => rows.push(row),
            None => warnings.push(format!(
                "failed to parse resultset row packet at index {index}"
            )),
        }
        index += 1;
    }

    response.columns = columns;
    response.row_count = rows.len();
    response.rows = rows;
}

fn parse_text_row(
    payload: &[u8],
    columns: &[MysqlColumn],
    max_value_bytes: usize,
) -> Option<Vec<MysqlValue>> {
    let mut offset = 0;
    let mut row = Vec::with_capacity(columns.len());
    for column in columns {
        if payload.get(offset) == Some(&0xfb) {
            row.push(mysql_null());
            offset += 1;
            continue;
        }
        let (bytes, next) = read_lenenc_bytes(payload, offset)?;
        row.push(parse_text_value(bytes, column, max_value_bytes));
        offset = next;
    }
    Some(row)
}

fn parse_binary_row(
    payload: &[u8],
    columns: &[MysqlColumn],
    max_value_bytes: usize,
) -> Option<Vec<MysqlValue>> {
    if payload.first().copied()? != 0x00 {
        return None;
    }
    let bitmap_len = (columns.len() + 7 + 2) / 8;
    let null_bitmap = payload.get(1..1 + bitmap_len)?;
    let mut offset = 1 + bitmap_len;
    let mut row = Vec::with_capacity(columns.len());
    for (index, column) in columns.iter().enumerate() {
        if null_bitmap_bit_with_offset(null_bitmap, index + 2) {
            row.push(mysql_null());
            continue;
        }
        let unsigned = column.flags.unwrap_or_default() & MYSQL_FLAG_UNSIGNED != 0;
        let (value, next) = parse_binary_value(
            payload,
            offset,
            column.column_type_code,
            unsigned,
            is_binary_column(column),
            max_value_bytes,
        )?;
        row.push(value);
        offset = next;
    }
    Some(row)
}

fn parse_text_value(bytes: &[u8], column: &MysqlColumn, max_value_bytes: usize) -> MysqlValue {
    match column.column_type_code {
        MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_LONG | MYSQL_TYPE_LONGLONG
        | MYSQL_TYPE_INT24 | MYSQL_TYPE_YEAR => {
            let text = String::from_utf8_lossy(bytes);
            if let Ok(value) = text.parse::<i64>() {
                mysql_json("integer", Value::Number(value.into()))
            } else if let Ok(value) = text.parse::<u64>() {
                mysql_json("integer", Value::Number(value.into()))
            } else {
                mysql_string(text.into_owned())
            }
        }
        MYSQL_TYPE_FLOAT | MYSQL_TYPE_DOUBLE | MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => {
            let text = String::from_utf8_lossy(bytes);
            if let Ok(value) = text.parse::<f64>()
                && let Some(number) = Number::from_f64(value)
            {
                return mysql_json("float", Value::Number(number));
            }
            mysql_string(text.into_owned())
        }
        MYSQL_TYPE_NULL => mysql_null(),
        _ => mysql_bytes_or_utf8(bytes, is_binary_column(column), max_value_bytes),
    }
}

fn parse_binary_value(
    payload: &[u8],
    offset: usize,
    type_code: u8,
    unsigned: bool,
    force_bytes: bool,
    max_value_bytes: usize,
) -> Option<(MysqlValue, usize)> {
    match type_code {
        MYSQL_TYPE_TINY => {
            let value = *payload.get(offset)?;
            let value = if unsigned {
                Value::Number((value as u64).into())
            } else {
                Value::Number((value as i8 as i64).into())
            };
            Some((mysql_json("integer", value), offset + 1))
        }
        MYSQL_TYPE_SHORT | MYSQL_TYPE_YEAR => {
            let value = read_u16_le(payload, offset)?;
            let value = if unsigned {
                Value::Number((value as u64).into())
            } else {
                Value::Number((value as i16 as i64).into())
            };
            Some((mysql_json("integer", value), offset + 2))
        }
        MYSQL_TYPE_LONG | MYSQL_TYPE_INT24 => {
            let value = read_u32_le(payload, offset)?;
            let value = if unsigned {
                Value::Number((value as u64).into())
            } else {
                Value::Number((value as i32 as i64).into())
            };
            Some((mysql_json("integer", value), offset + 4))
        }
        MYSQL_TYPE_LONGLONG => {
            let value = read_u64_le(payload, offset)?;
            let value = if unsigned {
                Value::Number(value.into())
            } else {
                Value::Number((value as i64).into())
            };
            Some((mysql_json("integer", value), offset + 8))
        }
        MYSQL_TYPE_FLOAT => {
            let value = f32::from_le_bytes(payload.get(offset..offset + 4)?.try_into().ok()?);
            let number = Number::from_f64(value as f64)?;
            Some((mysql_json("float", Value::Number(number)), offset + 4))
        }
        MYSQL_TYPE_DOUBLE => {
            let value = f64::from_le_bytes(payload.get(offset..offset + 8)?.try_into().ok()?);
            let number = Number::from_f64(value)?;
            Some((mysql_json("float", Value::Number(number)), offset + 8))
        }
        MYSQL_TYPE_NULL => Some((mysql_null(), offset)),
        MYSQL_TYPE_DATE | MYSQL_TYPE_NEWDATE | MYSQL_TYPE_DATETIME | MYSQL_TYPE_TIMESTAMP => {
            parse_binary_datetime(payload, offset).map(|(value, next)| {
                (
                    MysqlValue {
                        kind: "datetime".to_string(),
                        value: Some(Value::String(value)),
                        raw: None,
                    },
                    next,
                )
            })
        }
        MYSQL_TYPE_TIME => parse_binary_time(payload, offset).map(|(value, next)| {
            (
                MysqlValue {
                    kind: "time".to_string(),
                    value: Some(Value::String(value)),
                    raw: None,
                },
                next,
            )
        }),
        MYSQL_TYPE_DECIMAL
        | MYSQL_TYPE_NEWDECIMAL
        | MYSQL_TYPE_VARCHAR
        | MYSQL_TYPE_BIT
        | MYSQL_TYPE_JSON
        | MYSQL_TYPE_ENUM
        | MYSQL_TYPE_SET
        | MYSQL_TYPE_TINY_BLOB
        | MYSQL_TYPE_MEDIUM_BLOB
        | MYSQL_TYPE_LONG_BLOB
        | MYSQL_TYPE_BLOB
        | MYSQL_TYPE_VAR_STRING
        | MYSQL_TYPE_STRING
        | MYSQL_TYPE_GEOMETRY => {
            let (bytes, next) = read_lenenc_bytes(payload, offset)?;
            Some((
                mysql_bytes_or_utf8(bytes, force_bytes, max_value_bytes),
                next,
            ))
        }
        _ => {
            let (bytes, next) = read_lenenc_bytes(payload, offset)?;
            Some((
                mysql_bytes_or_utf8(bytes, force_bytes, max_value_bytes),
                next,
            ))
        }
    }
}

fn parse_binary_datetime(payload: &[u8], offset: usize) -> Option<(String, usize)> {
    let len = *payload.get(offset)? as usize;
    let start = offset + 1;
    match len {
        0 => Some(("0000-00-00 00:00:00".to_string(), start)),
        4 => {
            let year = read_u16_le(payload, start)?;
            let month = *payload.get(start + 2)?;
            let day = *payload.get(start + 3)?;
            Some((format!("{year:04}-{month:02}-{day:02}"), start + 4))
        }
        7 | 11 => {
            let year = read_u16_le(payload, start)?;
            let month = *payload.get(start + 2)?;
            let day = *payload.get(start + 3)?;
            let hour = *payload.get(start + 4)?;
            let minute = *payload.get(start + 5)?;
            let second = *payload.get(start + 6)?;
            if len == 11 {
                let micros = read_u32_le(payload, start + 7)?;
                Some((
                    format!(
                        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}"
                    ),
                    start + 11,
                ))
            } else {
                Some((
                    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"),
                    start + 7,
                ))
            }
        }
        _ => None,
    }
}

fn parse_binary_time(payload: &[u8], offset: usize) -> Option<(String, usize)> {
    let len = *payload.get(offset)? as usize;
    let start = offset + 1;
    match len {
        0 => Some(("00:00:00".to_string(), start)),
        8 | 12 => {
            let negative = *payload.get(start)? != 0;
            let days = read_u32_le(payload, start + 1)?;
            let hour = *payload.get(start + 5)? as u32 + days * 24;
            let minute = *payload.get(start + 6)?;
            let second = *payload.get(start + 7)?;
            let sign = if negative { "-" } else { "" };
            if len == 12 {
                let micros = read_u32_le(payload, start + 8)?;
                Some((
                    format!("{sign}{hour:02}:{minute:02}:{second:02}.{micros:06}"),
                    start + 12,
                ))
            } else {
                Some((
                    format!("{sign}{hour:02}:{minute:02}:{second:02}"),
                    start + 8,
                ))
            }
        }
        _ => None,
    }
}

fn parse_ok_packet(payload: &[u8]) -> Option<OkPacket> {
    if payload.first().copied()? != 0x00 {
        return None;
    }
    let (affected_rows, offset) = read_lenenc_int(payload, 1)?;
    let (last_insert_id, _) = read_lenenc_int(payload, offset)?;
    Some(OkPacket {
        affected_rows,
        last_insert_id,
    })
}

fn parse_stmt_prepare_ok(payload: &[u8]) -> Option<PrepareOkPacket> {
    if payload.len() < 12 || payload.first().copied()? != 0x00 {
        return None;
    }
    Some(PrepareOkPacket {
        statement_id: read_u32_le(payload, 1)?,
        num_columns: read_u16_le(payload, 5)?,
        num_params: read_u16_le(payload, 7)?,
    })
}

fn parse_column_definition(payload: &[u8]) -> Option<MysqlColumn> {
    let (_catalog, offset) = read_lenenc_string(payload, 0)?;
    let (_schema, offset) = read_lenenc_string(payload, offset)?;
    let (table, offset) = read_lenenc_string(payload, offset)?;
    let (org_table, offset) = read_lenenc_string(payload, offset)?;
    let (name, offset) = read_lenenc_string(payload, offset)?;
    let (org_name, offset) = read_lenenc_string(payload, offset)?;
    let (_, offset) = read_lenenc_int(payload, offset)?;
    let charset = read_u16_le(payload, offset)?;
    let _column_length = read_u32_le(payload, offset + 2)?;
    let column_type_code = *payload.get(offset + 6)?;
    let flags = read_u16_le(payload, offset + 7)?;
    let decimals = *payload.get(offset + 9)?;
    Some(MysqlColumn {
        name,
        table: empty_to_none(org_table).or_else(|| empty_to_none(table)),
        column: empty_to_none(org_name),
        family: mysql_column_family(column_type_code, charset, flags).to_string(),
        sql_type: mysql_sql_type_name(column_type_code, charset, flags).to_string(),
        unsigned: mysql_column_unsigned(column_type_code, flags),
        bits: mysql_column_bits(column_type_code),
        nullable: Some(flags & MYSQL_FLAG_NOT_NULL == 0),
        scale: mysql_column_scale(column_type_code, decimals),
        column_type_code,
        flags: Some(flags),
    })
}

fn is_eof_packet(packet: &MysqlPacket) -> bool {
    matches!(packet.payload.first(), Some(0xfe)) && packet.payload.len() < 9
}

fn null_bitmap_bit(bitmap: &[u8], index: usize) -> bool {
    null_bitmap_bit_with_offset(bitmap, index)
}

fn null_bitmap_bit_with_offset(bitmap: &[u8], bit_index: usize) -> bool {
    let byte_index = bit_index / 8;
    let bit = bit_index % 8;
    bitmap
        .get(byte_index)
        .is_some_and(|byte| byte & (1 << bit) != 0)
}

fn mysql_null() -> MysqlValue {
    MysqlValue {
        kind: "null".to_string(),
        value: None,
        raw: None,
    }
}

fn mysql_string(value: String) -> MysqlValue {
    MysqlValue {
        kind: "string".to_string(),
        value: Some(Value::String(value)),
        raw: None,
    }
}

fn mysql_json(kind: &str, value: Value) -> MysqlValue {
    MysqlValue {
        kind: kind.to_string(),
        value: Some(value),
        raw: None,
    }
}

fn mysql_raw(bytes: &[u8], max_value_bytes: usize) -> MysqlValue {
    MysqlValue {
        kind: "bytes".to_string(),
        value: None,
        raw: Some(capture_body(bytes, max_value_bytes)),
    }
}

fn mysql_utf8_or_raw(bytes: &[u8], max_value_bytes: usize) -> MysqlValue {
    match std::str::from_utf8(bytes) {
        Ok(value) => mysql_string(value.to_string()),
        Err(_) => mysql_raw(bytes, max_value_bytes),
    }
}

fn mysql_bytes_or_utf8(bytes: &[u8], force_bytes: bool, max_value_bytes: usize) -> MysqlValue {
    if force_bytes {
        mysql_raw(bytes, max_value_bytes)
    } else {
        mysql_utf8_or_raw(bytes, max_value_bytes)
    }
}

fn is_binary_column(column: &MysqlColumn) -> bool {
    column.family == "binary"
}

fn empty_to_none(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn mysql_sql_type_name(type_code: u8, charset: u16, flags: u16) -> &'static str {
    match type_code {
        MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => "DECIMAL",
        MYSQL_TYPE_TINY => "TINYINT",
        MYSQL_TYPE_SHORT => "SMALLINT",
        MYSQL_TYPE_LONG => "INT",
        MYSQL_TYPE_LONGLONG => "BIGINT",
        MYSQL_TYPE_INT24 => "MEDIUMINT",
        MYSQL_TYPE_YEAR => "YEAR",
        MYSQL_TYPE_FLOAT => "FLOAT",
        MYSQL_TYPE_DOUBLE => "DOUBLE",
        MYSQL_TYPE_NULL => "NULL",
        MYSQL_TYPE_TIMESTAMP => "TIMESTAMP",
        MYSQL_TYPE_DATE | MYSQL_TYPE_NEWDATE => "DATE",
        MYSQL_TYPE_TIME => "TIME",
        MYSQL_TYPE_DATETIME => "DATETIME",
        MYSQL_TYPE_VARCHAR | MYSQL_TYPE_VAR_STRING => {
            if is_binary_type(charset, flags) {
                "VARBINARY"
            } else {
                "VARCHAR"
            }
        }
        MYSQL_TYPE_STRING => {
            if is_binary_type(charset, flags) {
                "BINARY"
            } else {
                "VARCHAR"
            }
        }
        MYSQL_TYPE_BIT => "BIT",
        MYSQL_TYPE_JSON => "JSON",
        MYSQL_TYPE_ENUM => "ENUM",
        MYSQL_TYPE_SET => "SET",
        MYSQL_TYPE_TINY_BLOB => {
            if is_binary_type(charset, flags) {
                "TINYBLOB"
            } else {
                "TINYTEXT"
            }
        }
        MYSQL_TYPE_MEDIUM_BLOB => {
            if is_binary_type(charset, flags) {
                "MEDIUMBLOB"
            } else {
                "MEDIUMTEXT"
            }
        }
        MYSQL_TYPE_LONG_BLOB => {
            if is_binary_type(charset, flags) {
                "LONGBLOB"
            } else {
                "LONGTEXT"
            }
        }
        MYSQL_TYPE_BLOB => {
            if is_binary_type(charset, flags) {
                "BLOB"
            } else {
                "TEXT"
            }
        }
        MYSQL_TYPE_GEOMETRY => "GEOMETRY",
        _ => "UNKNOWN",
    }
}

fn mysql_column_family(type_code: u8, charset: u16, flags: u16) -> &'static str {
    match type_code {
        MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_LONG | MYSQL_TYPE_LONGLONG
        | MYSQL_TYPE_INT24 | MYSQL_TYPE_YEAR => "integer",
        MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => "decimal",
        MYSQL_TYPE_FLOAT | MYSQL_TYPE_DOUBLE => "float",
        MYSQL_TYPE_TIMESTAMP | MYSQL_TYPE_DATETIME => "datetime",
        MYSQL_TYPE_DATE | MYSQL_TYPE_NEWDATE => "date",
        MYSQL_TYPE_TIME => "time",
        MYSQL_TYPE_JSON => "json",
        MYSQL_TYPE_BIT => "bit",
        MYSQL_TYPE_GEOMETRY => "geometry",
        MYSQL_TYPE_NULL => "null",
        MYSQL_TYPE_TINY_BLOB | MYSQL_TYPE_MEDIUM_BLOB | MYSQL_TYPE_LONG_BLOB | MYSQL_TYPE_BLOB => {
            if is_binary_type(charset, flags) {
                "binary"
            } else {
                "string"
            }
        }
        MYSQL_TYPE_VARCHAR | MYSQL_TYPE_VAR_STRING | MYSQL_TYPE_STRING => {
            if is_binary_type(charset, flags) {
                "binary"
            } else {
                "string"
            }
        }
        MYSQL_TYPE_ENUM | MYSQL_TYPE_SET => "string",
        _ => "unknown",
    }
}

fn mysql_column_unsigned(type_code: u8, flags: u16) -> Option<bool> {
    match type_code {
        MYSQL_TYPE_TINY
        | MYSQL_TYPE_SHORT
        | MYSQL_TYPE_LONG
        | MYSQL_TYPE_LONGLONG
        | MYSQL_TYPE_INT24
        | MYSQL_TYPE_DECIMAL
        | MYSQL_TYPE_NEWDECIMAL
        | MYSQL_TYPE_FLOAT
        | MYSQL_TYPE_DOUBLE => Some(flags & MYSQL_FLAG_UNSIGNED != 0),
        _ => None,
    }
}

fn mysql_column_bits(type_code: u8) -> Option<u16> {
    match type_code {
        MYSQL_TYPE_TINY => Some(8),
        MYSQL_TYPE_SHORT | MYSQL_TYPE_YEAR => Some(16),
        MYSQL_TYPE_INT24 => Some(24),
        MYSQL_TYPE_LONG => Some(32),
        MYSQL_TYPE_LONGLONG => Some(64),
        MYSQL_TYPE_FLOAT => Some(32),
        MYSQL_TYPE_DOUBLE => Some(64),
        _ => None,
    }
}

fn mysql_column_scale(type_code: u8, decimals: u8) -> Option<u8> {
    matches!(type_code, MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL).then_some(decimals)
}

fn is_binary_charset(charset: u16) -> bool {
    charset == MYSQL_CHARSET_BINARY
}

fn is_binary_type(charset: u16, flags: u16) -> bool {
    is_binary_charset(charset) || flags & MYSQL_FLAG_BINARY != 0
}

fn read_lenenc_string(bytes: &[u8], offset: usize) -> Option<(String, usize)> {
    let (value, next) = read_lenenc_bytes(bytes, offset)?;
    Some((String::from_utf8_lossy(value).to_string(), next))
}

fn read_lenenc_bytes(bytes: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let (len, offset) = read_lenenc_int(bytes, offset)?;
    let len = len as usize;
    Some((bytes.get(offset..offset + len)?, offset + len))
}

fn read_lenenc_int(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(offset)?;
    match first {
        0xfc => Some((read_u16_le(bytes, offset + 1)? as u64, offset + 3)),
        0xfd => {
            let b1 = *bytes.get(offset + 1)? as u64;
            let b2 = *bytes.get(offset + 2)? as u64;
            let b3 = *bytes.get(offset + 3)? as u64;
            Some((b1 | (b2 << 8) | (b3 << 16), offset + 4))
        }
        0xfe => Some((read_u64_le(bytes, offset + 1)?, offset + 9)),
        0xfb => None,
        value => Some((value as u64, offset + 1)),
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
fn lenenc_bytes(value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 0xfb);
    let mut out = Vec::with_capacity(1 + value.len());
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mysql_protocol::parse_client_command;
    use crate::recorder::BodyCapture;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn parses_text_resultset_exchange() {
        let mut tracker = MysqlSemanticTracker::new(1024, test_context());
        let query = MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], b"select id, name".to_vec()].concat(),
        };
        let command = parse_client_command(&query).unwrap();
        assert!(
            tracker
                .start_query(Uuid::nil(), 1, &command, &query, None, None)
                .is_none()
        );

        tracker.observe_packet(&MysqlPacket {
            sequence_id: 1,
            payload: vec![2],
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 2,
            payload: column_def("id", MYSQL_TYPE_LONG),
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 3,
            payload: column_def("name", MYSQL_TYPE_VAR_STRING),
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 4,
            payload: vec![0xfe, 0, 0, 0, 0],
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 5,
            payload: [lenenc_bytes(b"42"), lenenc_bytes(b"alice")].concat(),
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 6,
            payload: vec![0xfe, 0, 0, 0, 0],
        });

        let exchange = tracker
            .finish_active("resultset", None, None, Some(5))
            .expect("exchange");
        assert_eq!(exchange.command, "COM_QUERY");
        assert_eq!(exchange.sql.as_deref(), Some("select id, name"));
        assert_eq!(exchange.response.columns.len(), 2);
        assert_eq!(exchange.response.row_count, 1);
        assert_eq!(
            exchange.response.rows[0][0].value,
            Some(Value::Number(42.into()))
        );
        assert_eq!(
            exchange.response.rows[0][1].value,
            Some(Value::String("alice".to_string()))
        );
    }

    #[test]
    fn serializes_column_as_semantic_schema() {
        let column = parse_column_definition(&column_def_with_flags(
            "id",
            MYSQL_TYPE_LONG,
            MYSQL_FLAG_NOT_NULL | MYSQL_FLAG_UNSIGNED,
        ))
        .expect("column definition");
        let value = serde_json::to_value(&column).expect("column serializes");

        assert_eq!(value["name"], "id");
        assert_eq!(value["table"], "t");
        assert_eq!(value["column"], "id");
        assert_eq!(value["family"], "integer");
        assert_eq!(value["sql_type"], "INT");
        assert_eq!(value["unsigned"], true);
        assert_eq!(value["bits"], 32);
        assert_eq!(value["nullable"], false);
        assert!(value.get("flags").is_none());
        assert!(value.get("column_type_code").is_none());
        assert!(value.get("column_type").is_none());
    }

    #[test]
    fn decodes_binary_charset_var_string_as_varbinary_schema() {
        let column = parse_column_definition(&column_def_with_charset_and_flags(
            "user_name",
            MYSQL_TYPE_VAR_STRING,
            MYSQL_CHARSET_BINARY,
            MYSQL_FLAG_NOT_NULL,
        ))
        .expect("column definition");
        let value = serde_json::to_value(&column).expect("column serializes");

        assert_eq!(value["name"], "user_name");
        assert_eq!(value["family"], "binary");
        assert_eq!(value["sql_type"], "VARBINARY");
        assert_eq!(value["nullable"], false);
    }

    #[test]
    fn decodes_binary_flag_var_string_as_varbinary_schema() {
        let column = parse_column_definition(&column_def_with_charset_and_flags(
            "department_id",
            MYSQL_TYPE_VAR_STRING,
            33,
            MYSQL_FLAG_BINARY,
        ))
        .expect("column definition");
        let value = serde_json::to_value(&column).expect("column serializes");

        assert_eq!(value["name"], "department_id");
        assert_eq!(value["family"], "binary");
        assert_eq!(value["sql_type"], "VARBINARY");
        assert_eq!(value["nullable"], true);
    }

    #[test]
    fn records_binary_charset_string_values_as_bytes() {
        let column = parse_column_definition(&column_def_with_charset_and_flags(
            "user_name",
            MYSQL_TYPE_VAR_STRING,
            MYSQL_CHARSET_BINARY,
            MYSQL_FLAG_NOT_NULL,
        ))
        .expect("column definition");

        let value = parse_text_value(b"alice", &column, 64);

        assert_eq!(value.kind, "bytes");
        assert!(value.value.is_none());
        assert_eq!(
            value.raw,
            Some(BodyCapture {
                encoding: "base64",
                original_len: 5,
                stored_len: 5,
                truncated: false,
                data: STANDARD.encode(b"alice")
            })
        );
    }

    #[test]
    fn records_binary_flag_string_values_as_bytes() {
        let column = parse_column_definition(&column_def_with_charset_and_flags(
            "department_id",
            MYSQL_TYPE_VAR_STRING,
            33,
            MYSQL_FLAG_BINARY,
        ))
        .expect("column definition");

        let value = parse_text_value(b"0", &column, 64);

        assert_eq!(value.kind, "bytes");
        assert!(value.value.is_none());
        assert_eq!(
            value.raw,
            Some(BodyCapture {
                encoding: "base64",
                original_len: 1,
                stored_len: 1,
                truncated: false,
                data: STANDARD.encode(b"0")
            })
        );
    }

    #[test]
    fn parses_prepare_and_execute_binary_resultset() {
        let mut tracker = MysqlSemanticTracker::new(1024, test_context());
        let prepare = MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x16], b"select name from user where id=?".to_vec()].concat(),
        };
        let command = parse_client_command(&prepare).unwrap();
        tracker.start_query(Uuid::nil(), 1, &command, &prepare, None, None);
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 1,
            payload: prepare_ok(9, 1, 1),
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 2,
            payload: column_def("id", MYSQL_TYPE_LONG),
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 3,
            payload: vec![0xfe, 0, 0, 0, 0],
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 4,
            payload: column_def("name", MYSQL_TYPE_VAR_STRING),
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 5,
            payload: vec![0xfe, 0, 0, 0, 0],
        });
        let prepare_exchange = tracker
            .finish_active("stmt_prepare", None, None, Some(2))
            .unwrap();
        assert_eq!(prepare_exchange.statement_id, Some(9));

        let execute = MysqlPacket {
            sequence_id: 0,
            payload: stmt_execute_long_param(9, 42),
        };
        let command = parse_client_command(&execute).unwrap();
        tracker.start_query(Uuid::nil(), 2, &command, &execute, None, None);
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 1,
            payload: vec![1],
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 2,
            payload: column_def("name", MYSQL_TYPE_VAR_STRING),
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 3,
            payload: vec![0xfe, 0, 0, 0, 0],
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 4,
            payload: [vec![0x00, 0x00], lenenc_bytes(b"alice")].concat(),
        });
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 5,
            payload: vec![0xfe, 0, 0, 0, 0],
        });

        let execute_exchange = tracker
            .finish_active("resultset", None, None, Some(3))
            .unwrap();
        assert_eq!(
            execute_exchange.sql.as_deref(),
            Some("select name from user where id=?")
        );
        assert_eq!(
            execute_exchange.params.unwrap()[0].value,
            Some(Value::Number(42.into()))
        );
        assert_eq!(
            execute_exchange.response.rows[0][0].value,
            Some(Value::String("alice".to_string()))
        );
    }

    fn prepare_ok(statement_id: u32, num_columns: u16, num_params: u16) -> Vec<u8> {
        let mut payload = vec![0x00];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.extend_from_slice(&num_columns.to_le_bytes());
        payload.extend_from_slice(&num_params.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload
    }

    fn stmt_execute_long_param(statement_id: u32, value: u32) -> Vec<u8> {
        let mut payload = vec![0x17];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.push(0);
        payload.push(1);
        payload.push(MYSQL_TYPE_LONG);
        payload.push(0);
        payload.extend_from_slice(&value.to_le_bytes());
        payload
    }

    fn column_def(name: &str, type_code: u8) -> Vec<u8> {
        column_def_with_flags(name, type_code, 0)
    }

    fn column_def_with_flags(name: &str, type_code: u8, flags: u16) -> Vec<u8> {
        column_def_with_charset_and_flags(name, type_code, 33, flags)
    }

    fn column_def_with_charset_and_flags(
        name: &str,
        type_code: u8,
        charset: u16,
        flags: u16,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&lenenc_bytes(b"def"));
        payload.extend_from_slice(&lenenc_bytes(b"test"));
        payload.extend_from_slice(&lenenc_bytes(b"t"));
        payload.extend_from_slice(&lenenc_bytes(b"t"));
        payload.extend_from_slice(&lenenc_bytes(name.as_bytes()));
        payload.extend_from_slice(&lenenc_bytes(name.as_bytes()));
        payload.push(0x0c);
        payload.extend_from_slice(&charset.to_le_bytes());
        payload.extend_from_slice(&255_u32.to_le_bytes());
        payload.push(type_code);
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&[0, 0]);
        payload
    }

    fn test_context() -> MysqlExchangeContext {
        MysqlExchangeContext {
            route_name: Some("mysql".to_string()),
            target_host: Some("mysql.internal".to_string()),
            target_port: Some(3306),
            target_addr: Some("mysql.internal:3306".to_string()),
            upstream_addr: Some("10.0.0.1:3306".to_string()),
            username: Some("root".to_string()),
            database: Some("appdb".to_string()),
        }
    }

    #[test]
    fn captures_invalid_utf8_as_raw_base64() {
        let value = mysql_utf8_or_raw(&[0xff, 0x00], 8);
        assert_eq!(value.kind, "bytes");
        assert_eq!(
            value.raw,
            Some(BodyCapture {
                encoding: "base64",
                original_len: 2,
                stored_len: 2,
                truncated: false,
                data: STANDARD.encode([0xff, 0x00])
            })
        );
    }
}
