use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct OkPacket {
    pub(super) server_status: Option<u16>,
    pub(super) affected_rows: u64,
    pub(super) last_insert_id: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PrepareOkPacket {
    pub(super) statement_id: u32,
    pub(super) num_columns: u16,
    pub(super) num_params: u16,
}

pub(super) fn parse_stmt_execute_params(
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

pub(super) fn parse_resultset_response(
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
            // Only the final row terminator describes the completed query.
            // The metadata EOF can carry a different transaction status.
            if packet.payload.len() == 5 && index + 1 == packets.len() {
                response.server_status = read_u16_le(&packet.payload, 3);
            }
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

pub(super) fn parse_text_row(
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

pub(super) fn parse_binary_row(
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

pub(super) fn parse_text_value(
    bytes: &[u8],
    column: &MysqlColumn,
    max_value_bytes: usize,
) -> MysqlValue {
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

pub(super) fn parse_binary_value(
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

pub(super) fn parse_binary_datetime(payload: &[u8], offset: usize) -> Option<(String, usize)> {
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

pub(super) fn parse_binary_time(payload: &[u8], offset: usize) -> Option<(String, usize)> {
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

pub(super) fn parse_ok_packet(payload: &[u8]) -> Option<OkPacket> {
    if payload.first().copied()? != 0x00 {
        return None;
    }
    let (affected_rows, offset) = read_lenenc_int(payload, 1)?;
    let (last_insert_id, offset) = read_lenenc_int(payload, offset)?;
    // Status and warning count follow both length-encoded integers in Protocol 41.
    let server_status = payload
        .get(offset..offset + 4)
        .map(|tail| u16::from_le_bytes([tail[0], tail[1]]));
    Some(OkPacket {
        server_status,
        affected_rows,
        last_insert_id,
    })
}

pub(super) fn parse_stmt_prepare_ok(payload: &[u8]) -> Option<PrepareOkPacket> {
    if payload.len() < 12 || payload.first().copied()? != 0x00 {
        return None;
    }
    Some(PrepareOkPacket {
        statement_id: read_u32_le(payload, 1)?,
        num_columns: read_u16_le(payload, 5)?,
        num_params: read_u16_le(payload, 7)?,
    })
}

pub(super) fn parse_column_definition(payload: &[u8]) -> Option<MysqlColumn> {
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

pub(super) fn is_eof_packet(packet: &MysqlPacket) -> bool {
    matches!(packet.payload.first(), Some(0xfe)) && packet.payload.len() < 9
}

pub(super) fn null_bitmap_bit(bitmap: &[u8], index: usize) -> bool {
    null_bitmap_bit_with_offset(bitmap, index)
}

pub(super) fn null_bitmap_bit_with_offset(bitmap: &[u8], bit_index: usize) -> bool {
    let byte_index = bit_index / 8;
    let bit = bit_index % 8;
    bitmap
        .get(byte_index)
        .is_some_and(|byte| byte & (1 << bit) != 0)
}

pub(super) fn mysql_null() -> MysqlValue {
    MysqlValue {
        kind: "null".to_string(),
        value: None,
        raw: None,
    }
}

pub(super) fn mysql_string(value: String) -> MysqlValue {
    MysqlValue {
        kind: "string".to_string(),
        value: Some(Value::String(value)),
        raw: None,
    }
}

pub(super) fn mysql_json(kind: &str, value: Value) -> MysqlValue {
    MysqlValue {
        kind: kind.to_string(),
        value: Some(value),
        raw: None,
    }
}

pub(super) fn mysql_raw(bytes: &[u8], max_value_bytes: usize) -> MysqlValue {
    MysqlValue {
        kind: "bytes".to_string(),
        value: None,
        raw: Some(capture_body(bytes, max_value_bytes)),
    }
}

pub(super) fn mysql_utf8_or_raw(bytes: &[u8], max_value_bytes: usize) -> MysqlValue {
    match std::str::from_utf8(bytes) {
        Ok(value) => mysql_string(value.to_string()),
        Err(_) => mysql_raw(bytes, max_value_bytes),
    }
}

pub(super) fn mysql_bytes_or_utf8(
    bytes: &[u8],
    force_bytes: bool,
    max_value_bytes: usize,
) -> MysqlValue {
    if force_bytes {
        mysql_raw(bytes, max_value_bytes)
    } else {
        mysql_utf8_or_raw(bytes, max_value_bytes)
    }
}

pub(super) fn is_binary_column(column: &MysqlColumn) -> bool {
    column.family == "binary"
}

pub(super) fn empty_to_none(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

pub(super) fn mysql_sql_type_name(type_code: u8, charset: u16, flags: u16) -> &'static str {
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

pub(super) fn mysql_column_family(type_code: u8, charset: u16, flags: u16) -> &'static str {
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

pub(super) fn mysql_column_unsigned(type_code: u8, flags: u16) -> Option<bool> {
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

pub(super) fn mysql_column_bits(type_code: u8) -> Option<u16> {
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

pub(super) fn mysql_column_scale(type_code: u8, decimals: u8) -> Option<u8> {
    matches!(type_code, MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL).then_some(decimals)
}

pub(super) fn is_binary_charset(charset: u16) -> bool {
    charset == MYSQL_CHARSET_BINARY
}

pub(super) fn is_binary_type(charset: u16, flags: u16) -> bool {
    is_binary_charset(charset) || flags & MYSQL_FLAG_BINARY != 0
}

pub(super) fn read_lenenc_string(bytes: &[u8], offset: usize) -> Option<(String, usize)> {
    let (value, next) = read_lenenc_bytes(bytes, offset)?;
    Some((String::from_utf8_lossy(value).to_string(), next))
}

pub(super) fn read_lenenc_bytes(bytes: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let (len, offset) = read_lenenc_int(bytes, offset)?;
    let len = len as usize;
    Some((bytes.get(offset..offset + len)?, offset + len))
}

pub(super) fn read_lenenc_int(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
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

pub(super) fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

pub(super) fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

pub(super) fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
pub(super) fn lenenc_bytes(value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 0xfb);
    let mut out = Vec::with_capacity(1 + value.len());
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}
