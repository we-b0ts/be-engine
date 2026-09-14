pub(in crate::replay) async fn write_response(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    response: &RecordedMysqlResponse,
    row_encoding: ResultRowEncoding,
    status_flags: u16,
) -> Result<()> {
    match response.status.as_str() {
        "resultset" => {
            write_resultset(
                stream,
                &response.columns,
                &response.rows,
                row_encoding,
                status_flags,
            )
            .await
        }
        "ok" => {
            write_packet(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: ok_payload_with_status(
                        response.affected_rows.unwrap_or_default(),
                        response.last_insert_id.unwrap_or_default(),
                        status_flags,
                    ),
                },
            )
            .await
        }
        "error" => {
            write_packet(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: err_payload(
                        response.error_code.unwrap_or(1105),
                        response
                            .error_message
                            .as_deref()
                            .unwrap_or("recorded MySQL dependency error"),
                    ),
                },
            )
            .await
        }
        other => {
            write_packet(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: err_payload(
                        1105,
                        &format!("unsupported recorded MySQL response status {other}"),
                    ),
                },
            )
            .await
        }
    }
}

pub(in crate::replay) async fn write_stmt_prepare_ok(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    statement_id: u32,
    metadata: &StatementMetadata,
    status_flags: u16,
) -> Result<()> {
    let mut sequence_id = 1_u8;
    write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: stmt_prepare_ok_payload(
                statement_id,
                metadata.columns.len() as u16,
                metadata.param_count as u16,
            ),
        },
    )
    .await?;
    advance_sequence_id(&mut sequence_id);

    for index in 0..metadata.param_count {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: column_definition_payload(&RecordedMysqlColumn {
                    name: format!("param_{}", index + 1),
                    table: None,
                    table_alias: None,
                    column: None,
                    family: "string".to_string(),
                    sql_type: "VARCHAR".to_string(),
                    unsigned: None,
                    bits: None,
                    nullable: Some(true),
                    scale: None,
                }),
            },
        )
        .await?;
        advance_sequence_id(&mut sequence_id);
    }
    if metadata.param_count > 0 {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: eof_payload_with_status(status_flags),
            },
        )
        .await?;
        advance_sequence_id(&mut sequence_id);
    }

    for column in &metadata.columns {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: column_definition_payload(column),
            },
        )
        .await?;
        advance_sequence_id(&mut sequence_id);
    }
    if !metadata.columns.is_empty() {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: eof_payload_with_status(status_flags),
            },
        )
        .await?;
    }
    // TLS may accept writes into its buffer without sending every packet.
    // Deliver the complete metadata response before waiting for EXECUTE.
    stream
        .flush()
        .await
        .context("failed to flush MySQL prepare metadata")
}

pub(in crate::replay) async fn write_resultset(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    columns: &[RecordedMysqlColumn],
    rows: &[Vec<RecordedMysqlValue>],
    row_encoding: ResultRowEncoding,
    status_flags: u16,
) -> Result<()> {
    if columns.is_empty() {
        return write_packet(
            stream,
            MysqlPacket {
                sequence_id: 1,
                payload: err_payload(1105, "recorded resultset has no column metadata"),
            },
        )
        .await;
    }

    let mut sequence_id = 1_u8;
    write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: lenenc_int(columns.len() as u64),
        },
    )
    .await?;
    advance_sequence_id(&mut sequence_id);

    for column in columns {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: column_definition_payload(column),
            },
        )
        .await?;
        advance_sequence_id(&mut sequence_id);
    }
    write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: eof_payload_with_status(status_flags),
        },
    )
    .await?;
    advance_sequence_id(&mut sequence_id);

    for row in rows {
        let payload = match row_encoding {
            ResultRowEncoding::Text => text_row_payload(row),
            ResultRowEncoding::Binary => binary_row_payload(columns, row),
        }?;
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload,
            },
        )
        .await?;
        advance_sequence_id(&mut sequence_id);
    }
    write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: eof_payload_with_status(status_flags),
        },
    )
    .await?;
    // TLS may accept writes into its buffer without sending every packet.
    // The sibling write_stmt_prepare_ok flushes for the same reason; without
    // this flush, large resultsets (e.g. 316-column JOINs) stay buffered in
    // the rustls layer and never reach the target, which then blocks waiting
    // for the response until its request timeout. Small resultsets sometimes
    // slipped through because a single TLS record auto-flushed, but any
    // multi-record resultset reliably deadlocks.
    stream
        .flush()
        .await
        .context("failed to flush MySQL resultset")
}

pub(in crate::replay) async fn write_packet(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    packet: MysqlPacket,
) -> Result<()> {
    stream
        .write_all(&packet.to_wire_bytes())
        .await
        .context("failed to write MySQL replay packet")
}

pub(in crate::replay) fn advance_sequence_id(sequence_id: &mut u8) {
    *sequence_id = sequence_id.wrapping_add(1);
}

pub(in crate::replay) fn handshake_packet(connection_id: u32) -> MysqlPacket {
    let capabilities = CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_PROTOCOL_41
        | CLIENT_SSL
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_MULTI_RESULTS
        | CLIENT_PLUGIN_AUTH;
    let mut payload = Vec::new();
    payload.push(0x0a);
    payload.extend_from_slice(b"8.0.0-traffic-recorder-replay\0");
    payload.extend_from_slice(&connection_id.to_le_bytes());
    payload.extend_from_slice(MYSQL_REPLAY_AUTH_PLUGIN_DATA_1);
    payload.push(0);
    payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    payload.push(mysql_replay_auth_plugin_data_len());
    payload.extend_from_slice(&[0; 10]);
    payload.extend_from_slice(MYSQL_REPLAY_AUTH_PLUGIN_DATA_2);
    payload.push(0);
    payload.extend_from_slice(MYSQL_REPLAY_AUTH_PLUGIN);
    payload.push(0);
    MysqlPacket {
        sequence_id: 0,
        payload,
    }
}

pub(in crate::replay) fn mysql_replay_auth_plugin_data_len() -> u8 {
    u8::try_from(MYSQL_REPLAY_AUTH_PLUGIN_DATA_1.len() + MYSQL_REPLAY_AUTH_PLUGIN_DATA_2.len() + 1)
        .expect("MySQL replay auth plugin data length fits u8")
}

pub(in crate::replay) fn ok_payload(affected_rows: u64, last_insert_id: u64) -> Vec<u8> {
    ok_payload_with_status(affected_rows, last_insert_id, SERVER_STATUS_AUTOCOMMIT)
}

pub(in crate::replay) fn ok_payload_with_status(
    affected_rows: u64,
    last_insert_id: u64,
    status_flags: u16,
) -> Vec<u8> {
    let mut payload = vec![0x00];
    payload.extend_from_slice(&lenenc_int(affected_rows));
    payload.extend_from_slice(&lenenc_int(last_insert_id));
    payload.extend_from_slice(&status_flags.to_le_bytes());
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload
}

pub(in crate::replay) fn err_payload(code: u16, message: &str) -> Vec<u8> {
    let mut payload = vec![0xff];
    payload.extend_from_slice(&code.to_le_bytes());
    payload.extend_from_slice(b"#HY000");
    payload.extend_from_slice(message.as_bytes());
    payload
}

fn eof_payload_with_status(status_flags: u16) -> Vec<u8> {
    let mut payload = vec![0xfe];
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.extend_from_slice(&status_flags.to_le_bytes());
    payload
}

pub(in crate::replay) fn stmt_prepare_ok_payload(
    statement_id: u32,
    column_count: u16,
    param_count: u16,
) -> Vec<u8> {
    let mut payload = vec![0x00];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.extend_from_slice(&column_count.to_le_bytes());
    payload.extend_from_slice(&param_count.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload
}

pub(in crate::replay) fn column_definition_payload(column: &RecordedMysqlColumn) -> Vec<u8> {
    let type_code = column_type_code(column);
    let charset = if column.family == "binary" {
        MYSQL_CHARSET_BINARY
    } else {
        MYSQL_CHARSET_UTF8_GENERAL_CI
    };
    let mut flags = 0_u16;
    if column.nullable == Some(false) {
        flags |= MYSQL_FLAG_NOT_NULL;
    }
    if column.unsigned == Some(true) {
        flags |= MYSQL_FLAG_UNSIGNED;
    }
    if column.family == "binary" {
        flags |= MYSQL_FLAG_BINARY;
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(&lenenc_bytes(b"def"));
    payload.extend_from_slice(&lenenc_bytes(b""));
    payload.extend_from_slice(&lenenc_bytes(
        column
            .table_alias
            .as_deref()
            .or(column.table.as_deref())
            .unwrap_or_default()
            .as_bytes(),
    ));
    payload.extend_from_slice(&lenenc_bytes(
        column.table.as_deref().unwrap_or_default().as_bytes(),
    ));
    payload.extend_from_slice(&lenenc_bytes(column.name.as_bytes()));
    payload.extend_from_slice(&lenenc_bytes(
        column.column.as_deref().unwrap_or(&column.name).as_bytes(),
    ));
    payload.push(0x0c);
    payload.extend_from_slice(&charset.to_le_bytes());
    payload.extend_from_slice(&column_length(column).to_le_bytes());
    payload.push(type_code);
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.push(column.scale.unwrap_or_default());
    payload.extend_from_slice(&[0, 0]);
    payload
}

pub(in crate::replay) fn text_row_payload(row: &[RecordedMysqlValue]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for value in row {
        if value.kind == "null" || value.value.is_none() && value.raw.is_none() {
            payload.push(0xfb);
        } else {
            let bytes = mysql_value_bytes(value)?;
            payload.extend_from_slice(&lenenc_bytes(&bytes));
        }
    }
    Ok(payload)
}

pub(in crate::replay) fn binary_row_payload(
    columns: &[RecordedMysqlColumn],
    row: &[RecordedMysqlValue],
) -> Result<Vec<u8>> {
    let mut payload = vec![0x00];
    let bitmap_len = (columns.len() + 7 + 2) / 8;
    let bitmap_offset = payload.len();
    payload.resize(payload.len() + bitmap_len, 0);
    for (index, column) in columns.iter().enumerate() {
        let value = row
            .get(index)
            .ok_or_else(|| anyhow!("recorded row has fewer values than columns"))?;
        if value.kind == "null" || value.value.is_none() && value.raw.is_none() {
            set_null_bitmap_bit(
                &mut payload[bitmap_offset..bitmap_offset + bitmap_len],
                index + 2,
            );
            continue;
        }
        encode_binary_value(&mut payload, column, value)?;
    }
    Ok(payload)
}

pub(in crate::replay) fn encode_binary_value(
    payload: &mut Vec<u8>,
    column: &RecordedMysqlColumn,
    value: &RecordedMysqlValue,
) -> Result<()> {
    let type_code = column_type_code(column);
    match type_code {
        MYSQL_TYPE_TINY => payload.push(value_as_i64(value)? as i8 as u8),
        MYSQL_TYPE_SHORT | MYSQL_TYPE_YEAR => {
            payload.extend_from_slice(&(value_as_i64(value)? as i16).to_le_bytes());
        }
        MYSQL_TYPE_LONG | MYSQL_TYPE_INT24 => {
            payload.extend_from_slice(&(value_as_i64(value)? as i32).to_le_bytes());
        }
        MYSQL_TYPE_LONGLONG => {
            if column.unsigned == Some(true) {
                let value = match value.value.as_ref() {
                    Some(Value::Number(value)) => value
                        .as_u64()
                        .context("recorded integer does not fit u64")?,
                    Some(Value::String(value)) => value
                        .parse::<u64>()
                        .context("invalid recorded unsigned integer")?,
                    _ => return Err(anyhow!("recorded unsigned integer has no numeric value")),
                };
                payload.extend_from_slice(&value.to_le_bytes());
            } else {
                payload.extend_from_slice(&value_as_i64(value)?.to_le_bytes());
            }
        }
        MYSQL_TYPE_FLOAT => {
            payload.extend_from_slice(&(value_as_f64(value)? as f32).to_le_bytes());
        }
        MYSQL_TYPE_DOUBLE => {
            payload.extend_from_slice(&value_as_f64(value)?.to_le_bytes());
        }
        MYSQL_TYPE_DATE | MYSQL_TYPE_DATETIME | MYSQL_TYPE_TIMESTAMP => {
            payload.extend_from_slice(&binary_datetime_bytes(value_as_str(value)?)?);
        }
        MYSQL_TYPE_TIME => {
            payload.extend_from_slice(&binary_time_bytes(value_as_str(value)?)?);
        }
        MYSQL_TYPE_NULL => {}
        _ => {
            let bytes = mysql_value_bytes(value)?;
            payload.extend_from_slice(&lenenc_bytes(&bytes));
        }
    }
    Ok(())
}

pub(in crate::replay) fn parse_binary_value(
    payload: &[u8],
    offset: usize,
    type_code: u8,
    unsigned: bool,
    force_bytes: bool,
) -> Option<(RecordedMysqlValue, usize)> {
    match type_code {
        MYSQL_TYPE_TINY => {
            let value = *payload.get(offset)?;
            let number = if unsigned {
                Value::Number((value as u64).into())
            } else {
                Value::Number((value as i8 as i64).into())
            };
            Some((mysql_json("integer", number), offset + 1))
        }
        MYSQL_TYPE_SHORT | MYSQL_TYPE_YEAR => {
            let value = read_u16_le(payload, offset)?;
            let number = if unsigned {
                Value::Number((value as u64).into())
            } else {
                Value::Number((value as i16 as i64).into())
            };
            Some((mysql_json("integer", number), offset + 2))
        }
        MYSQL_TYPE_LONG | MYSQL_TYPE_INT24 => {
            let value = read_u32_le(payload, offset)?;
            let number = if unsigned {
                Value::Number((value as u64).into())
            } else {
                Value::Number((value as i32 as i64).into())
            };
            Some((mysql_json("integer", number), offset + 4))
        }
        MYSQL_TYPE_LONGLONG => {
            let value = read_u64_le(payload, offset)?;
            let number = if unsigned {
                Value::Number(value.into())
            } else {
                Value::Number((value as i64).into())
            };
            Some((mysql_json("integer", number), offset + 8))
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
        MYSQL_TYPE_NEWDECIMAL => {
            let (bytes, next) = read_lenenc_bytes(payload, offset)?;
            let value = std::str::from_utf8(bytes).ok()?;
            Some((mysql_json("decimal", Value::String(value.to_owned())), next))
        }
        MYSQL_TYPE_DATE | MYSQL_TYPE_DATETIME | MYSQL_TYPE_TIMESTAMP => {
            parse_binary_datetime(payload, offset)
                .map(|(value, next)| (mysql_json("datetime", Value::String(value)), next))
        }
        MYSQL_TYPE_TIME => parse_binary_time(payload, offset)
            .map(|(value, next)| (mysql_json("time", Value::String(value)), next)),
        _ => {
            let (bytes, next) = read_lenenc_bytes(payload, offset)?;
            Some((mysql_bytes_or_utf8(bytes, force_bytes), next))
        }
    }
}
use super::*;
