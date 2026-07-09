struct ReplaySession {
    target: Option<TargetKey>,
    database: Option<String>,
    username: Option<String>,
    next_statement_id: u32,
    statements: HashMap<u32, PreparedStatement>,
}

impl ReplaySession {
    fn identity(&self) -> ReplaySessionIdentity {
        ReplaySessionIdentity {
            target: self.target.clone(),
            database: self.database.clone(),
            username: self.username.clone(),
        }
    }
}

async fn handle_query(
    stream: &mut TcpStream,
    state: Arc<Mutex<ReplayState>>,
    session: &ReplaySession,
    sql: &str,
) -> Result<()> {
    if let Some(response) = builtin_response(sql, session.database.as_deref()) {
        write_response(stream, &response, ResultRowEncoding::Text).await?;
        let mut state = state.lock().await;
        let identity = session.identity();
        state.record_builtin(
            &identity,
            "COM_QUERY",
            Some(sql),
            "driver/session query handled by replay server",
        );
        return Ok(());
    }

    let matched = {
        let mut state = state.lock().await;
        let identity = session.identity();
        state.match_exchange(&identity, "COM_QUERY", Some(sql), None)
    };
    match matched {
        Some(matched) => {
            write_response(stream, &matched.record.response, ResultRowEncoding::Text).await
        }
        None => {
            {
                let mut state = state.lock().await;
                let identity = session.identity();
                state.record_unmatched(
                    &identity,
                    "COM_QUERY",
                    Some(sql),
                    None,
                    "no recorded semantic dependency matched this SQL",
                );
            }
            write_packet(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: err_payload(1105, "no recorded dependency matched this SQL"),
                },
            )
            .await
        }
    }
}

async fn handle_stmt_prepare(
    stream: &mut TcpStream,
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    sql: &str,
) -> Result<()> {
    let failed_prepare = {
        let mut state = state.lock().await;
        let identity = session.identity();
        state.match_exchange(&identity, "COM_STMT_PREPARE", Some(sql), None)
    };
    if let Some(matched) = failed_prepare
        && matched.record.response.status == "error"
    {
        return write_response(stream, &matched.record.response, ResultRowEncoding::Text).await;
    }

    let metadata = {
        let state = state.lock().await;
        let identity = session.identity();
        state.statement_metadata(&identity, sql)
    };
    if metadata.columns.is_empty() && looks_like_select(sql) {
        let mut state = state.lock().await;
        state.record_metadata_warning(format!(
            "COM_STMT_PREPARE for `{sql}` has no recorded result column metadata"
        ));
    }

    let statement_id = session.next_statement_id;
    session.next_statement_id += 1;
    session.statements.insert(
        statement_id,
        PreparedStatement {
            sql: sql.to_string(),
            param_count: metadata.param_count,
            last_param_types: Vec::new(),
        },
    );
    write_stmt_prepare_ok(stream, statement_id, &metadata).await
}

async fn handle_stmt_execute(
    stream: &mut TcpStream,
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    packet: &MysqlPacket,
) -> Result<()> {
    let parsed = parse_stmt_execute(packet, session);
    let Some(statement) = session.statements.get(&parsed.statement_id).cloned() else {
        {
            let mut state = state.lock().await;
            let identity = session.identity();
            state.record_unmatched(
                &identity,
                "COM_STMT_EXECUTE",
                None,
                parsed.params.as_deref(),
                "COM_STMT_EXECUTE referenced an unknown replay statement id",
            );
        }
        return write_packet(
            stream,
            MysqlPacket {
                sequence_id: 1,
                payload: err_payload(1105, "unknown prepared statement id"),
            },
        )
        .await;
    };
    if let Some(param_types) = parsed.param_types
        && let Some(statement) = session.statements.get_mut(&parsed.statement_id)
    {
        statement.last_param_types = param_types;
    }

    if let Some(response) = builtin_response(&statement.sql, session.database.as_deref()) {
        write_response(stream, &response, ResultRowEncoding::Binary).await?;
        let mut state = state.lock().await;
        let identity = session.identity();
        state.record_builtin(
            &identity,
            "COM_STMT_EXECUTE",
            Some(&statement.sql),
            "prepared driver/session query handled by replay server",
        );
        return Ok(());
    }

    if !parsed.warnings.is_empty() {
        let mut state = state.lock().await;
        for warning in &parsed.warnings {
            state.record_metadata_warning(warning.clone());
        }
    }

    let matched = {
        let mut state = state.lock().await;
        let identity = session.identity();
        state.match_exchange(
            &identity,
            "COM_STMT_EXECUTE",
            Some(&statement.sql),
            parsed.params.as_deref(),
        )
    };
    match matched {
        Some(matched) => {
            write_response(stream, &matched.record.response, ResultRowEncoding::Binary).await
        }
        None => {
            {
                let mut state = state.lock().await;
                let identity = session.identity();
                state.record_unmatched(
                    &identity,
                    "COM_STMT_EXECUTE",
                    Some(&statement.sql),
                    parsed.params.as_deref(),
                    "no recorded semantic dependency matched this prepared SQL and params",
                );
            }
            write_packet(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: err_payload(
                        1105,
                        "no recorded dependency matched this prepared SQL and params",
                    ),
                },
            )
            .await
        }
    }
}

#[derive(Debug)]
struct ParsedStmtExecute {
    statement_id: u32,
    params: Option<Vec<RecordedMysqlValue>>,
    param_types: Option<Vec<BoundParamType>>,
    warnings: Vec<String>,
}

fn parse_stmt_execute(packet: &MysqlPacket, session: &ReplaySession) -> ParsedStmtExecute {
    let Some(statement_id) = read_u32_le(&packet.payload, 1) else {
        return ParsedStmtExecute {
            statement_id: 0,
            params: None,
            param_types: None,
            warnings: vec!["COM_STMT_EXECUTE packet missing statement id".to_string()],
        };
    };
    let Some(statement) = session.statements.get(&statement_id) else {
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types: None,
            warnings: Vec::new(),
        };
    };
    let param_count = statement.param_count;
    if param_count == 0 {
        return ParsedStmtExecute {
            statement_id,
            params: Some(Vec::new()),
            param_types: Some(Vec::new()),
            warnings: Vec::new(),
        };
    }
    let mut warnings = Vec::new();
    if packet.payload.len() < 11 {
        warnings.push("COM_STMT_EXECUTE packet too short for parameter metadata".to_string());
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types: None,
            warnings,
        };
    }

    let bitmap_offset = 10;
    let bitmap_len = param_count.div_ceil(8);
    let Some(null_bitmap) = packet
        .payload
        .get(bitmap_offset..bitmap_offset + bitmap_len)
    else {
        warnings.push("COM_STMT_EXECUTE packet missing parameter null bitmap".to_string());
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types: None,
            warnings,
        };
    };
    let mut offset = bitmap_offset + bitmap_len;
    let Some(new_params_bound_flag) = packet.payload.get(offset).copied() else {
        warnings.push("COM_STMT_EXECUTE packet missing new-params-bound flag".to_string());
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types: None,
            warnings,
        };
    };
    offset += 1;

    let param_types = if new_params_bound_flag == 1 {
        let mut param_types = Vec::with_capacity(param_count);
        for _ in 0..param_count {
            let Some(type_code) = packet.payload.get(offset).copied() else {
                warnings.push("COM_STMT_EXECUTE packet ended inside parameter types".to_string());
                return ParsedStmtExecute {
                    statement_id,
                    params: None,
                    param_types: None,
                    warnings,
                };
            };
            let Some(flags) = packet.payload.get(offset + 1).copied() else {
                warnings.push("COM_STMT_EXECUTE packet ended inside parameter flags".to_string());
                return ParsedStmtExecute {
                    statement_id,
                    params: None,
                    param_types: None,
                    warnings,
                };
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
            "COM_STMT_EXECUTE for statement {statement_id} reused parameter types before replay captured them"
        ));
        None
    };

    let Some(types) = param_types.as_ref() else {
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types,
            warnings,
        };
    };
    let mut params = Vec::with_capacity(param_count);
    for (index, param_type) in types.iter().enumerate() {
        if null_bitmap_bit(null_bitmap, index) {
            params.push(mysql_null());
            continue;
        }
        match parse_binary_value(
            &packet.payload,
            offset,
            param_type.type_code,
            param_type.unsigned,
            false,
        ) {
            Some((value, next)) => {
                params.push(value);
                offset = next;
            }
            None => {
                warnings.push(format!(
                    "failed to parse COM_STMT_EXECUTE parameter {index}"
                ));
                break;
            }
        }
    }

    ParsedStmtExecute {
        statement_id,
        params: Some(params),
        param_types,
        warnings,
    }
}
