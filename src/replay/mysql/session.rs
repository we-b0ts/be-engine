pub(in crate::replay) struct ReplaySession {
    pub(in crate::replay) target: Option<TargetKey>,
    pub(in crate::replay) database: Option<String>,
    pub(in crate::replay) username: Option<String>,
    pub(in crate::replay) next_statement_id: u32,
    pub(in crate::replay) statements: HashMap<u32, PreparedStatement>,
}

impl ReplaySession {
    pub(in crate::replay) fn identity(&self) -> ReplaySessionIdentity {
        ReplaySessionIdentity {
            target: self.target.clone(),
            database: self.database.clone(),
            username: self.username.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::replay) enum SessionDirective {
    Continue,
    ClientTerminated,
}

async fn deliver_matched(
    stream: &mut TcpStream,
    state: Arc<Mutex<ReplayState>>,
    session: &ReplaySession,
    matched: MatchedExchange,
    row_encoding: ResultRowEncoding,
) -> Result<SessionDirective> {
    if matched.timing.outcome().is_client_terminated() {
        match matched.timing.await_client_termination(stream).await {
            Ok(_) => {
                state.lock().await.complete_exchange(&matched);
                return Ok(SessionDirective::ClientTerminated);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .fail_exchange(&matched, &session.identity(), &error.to_string());
                return Err(error);
            }
        }
    }

    matched.timing.delay_response().await;
    if let Err(error) = write_response(stream, &matched.record.response, row_encoding).await {
        state.lock().await.fail_exchange(
            &matched,
            &session.identity(),
            &format!("failed to deliver recorded MySQL response: {error}"),
        );
        return Err(error);
    }
    state.lock().await.complete_exchange(&matched);
    Ok(SessionDirective::Continue)
}

pub(in crate::replay) async fn handle_query(
    stream: &mut TcpStream,
    state: Arc<Mutex<ReplayState>>,
    session: &ReplaySession,
    sql: &str,
) -> Result<SessionDirective> {
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
        return Ok(SessionDirective::Continue);
    }

    let matched = {
        let mut state = state.lock().await;
        let identity = session.identity();
        state.match_exchange(&identity, "COM_QUERY", Some(sql), None)
    };
    match matched {
        Some(matched) => {
            deliver_matched(stream, state, session, matched, ResultRowEncoding::Text).await
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
            .await?;
            Ok(SessionDirective::Continue)
        }
    }
}

pub(in crate::replay) async fn handle_stmt_prepare(
    stream: &mut TcpStream,
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    sql: &str,
) -> Result<SessionDirective> {
    let failed_prepare = {
        let mut state = state.lock().await;
        let identity = session.identity();
        state.match_exchange(&identity, "COM_STMT_PREPARE", Some(sql), None)
    };
    if let Some(matched) = failed_prepare {
        return deliver_matched(stream, state, session, matched, ResultRowEncoding::Text).await;
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
    write_stmt_prepare_ok(stream, statement_id, &metadata).await?;
    Ok(SessionDirective::Continue)
}

pub(in crate::replay) async fn handle_stmt_execute(
    stream: &mut TcpStream,
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    packet: &MysqlPacket,
) -> Result<SessionDirective> {
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
        write_packet(
            stream,
            MysqlPacket {
                sequence_id: 1,
                payload: err_payload(1105, "unknown prepared statement id"),
            },
        )
        .await?;
        return Ok(SessionDirective::Continue);
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
        return Ok(SessionDirective::Continue);
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
            deliver_matched(stream, state, session, matched, ResultRowEncoding::Binary).await
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
            .await?;
            Ok(SessionDirective::Continue)
        }
    }
}

#[derive(Debug)]
pub(in crate::replay) struct ParsedStmtExecute {
    pub(in crate::replay) statement_id: u32,
    pub(in crate::replay) params: Option<Vec<RecordedMysqlValue>>,
    pub(in crate::replay) param_types: Option<Vec<BoundParamType>>,
    pub(in crate::replay) warnings: Vec<String>,
}

pub(in crate::replay) fn parse_stmt_execute(
    packet: &MysqlPacket,
    session: &ReplaySession,
) -> ParsedStmtExecute {
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
use super::*;
