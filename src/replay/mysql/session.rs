pub(in crate::replay) struct ReplaySession {
    pub(in crate::replay) control: crate::dependency::termination::ConnectionControl,
    pub(in crate::replay) request_started: tokio::time::Instant,
    pub(super) fast_response_timing: bool,
    pub(in crate::replay) target: Option<TargetKey>,
    pub(in crate::replay) database: Option<String>,
    pub(in crate::replay) username: Option<String>,
    pub(in crate::replay) next_statement_id: u32,
    pub(in crate::replay) status_flags: u16,
    pub(in crate::replay) statements: HashMap<u32, PreparedStatement>,
    pub(super) transaction_scope: super::transaction_scope::Scope,
    pub(super) savepoints: super::savepoints::Bindings,
    pub(super) transaction_witness: super::transaction_equivalence::Witness,
}

impl ReplaySession {
    pub(super) fn request_case(&self, state: &ReplayState, sql: Option<&str>) -> Option<String> {
        self.transaction_scope
            .case(state.active_case_id.as_deref(), sql)
    }

    fn observe_response(
        &mut self,
        sql: &str,
        response: &RecordedMysqlResponse,
        case: Option<&str>,
        source_before: Option<u16>,
    ) {
        if !matches!(response.status.as_str(), "ok" | "resultset") {
            return;
        }
        let before = self.status_flags;
        self.update_status(sql, response);
        // A known Source active -> inactive transition also covers implicit
        // commits (for example DDL). An autocommitting Source SELECT alone
        // cannot end an explicit Target transaction.
        if let Some(after) = response.server_status
            && source_before.is_some_and(|flags| flags & 1 != 0)
            && after & 1 == 0
            && before & SERVER_STATUS_AUTOCOMMIT == after & SERVER_STATUS_AUTOCOMMIT
        {
            self.status_flags &= !0x2001;
        }
        self.transaction_scope
            .observe(before, self.status_flags, sql, case);
    }

    fn update_status(&mut self, sql: &str, response: &RecordedMysqlResponse) {
        if let Some(enabled) = crate::mysql::autocommit::assignment(sql) {
            if enabled {
                // Only OFF -> ON implicitly commits. Repeating ON inside an
                // explicit transaction must preserve that transaction.
                if self.status_flags & SERVER_STATUS_AUTOCOMMIT == 0 {
                    self.status_flags &= !0x2001;
                }
                self.status_flags |= SERVER_STATUS_AUTOCOMMIT;
            } else {
                self.status_flags &= !SERVER_STATUS_AUTOCOMMIT;
            }
            return;
        }
        match normalize_sql(sql).as_str() {
            "begin" | "start transaction" => self.status_flags |= 0x0001,
            "commit" | "rollback" => self.status_flags &= !0x2001,
            _ => {
                // Only copy transaction evidence when the source and target
                // use the same autocommit mode. Source implicit read sessions
                // must not turn an autocommitting target connection into one.
                if self.status_flags & SERVER_STATUS_AUTOCOMMIT == 0
                    && let Some(flags) = response.server_status
                    && flags & SERVER_STATUS_AUTOCOMMIT == 0
                {
                    self.status_flags = (self.status_flags & !0x2001) | (flags & 0x2001);
                }
            }
        }
    }

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
    Close,
}

pub(super) async fn deliver_matched(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    mut matched: MatchedExchange,
    row_encoding: ResultRowEncoding,
) -> Result<SessionDirective> {
    let _delivery = matched.claim.guard();
    if let Some(owner) = &matched.hypothesis_owner
        && let Err(error) = owner.await_hypotheses_durable().await
    {
        state.lock().await.fail_exchange(
            &matched,
            &session.identity(),
            "hypothesis evidence persistence failed",
        );
        return Err(error);
    }
    if matched.record.lifecycle_cleanup {
        match super::lifecycle::deliver(
            stream,
            &state,
            &matched,
            session.request_started,
            row_encoding,
        )
        .await
        {
            Ok(()) => {
                matched.claim.publish_wire();
                ensure!(
                    state.lock().await.complete_exchange(&matched),
                    "MySQL cleanup claim was cancelled before completion"
                );
                return Ok(SessionDirective::Close);
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
    if matched.timing.outcome().is_client_terminated()
        || matched.timing.outcome().is_server_terminated()
    {
        let result = super::termination::deliver(
            stream,
            &matched,
            &session.control,
            session.request_started,
            row_encoding,
        )
        .await;
        match result {
            Ok(_) => {
                matched.claim.publish_wire();
                ensure!(
                    state.lock().await.complete_exchange(&matched),
                    "MySQL termination claim was cancelled before completion"
                );
                if matched.timing.outcome().termination().is_some_and(|end| {
                    end.side == crate::dependency::TerminationSide::Server
                        && end.kind == crate::dependency::TerminationKind::Eof
                }) {
                    let mut probe = [0_u8; 1];
                    if matches!(tokio::io::AsyncReadExt::read(stream, &mut probe).await, Ok(count) if count > 0)
                    {
                        state.lock().await.record_unmatched_in_case(
                            matched.report.case_id.as_deref(),
                            &session.identity(),
                            &matched.report.command,
                            matched.report.sql.as_deref(),
                            matched.report.params.as_deref(),
                            "client sent another MySQL request after recorded server EOF",
                        );
                        super::super::exchange::retain_connection(stream).await;
                    }
                }
                return Ok(SessionDirective::Close);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .fail_exchange(&matched, &session.identity(), &error.to_string());
                super::super::exchange::retain_connection(stream).await;
                return Err(error);
            }
        }
    }

    matched
        .timing
        .delay_response_from_request(session.request_started, session.fast_response_timing)
        .await;
    let rendered_at = Utc::now();
    let mut delivered_identities = None;
    if let Some(prepared) = &matched.value_delivery {
        match prepared.render(rendered_at) {
            Ok((response, identities)) => {
                matched.record.response = response;
                delivered_identities = identities;
            }
            Err(error) => {
                state.lock().await.fail_exchange(
                    &matched,
                    &session.identity(),
                    &format!("SQL response contract: {error:#}"),
                );
                return Err(error);
            }
        }
    }
    let target_status_before = session.status_flags;
    session.observe_response(
        matched.record.sql.as_deref().unwrap_or_default(),
        &matched.record.response,
        matched.report.case_id.as_deref(),
        matched.record.server_status_before,
    );
    if matches!(matched.record.response.status.as_str(), "ok" | "resultset")
        && let Some(owner) = &matched.transaction_owner
        && session.transaction_scope.confirm(owner).is_err()
    {
        matched.report.case_id = session.transaction_scope.case(None, None);
        let error = "MySQL transaction contains conflicting Case and Global ownership evidence";
        state
            .lock()
            .await
            .fail_exchange(&matched, &session.identity(), error);
        return Err(anyhow!(error));
    }
    if let Err(error) = write_response(
        stream,
        &matched.record.response,
        row_encoding,
        session.status_flags,
    )
    .await
    {
        state.lock().await.fail_exchange(
            &matched,
            &session.identity(),
            &format!("failed to deliver recorded MySQL response: {error}"),
        );
        return Err(error);
    }
    matched.claim.publish_wire();
    // These are facts about bytes already flushed to the native client. Another
    // connection may immediately copy them while the async report mutex is held.
    // Their success/error still enters the shared terminal transaction below.
    let copy_commit = if let Some(prepared) = &matched.time_copy_delivery {
        prepared.commit_after_wire(
            matched.report.case_id.as_deref(),
            &session.identity(),
            &matched.record.response,
            matched.report.sql.as_deref(),
        )
    } else {
        Ok(())
    };
    let mut replay = state.lock().await;
    let policy_owner = replay
        .replay_policy
        .as_ref()
        .map(|policy| policy.request_contracts.clone());
    let completed = replay.finish_mysql_exchange(&matched, || {
        copy_commit?;
        if let Some(prepared) = &matched.value_delivery {
            prepared.commit(
                policy_owner
                    .as_ref()
                    .context("MySQL response contract owner is unavailable")?,
                &matched.record.response,
                rendered_at,
                delivered_identities,
            )?;
        }
        Ok(())
    })?;
    ensure!(
        completed,
        "MySQL response claim was cancelled before completion"
    );
    session.savepoints.observe(
        &matched.record,
        matched.report.sql.as_deref().unwrap_or_default(),
    );
    let identity = session.identity();
    replay.observe_mysql_transaction(
        &mut session.transaction_witness,
        super::transaction_equivalence::Delivery {
            command: &matched.report.command,
            params: matched.report.params.as_deref(),
            sql: matched.report.sql.as_deref().unwrap_or_default(),
            index: Some(matched.index),
            successful: matches!(matched.record.response.status.as_str(), "ok" | "resultset"),
            before: target_status_before,
            after: session.status_flags,
        },
        matched
            .request_observed_at
            .map(|requested_at| (&matched.record.response, requested_at, rendered_at)),
        matched.report.case_id.as_deref(),
        &identity,
    );
    Ok(SessionDirective::Continue)
}

pub(in crate::replay) async fn handle_query(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    sql: &str,
) -> Result<SessionDirective> {
    let super::admission::RequestSelection {
        matched,
        case_id,
        observation_id,
        event_index,
        recorded_rejection,
        terminal_reason,
    } = super::admission::match_request(&state, session, "COM_QUERY", Some(sql), None).await;
    if let Some(reason) = terminal_reason {
        return Err(anyhow!(reason));
    }
    if let Some(reason) = recorded_rejection {
        return Err(anyhow!(reason));
    }
    if matched.is_none()
        && let Some(response) = builtin_response(sql, session.database.as_deref())
    {
        let target_status_before = session.status_flags;
        session.observe_response(sql, &response, case_id.as_deref(), None);
        write_response(
            stream,
            &response,
            ResultRowEncoding::Text,
            session.status_flags,
        )
        .await?;
        let mut state = state.lock().await;
        let identity = session.identity();
        state.record_builtin_observed_in_case(
            case_id.as_deref(),
            &identity,
            "COM_QUERY",
            Some(sql),
            "driver/session query handled by replay server",
            event_index,
            observation_id.as_deref(),
        );
        if matches!(
            normalize_sql(sql).as_str(),
            "begin" | "start transaction" | "commit" | "rollback"
        ) {
            session.savepoints = Default::default();
        }
        state.observe_mysql_transaction(
            &mut session.transaction_witness,
            super::transaction_equivalence::Delivery {
                command: "COM_QUERY",
                params: None,
                sql,
                index: None,
                successful: true,
                before: target_status_before,
                after: session.status_flags,
            },
            None,
            case_id.as_deref(),
            &identity,
        );
        return Ok(SessionDirective::Continue);
    }

    match matched {
        Some(matched) => {
            deliver_matched(stream, state, session, matched, ResultRowEncoding::Text).await
        }
        None => {
            {
                let mut state = state.lock().await;
                let identity = session.identity();
                state
                    .mysql
                    .isolation
                    .reject_connection(session.transaction_witness.connection());
                state.record_unmatched_in_case(
                    case_id.as_deref(),
                    &identity,
                    "COM_QUERY",
                    Some(sql),
                    None,
                    "no recorded semantic dependency matched this SQL",
                );
                if let Some(report) = state.mysql.events.unmatched_queries.last_mut() {
                    report.target_observation_id = observation_id.clone();
                    report.target_event_index = event_index;
                }
            }
            Ok(SessionDirective::Close)
        }
    }
}

pub(in crate::replay) async fn handle_stmt_prepare(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    sql: &str,
) -> Result<SessionDirective> {
    let super::admission::RequestSelection {
        matched: failed_prepare,
        case_id,
        recorded_rejection,
        terminal_reason,
        ..
    } = super::admission::match_request(&state, session, "COM_STMT_PREPARE", Some(sql), None).await;
    if let Some(reason) = terminal_reason {
        return Err(anyhow!(reason));
    }
    if let Some(reason) = recorded_rejection {
        return Err(anyhow!(reason));
    }
    if let Some(matched) = failed_prepare {
        return deliver_matched(stream, state, session, matched, ResultRowEncoding::Text).await;
    }

    let metadata = {
        let mut state = state.lock().await;
        let identity = session.identity();
        state.statement_metadata_in_case(case_id.as_deref(), &identity, sql)
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
    write_stmt_prepare_ok(stream, statement_id, &metadata, session.status_flags).await?;
    Ok(SessionDirective::Continue)
}

pub(in crate::replay) async fn handle_stmt_execute(
    stream: &mut (impl MysqlReplayIo + ?Sized),
    state: Arc<Mutex<ReplayState>>,
    session: &mut ReplaySession,
    packet: &MysqlPacket,
) -> Result<SessionDirective> {
    let parsed = parse_stmt_execute(packet, session);
    let Some(statement) = session.statements.get(&parsed.statement_id).cloned() else {
        {
            let mut state = state.lock().await;
            let identity = session.identity();
            let case = session.request_case(&state, None);
            state.record_unmatched_in_case(
                case.as_deref(),
                &identity,
                "COM_STMT_EXECUTE",
                None,
                parsed.params.as_deref(),
                "COM_STMT_EXECUTE referenced an unknown replay statement id",
            );
        }
        return Ok(SessionDirective::Close);
    };
    if let Some(param_types) = parsed.param_types
        && let Some(statement) = session.statements.get_mut(&parsed.statement_id)
    {
        statement.last_param_types = param_types;
    }

    if !parsed.warnings.is_empty() {
        let mut state = state.lock().await;
        for warning in &parsed.warnings {
            state.record_metadata_warning(warning.clone());
        }
    }

    let super::admission::RequestSelection {
        matched,
        case_id,
        observation_id,
        event_index,
        recorded_rejection,
        terminal_reason,
    } = super::admission::match_request(
        &state,
        session,
        "COM_STMT_EXECUTE",
        Some(&statement.sql),
        parsed.params.as_deref(),
    )
    .await;
    if let Some(reason) = terminal_reason {
        return Err(anyhow!(reason));
    }
    if let Some(reason) = recorded_rejection {
        return Err(anyhow!(reason));
    }
    if matched.is_none()
        && let Some(response) = builtin_response(&statement.sql, session.database.as_deref())
    {
        let target_status_before = session.status_flags;
        session.observe_response(&statement.sql, &response, case_id.as_deref(), None);
        write_response(
            stream,
            &response,
            ResultRowEncoding::Binary,
            session.status_flags,
        )
        .await?;
        let mut state = state.lock().await;
        let identity = session.identity();
        state.record_builtin_observed_in_case(
            case_id.as_deref(),
            &identity,
            "COM_STMT_EXECUTE",
            Some(&statement.sql),
            "prepared driver/session query handled by replay server",
            event_index,
            observation_id.as_deref(),
        );
        if matches!(
            normalize_sql(&statement.sql).as_str(),
            "begin" | "start transaction" | "commit" | "rollback"
        ) {
            session.savepoints = Default::default();
        }
        state.observe_mysql_transaction(
            &mut session.transaction_witness,
            super::transaction_equivalence::Delivery {
                command: "COM_STMT_EXECUTE",
                params: parsed.params.as_deref(),
                sql: &statement.sql,
                index: None,
                successful: true,
                before: target_status_before,
                after: session.status_flags,
            },
            None,
            case_id.as_deref(),
            &identity,
        );
        return Ok(SessionDirective::Continue);
    }

    match matched {
        Some(matched) => {
            deliver_matched(stream, state, session, matched, ResultRowEncoding::Binary).await
        }
        None => {
            {
                let mut state = state.lock().await;
                let identity = session.identity();
                state
                    .mysql
                    .isolation
                    .reject_connection(session.transaction_witness.connection());
                state.record_unmatched_in_case(
                    case_id.as_deref(),
                    &identity,
                    "COM_STMT_EXECUTE",
                    Some(&statement.sql),
                    parsed.params.as_deref(),
                    "no recorded semantic dependency matched this prepared SQL and params",
                );
                if let Some(report) = state.mysql.events.unmatched_queries.last_mut() {
                    report.target_observation_id = observation_id.clone();
                    report.target_event_index = event_index;
                }
            }
            Ok(SessionDirective::Close)
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
