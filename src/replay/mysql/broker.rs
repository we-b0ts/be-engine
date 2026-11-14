use super::*;

pub(crate) async fn handle_connection(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    target: Option<TargetKey>,
    state: Arc<Mutex<ReplayState>>,
    ca: Arc<MitmCa>,
) -> Result<()> {
    super::wire_diagnostics::connection(
        peer_addr,
        handle_connection_inner(tcp_stream, peer_addr, target, state, ca),
    )
    .await
}

async fn handle_connection_inner(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    target: Option<TargetKey>,
    state: Arc<Mutex<ReplayState>>,
    ca: Arc<MitmCa>,
) -> Result<()> {
    let providers = state.lock().await.providers.clone();
    let decoder = crate::protocols::mysql_session(&providers)?;
    let tls_host = target
        .as_ref()
        .map(|target| target.host.as_str())
        .unwrap_or("localhost");
    let pending = traffic_protocol_mysql::server::negotiate(tcp_stream, decoder, 1, || {
        ca.mysql_server_config_for_host(tls_host)
    })
    .await?;
    let login = pending.login();
    let fast_response_timing = {
        let mut state = state.lock().await;
        state.record_connection(
            peer_addr,
            target.as_ref(),
            login.database.clone(),
            login.username.clone(),
        );
        state.stream_timing == Some(ReplayStreamTiming::Fast)
    };
    super::wire_diagnostics::response_kind("login_ok", Some(SERVER_STATUS_AUTOCOMMIT));
    let traffic_protocol_mysql::server::Connection {
        io: mut stream,
        mut decoder,
        login,
        control,
    } = pending.accept().await?;
    let mut session = ReplaySession {
        control,
        request_started: tokio::time::Instant::now(),
        fast_response_timing,
        target,
        database: login.database,
        username: login.username,
        next_statement_id: 1,
        status_flags: SERVER_STATUS_AUTOCOMMIT,
        statements: HashMap::new(),
        transaction_scope: Default::default(),
        savepoints: Default::default(),
        transaction_witness: Default::default(),
    };
    loop {
        let Some(packet) =
            traffic_protocol_mysql::read_packet_with_session(&mut stream, decoder.as_mut()).await?
        else {
            super::wire_diagnostics::client_eof();
            break;
        };
        session.request_started = tokio::time::Instant::now();
        let Some(command) = parse_client_command(&packet) else {
            continue;
        };
        super::wire_diagnostics::request(&packet, &command.command_name);
        let stopping = {
            let state = state.lock().await;
            state.target_session_stopped
                || state.async_case_quiescing()
                || state
                    .active_case_id
                    .as_ref()
                    .is_some_and(|case| state.target_stop_prepared.contains(case))
        };
        if stopping {
            session.control.reset()?;
            break;
        }
        match command.command_name.as_str() {
            "COM_QUIT" => break,
            "COM_PING" | "COM_INIT_DB" => {
                let super::admission::RequestSelection {
                    matched,
                    case_id,
                    event_index,
                    observation_id,
                    terminal_reason,
                    ..
                } = super::admission::match_request(
                    &state,
                    &session,
                    &command.command_name,
                    command.query.as_deref(),
                    None,
                )
                .await;
                if let Some(reason) = terminal_reason {
                    return Err(anyhow!(reason));
                }
                if let Some(matched) = matched {
                    let successful = matched.record.outcome
                        == crate::DependencyExchangeOutcome::Response
                        && matched.record.response.status == "ok";
                    let directive = deliver_matched(
                        &mut stream,
                        state.clone(),
                        &mut session,
                        matched,
                        ResultRowEncoding::Text,
                    )
                    .await?;
                    if directive == SessionDirective::Close {
                        break;
                    }
                    if command.command_name == "COM_INIT_DB" && successful {
                        session.database = command.query.clone();
                    }
                    continue;
                }
                if command.command_name == "COM_INIT_DB" {
                    session.database = command.query.clone();
                }
                super::wire_diagnostics::response_kind("control_ok", Some(session.status_flags));
                write_packet_and_flush(
                    &mut stream,
                    MysqlPacket {
                        sequence_id: 1,
                        payload: ok_payload_with_status(0, 0, session.status_flags),
                    },
                )
                .await?;
                {
                    let mut state = state.lock().await;
                    let identity = session.identity();
                    state.record_builtin_observed_in_case(
                        case_id.as_deref(),
                        &identity,
                        &command.command_name,
                        command.query.as_deref(),
                        "driver/session command handled by replay server",
                        event_index,
                        observation_id.as_deref(),
                    );
                }
            }
            "COM_QUERY" => {
                let sql = command.query.as_deref().unwrap_or_default();
                if handle_query(&mut stream, state.clone(), &mut session, sql).await?
                    == SessionDirective::Close
                {
                    break;
                }
            }
            "COM_STMT_PREPARE" => {
                let sql = command.query.as_deref().unwrap_or_default();
                if handle_stmt_prepare(&mut stream, state.clone(), &mut session, sql).await?
                    == SessionDirective::Close
                {
                    break;
                }
            }
            "COM_STMT_EXECUTE" => {
                if handle_stmt_execute(&mut stream, state.clone(), &mut session, &packet).await?
                    == SessionDirective::Close
                {
                    break;
                }
            }
            "COM_STMT_CLOSE" => {
                let statement_id = read_u32_le(&packet.payload, 1);
                let mut state = state.lock().await;
                let identity = session.identity();
                let case = session.request_case(&state, None);
                if let Some(statement_id) = statement_id {
                    session.statements.remove(&statement_id);
                    state.record_builtin_in_case(
                        case.as_deref(),
                        &identity,
                        "COM_STMT_CLOSE",
                        None,
                        "prepared statement closed without a server response",
                    );
                } else {
                    state.record_unsupported_in_case(
                        case.as_deref(),
                        &identity,
                        "COM_STMT_CLOSE",
                        None,
                        None,
                        "COM_STMT_CLOSE packet missing statement id",
                    );
                }
            }
            other => {
                {
                    let mut state = state.lock().await;
                    let identity = session.identity();
                    let case = session.request_case(&state, None);
                    state.record_unsupported_in_case(
                        case.as_deref(),
                        &identity,
                        other,
                        command.query.as_deref(),
                        None,
                        "unsupported MySQL command",
                    );
                }
                write_packet_and_flush(
                    &mut stream,
                    MysqlPacket {
                        sequence_id: 1,
                        payload: err_payload(1105, &format!("unsupported replay command {other}")),
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}
