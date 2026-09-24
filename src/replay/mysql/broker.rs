use super::*;

pub(in crate::replay) async fn handle_connection(
    mut tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    target: Option<TargetKey>,
    state: Arc<Mutex<ReplayState>>,
    ca: Arc<MitmCa>,
) -> Result<()> {
    write_packet_and_flush(&mut tcp_stream, handshake_packet(1)).await?;
    let first_login_packet = read_packet(&mut tcp_stream)
        .await
        .context("failed to read MySQL replay login packet")?
        .context("MySQL replay client closed before login packet")?;
    let first_login = parse_handshake_response(&first_login_packet);
    let (mut stream, login_packet): (BoxedMysqlReplayIo, MysqlPacket) = if first_login.tls_requested
    {
        let tls_host = target
            .as_ref()
            .map(|target| target.host.as_str())
            .unwrap_or("localhost");
        let config = ca.mysql_server_config_for_host(tls_host)?;
        let mut tls_stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(tcp_stream)
            .await
            .context("failed to accept MySQL replay client TLS")?;
        let secure_login_packet = read_packet(&mut tls_stream)
            .await
            .context("failed to read MySQL replay TLS login packet")?
            .context("MySQL replay TLS client closed before login packet")?;
        (Box::new(tls_stream), secure_login_packet)
    } else {
        (Box::new(tcp_stream), first_login_packet)
    };
    let login = parse_handshake_response(&login_packet);
    {
        let mut state = state.lock().await;
        state.record_connection(
            peer_addr,
            target.as_ref(),
            login.database.clone(),
            login.username.clone(),
        );
    }
    write_packet_and_flush(
        &mut stream,
        MysqlPacket {
            sequence_id: login_packet.sequence_id.wrapping_add(1),
            payload: ok_payload(0, 0),
        },
    )
    .await?;
    let mut session = ReplaySession {
        target,
        database: login.database,
        username: login.username,
        next_statement_id: 1,
        status_flags: SERVER_STATUS_AUTOCOMMIT,
        statements: HashMap::new(),
    };
    loop {
        let Some(packet) = read_packet(&mut stream).await? else {
            break;
        };
        let Some(command) = parse_client_command(&packet) else {
            continue;
        };
        match command.command_name.as_str() {
            "COM_QUIT" => break,
            "COM_PING" | "COM_INIT_DB" => {
                if command.command_name == "COM_INIT_DB" {
                    session.database = command.query.clone();
                }
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
                    state.record_builtin(
                        &identity,
                        &command.command_name,
                        command.query.as_deref(),
                        "driver/session command handled by replay server",
                    );
                }
            }
            "COM_QUERY" => {
                let sql = command.query.as_deref().unwrap_or_default();
                if handle_query(&mut stream, state.clone(), &mut session, sql).await?
                    == SessionDirective::ClientTerminated
                {
                    break;
                }
            }
            "COM_STMT_PREPARE" => {
                let sql = command.query.as_deref().unwrap_or_default();
                if handle_stmt_prepare(&mut stream, state.clone(), &mut session, sql).await?
                    == SessionDirective::ClientTerminated
                {
                    break;
                }
            }
            "COM_STMT_EXECUTE" => {
                if handle_stmt_execute(&mut stream, state.clone(), &mut session, &packet).await?
                    == SessionDirective::ClientTerminated
                {
                    break;
                }
            }
            "COM_STMT_CLOSE" => {
                let statement_id = read_u32_le(&packet.payload, 1);
                let mut state = state.lock().await;
                let identity = session.identity();
                if let Some(statement_id) = statement_id {
                    session.statements.remove(&statement_id);
                    state.record_builtin(
                        &identity,
                        "COM_STMT_CLOSE",
                        None,
                        "prepared statement closed without a server response",
                    );
                } else {
                    state.record_unsupported(
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
                    state.record_unsupported(
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
