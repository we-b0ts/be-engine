use super::*;

pub(in crate::replay) async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    target: Option<TargetKey>,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    write_packet(&mut stream, handshake_packet(1)).await?;
    let login_packet = read_packet(&mut stream)
        .await
        .context("failed to read MySQL replay login packet")?
        .context("MySQL replay client closed before login packet")?;
    let login = parse_handshake_response(&login_packet);
    if login.tls_requested {
        write_packet(
            &mut stream,
            MysqlPacket {
                sequence_id: 2,
                payload: err_payload(3159, "MySQL TLS is not supported by replay mode"),
            },
        )
        .await?;
        {
            let mut state = state.lock().await;
            let identity = ReplaySessionIdentity {
                target: target.clone(),
                database: login.database.clone(),
                username: login.username.clone(),
            };
            state.record_unsupported(
                &identity,
                "HANDSHAKE",
                None,
                None,
                "MySQL TLS requested; replay mode requires a non-TLS test connection",
            );
        }
        write_report_snapshot(state, report_path).await?;
        return Ok(());
    }
    {
        let mut state = state.lock().await;
        state.record_connection(
            peer_addr,
            target.as_ref(),
            login.database.clone(),
            login.username.clone(),
        );
    }
    write_packet(
        &mut stream,
        MysqlPacket {
            sequence_id: 2,
            payload: ok_payload(0, 0),
        },
    )
    .await?;
    write_report_snapshot(state.clone(), report_path.clone()).await?;

    let mut session = ReplaySession {
        target,
        database: login.database,
        username: login.username,
        next_statement_id: 1,
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
                write_packet(
                    &mut stream,
                    MysqlPacket {
                        sequence_id: 1,
                        payload: ok_payload(0, 0),
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
                handle_query(&mut stream, state.clone(), &session, sql).await?;
            }
            "COM_STMT_PREPARE" => {
                let sql = command.query.as_deref().unwrap_or_default();
                handle_stmt_prepare(&mut stream, state.clone(), &mut session, sql).await?;
            }
            "COM_STMT_EXECUTE" => {
                handle_stmt_execute(&mut stream, state.clone(), &mut session, &packet).await?;
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
                write_packet(
                    &mut stream,
                    MysqlPacket {
                        sequence_id: 1,
                        payload: err_payload(1105, &format!("unsupported replay command {other}")),
                    },
                )
                .await?;
            }
        }
        write_report_snapshot(state.clone(), report_path.clone()).await?;
    }
    Ok(())
}
