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
    let mut session = ReplaySession::new(
        control,
        target,
        login,
        super::session::SessionState {
            fast_response_timing,
            ..Default::default()
        },
    );
    traffic_protocol_mysql::server::serve(
        stream.as_mut(),
        &mut decoder,
        &super::server_host::Host { state },
        &mut session,
    )
    .await
}
