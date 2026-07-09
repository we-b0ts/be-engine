use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

use crate::mysql_protocol::{
    CLIENT_CONNECT_WITH_DB, CLIENT_SECURE_CONNECTION, MysqlPacket, parse_client_command,
    parse_handshake_response, read_packet,
};

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
const MYSQL_REPLAY_AUTH_PLUGIN: &[u8] = b"mysql_native_password";
const MYSQL_REPLAY_AUTH_PLUGIN_DATA_1: &[u8; 8] = b"replay01";
const MYSQL_REPLAY_AUTH_PLUGIN_DATA_2: &[u8; 12] = b"replay-seed2";

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
const MYSQL_TYPE_BIT: u8 = 16;
const MYSQL_TYPE_JSON: u8 = 245;
const MYSQL_TYPE_NEWDECIMAL: u8 = 246;
const MYSQL_TYPE_VAR_STRING: u8 = 253;
const MYSQL_TYPE_STRING: u8 = 254;
const MYSQL_TYPE_GEOMETRY: u8 = 255;

const MYSQL_FLAG_NOT_NULL: u16 = 0x0001;
const MYSQL_FLAG_UNSIGNED: u16 = 0x0020;
const MYSQL_FLAG_BINARY: u16 = 0x0080;
const MYSQL_CHARSET_UTF8_GENERAL_CI: u16 = 33;
const MYSQL_CHARSET_BINARY: u16 = 63;
const SO_ORIGINAL_DST: libc::c_int = 80;

#[derive(Debug, Clone)]
pub struct MysqlReplayConfig {
    pub case_dir: PathBuf,
    pub dns_listen: SocketAddr,
    pub tcp_listen: SocketAddr,
    pub fake_cidr: String,
    pub report_path: Option<PathBuf>,
}

pub async fn run_mysql_replay(config: MysqlReplayConfig) -> Result<()> {
    let tcp_listener = TcpListener::bind(config.tcp_listen)
        .await
        .with_context(|| format!("failed to bind MySQL replay gateway {}", config.tcp_listen))?;
    let tcp_listen = tcp_listener
        .local_addr()
        .context("failed to read MySQL replay gateway listen address")?;
    let dns_socket = UdpSocket::bind(config.dns_listen)
        .await
        .with_context(|| format!("failed to bind MySQL replay DNS {}", config.dns_listen))?;
    let dns_listen = dns_socket
        .local_addr()
        .context("failed to read MySQL replay DNS listen address")?;
    let runtime = MysqlReplayRuntime::load(config, dns_listen, tcp_listen).await?;
    runtime.write_report().await?;
    info!(
        dns_listen = %dns_listen,
        tcp_listen = %tcp_listen,
        "MySQL dependency replay intercept listening"
    );
    tokio::select! {
        result = runtime.run_dns(dns_socket) => result,
        result = runtime.run_tcp(tcp_listener) => result,
    }
}

struct MysqlReplayRuntime {
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
}

impl MysqlReplayRuntime {
    async fn load(
        config: MysqlReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
    ) -> Result<Self> {
        let case_dir = config.case_dir;
        let case_dependencies_path = case_dir.join("dependencies.jsonl");
        let bootstrap_path = find_upward(&case_dir, "bootstrap-dependencies.jsonl");
        let mut exchanges = Vec::new();
        let mut targets = BTreeMap::new();
        let mut connection_identities = HashMap::new();
        let fake_cidr = Ipv4Cidr::parse(&config.fake_cidr)?;

        if let Some(path) = &bootstrap_path {
            load_dependency_file(
                path,
                ReplaySource::Bootstrap,
                &mut exchanges,
                &mut targets,
                &mut connection_identities,
            )
            .await?;
        }
        load_dependency_file(
            &case_dependencies_path,
            ReplaySource::Case,
            &mut exchanges,
            &mut targets,
            &mut connection_identities,
        )
        .await?;

        let targets = assign_fake_ips(targets, fake_cidr)?;

        let state = ReplayState {
            dns_listen,
            tcp_listen,
            case_dir,
            case_dependencies_path,
            bootstrap_path,
            targets,
            exchanges,
            events: ReplayEvents::default(),
        };
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            report_path: config.report_path,
        })
    }

    async fn run_tcp(&self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, peer_addr) = listener
                .accept()
                .await
                .context("failed to accept MySQL replay gateway client")?;
            let state = self.state.clone();
            let report_path = self.report_path.clone();
            tokio::spawn(async move {
                if let Err(err) =
                    handle_gateway_connection(stream, peer_addr, state, report_path).await
                {
                    warn!(error = %err, "MySQL replay connection failed");
                }
            });
        }
    }

    async fn run_dns(&self, socket: UdpSocket) -> Result<()> {
        let socket = Arc::new(socket);
        let mut buf = vec![0_u8; 4096];
        loop {
            let (len, peer) = socket
                .recv_from(&mut buf)
                .await
                .context("failed to receive MySQL replay DNS query")?;
            let query = buf[..len].to_vec();
            let socket = socket.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_dns_query(socket, state, query, peer).await {
                    warn!(error = %err, peer = %peer, "failed to handle MySQL replay DNS query");
                }
            });
        }
    }

    async fn write_report(&self) -> Result<()> {
        write_report_snapshot(self.state.clone(), self.report_path.clone()).await
    }
}

#[derive(Debug)]
struct ReplayState {
    dns_listen: SocketAddr,
    tcp_listen: SocketAddr,
    case_dir: PathBuf,
    case_dependencies_path: PathBuf,
    bootstrap_path: Option<PathBuf>,
    targets: Vec<ReplayTarget>,
    exchanges: Vec<ReplayExchange>,
    events: ReplayEvents,
}

impl ReplayState {
    fn record_connection(
        &mut self,
        peer_addr: SocketAddr,
        target: Option<&TargetKey>,
        database: Option<String>,
        username: Option<String>,
    ) {
        self.events.connections += 1;
        self.events.connection_events.push(ConnectionReport {
            peer_addr: peer_addr.to_string(),
            target: target.cloned(),
            database,
            username,
        });
    }

    fn record_builtin(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        reason: &str,
    ) {
        let recorded_match = self.consume_builtin_exchange(identity, command, sql);
        self.events.builtin_queries.push(QueryReport {
            target: identity.target.clone(),
            database: identity.database.clone(),
            username: identity.username.clone(),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            params: None,
            reason: reason.to_string(),
            recorded_source: recorded_match.map(|(source, _)| source),
            recorded_index: recorded_match.map(|(_, index)| index),
        });
    }

    fn record_unsupported(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        reason: &str,
    ) {
        self.events.unsupported_commands.push(QueryReport {
            target: identity.target.clone(),
            database: identity.database.clone(),
            username: identity.username.clone(),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            params: params.map(ToOwned::to_owned),
            reason: reason.to_string(),
            recorded_source: None,
            recorded_index: None,
        });
    }

    fn record_unmatched(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        reason: &str,
    ) {
        self.events.unmatched_queries.push(QueryReport {
            target: identity.target.clone(),
            database: identity.database.clone(),
            username: identity.username.clone(),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            params: params.map(ToOwned::to_owned),
            reason: reason.to_string(),
            recorded_source: None,
            recorded_index: None,
        });
    }

    fn record_metadata_warning(&mut self, warning: String) {
        self.events.metadata_warnings.push(warning);
    }

    fn match_exchange(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<MatchedExchange> {
        let normalized_sql = sql.map(normalize_sql);
        for (index, exchange) in self.exchanges.iter_mut().enumerate() {
            if exchange.consumed || exchange.record.command != command {
                continue;
            }
            if !identity_matches_exchange(identity, &exchange.identity) {
                continue;
            }
            let Some(recorded_sql) = exchange.record.sql.as_deref().map(normalize_sql) else {
                continue;
            };
            if Some(recorded_sql) != normalized_sql {
                continue;
            }
            if !params_match(exchange.record.params.as_deref(), params) {
                continue;
            }
            exchange.consumed = true;
            let matched = MatchedQueryReport {
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
                source: exchange.source,
                index,
                command: command.to_string(),
                sql: sql.map(ToOwned::to_owned),
                params: params.map(ToOwned::to_owned),
                status: exchange.record.response.status.clone(),
            };
            self.events.matched_queries.push(matched);
            return Some(MatchedExchange {
                source: exchange.source,
                index,
                record: exchange.record.clone(),
            });
        }
        None
    }

    fn consume_builtin_exchange(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
    ) -> Option<(ReplaySource, usize)> {
        let normalized_sql = sql.map(normalize_sql);
        for (index, exchange) in self.exchanges.iter_mut().enumerate() {
            if exchange.consumed || exchange.record.command != command {
                continue;
            }
            if !identity_matches_exchange(identity, &exchange.identity) {
                continue;
            }
            let recorded_sql = exchange.record.sql.as_deref().map(normalize_sql);
            if recorded_sql != normalized_sql {
                continue;
            }
            exchange.consumed = true;
            return Some((exchange.source, index));
        }
        None
    }

    fn statement_metadata(&self, identity: &ReplaySessionIdentity, sql: &str) -> StatementMetadata {
        let normalized_sql = normalize_sql(sql);
        for exchange in &self.exchanges {
            if exchange.record.command != "COM_STMT_EXECUTE" {
                continue;
            }
            if !identity_matches_exchange(identity, &exchange.identity) {
                continue;
            }
            if exchange
                .record
                .sql
                .as_deref()
                .is_some_and(|recorded_sql| normalize_sql(recorded_sql) == normalized_sql)
            {
                return StatementMetadata {
                    param_count: exchange
                        .record
                        .params
                        .as_ref()
                        .map_or_else(|| count_sql_placeholders(sql), Vec::len),
                    columns: exchange.record.response.columns.clone(),
                };
            }
        }
        StatementMetadata {
            param_count: count_sql_placeholders(sql),
            columns: Vec::new(),
        }
    }

    fn snapshot_report(&self) -> ReplayReport {
        ReplayReport {
            version: 1,
            dns_listen: self.dns_listen.to_string(),
            tcp_listen: self.tcp_listen.to_string(),
            case_dir: self.case_dir.display().to_string(),
            case_dependencies_path: self.case_dependencies_path.display().to_string(),
            bootstrap_dependencies_path: self
                .bootstrap_path
                .as_ref()
                .map(|path| path.display().to_string()),
            targets: self.targets.clone(),
            connections: self.events.connections,
            connection_events: self.events.connection_events.clone(),
            builtin_queries: self.events.builtin_queries.clone(),
            matched_queries: self.events.matched_queries.clone(),
            unmatched_queries: self.events.unmatched_queries.clone(),
            unsupported_commands: self.events.unsupported_commands.clone(),
            metadata_warnings: self.events.metadata_warnings.clone(),
            unused_bootstrap_exchanges: self.unused_exchanges(ReplaySource::Bootstrap),
            unused_case_exchanges: self.unused_exchanges(ReplaySource::Case),
        }
    }

    fn unused_exchanges(&self, source: ReplaySource) -> Vec<RecordedExchangeSummary> {
        self.exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.source == source && !exchange.consumed)
            .map(|(index, exchange)| RecordedExchangeSummary {
                index,
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
                command: exchange.record.command.clone(),
                sql: exchange.record.sql.clone(),
                status: exchange.record.response.status.clone(),
            })
            .collect()
    }
}

include!("mysql_replay_records.rs");
include!("mysql_replay_dns.rs");
async fn handle_gateway_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    let target = replay_target_for_stream(&stream, &state).await;
    handle_replay_connection(stream, peer_addr, target, state, report_path).await
}

async fn replay_target_for_stream(
    stream: &TcpStream,
    state: &Arc<Mutex<ReplayState>>,
) -> Option<TargetKey> {
    let original = original_dst(stream).ok();
    let state = state.lock().await;
    if let Some(SocketAddr::V4(addr)) = original {
        let ip = *addr.ip();
        let port = addr.port();
        if let Some(target) = state
            .targets
            .iter()
            .find(|target| target.fake_ip == ip && target.port == port)
        {
            return Some(TargetKey {
                host: target.host.clone(),
                port: target.port,
            });
        }
    }
    if state.targets.len() == 1 {
        let target = &state.targets[0];
        return Some(TargetKey {
            host: target.host.clone(),
            port: target.port,
        });
    }
    None
}

fn original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len as *mut _,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("getsockopt SO_ORIGINAL_DST failed");
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

async fn handle_replay_connection(
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

include!("mysql_replay_session.rs");
include!("mysql_replay_response.rs");
include!("mysql_replay_values.rs");
include!("mysql_replay_tests.rs");
