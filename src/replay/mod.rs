use std::collections::{BTreeMap, HashMap};
use std::future::pending;
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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

use crate::MitmCa;
use crate::mysql_protocol::{
    CLIENT_CONNECT_WITH_DB, CLIENT_SECURE_CONNECTION, MysqlPacket, parse_client_command,
    parse_handshake_response, read_packet,
};

mod cache;
#[cfg(test)]
mod cache_tests;
mod control;
mod dns;
mod http;
mod kafka;
#[cfg(test)]
#[path = "tests.rs"]
mod legacy_tests;
mod records;
mod response;
mod session;
mod values;

use control::*;
use dns::*;
use records::*;
use response::*;
use session::*;
use values::*;

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
pub struct ReplayConfig {
    pub case_dir: PathBuf,
    pub dns_listen: SocketAddr,
    pub tcp_listen: SocketAddr,
    pub fake_cidr: String,
    pub report_path: Option<PathBuf>,
    pub session_path: Option<PathBuf>,
    pub control_socket_path: Option<PathBuf>,
    pub ca_cert_path: Option<PathBuf>,
    pub ca_key_path: Option<PathBuf>,
    pub http_ignore_query_params: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReplayControlConfig {
    pub session_path: PathBuf,
    pub command: String,
    pub case_id: Option<String>,
    pub fail_on_dirty: bool,
}

pub type MysqlReplayControlConfig = ReplayControlConfig;

pub async fn run_replay_control(config: ReplayControlConfig) -> Result<Value> {
    send_control_request(config).await
}

pub async fn run_mysql_replay_control(config: MysqlReplayControlConfig) -> Result<Value> {
    run_replay_control(config).await
}

pub async fn run_replay(config: ReplayConfig) -> Result<()> {
    let tcp_listener = TcpListener::bind(config.tcp_listen)
        .await
        .with_context(|| {
            format!(
                "failed to bind dependency replay gateway {}",
                config.tcp_listen
            )
        })?;
    let tcp_listen = tcp_listener
        .local_addr()
        .context("failed to read dependency replay gateway listen address")?;
    let dns_socket = UdpSocket::bind(config.dns_listen)
        .await
        .with_context(|| format!("failed to bind dependency replay DNS {}", config.dns_listen))?;
    let dns_listen = dns_socket
        .local_addr()
        .context("failed to read dependency replay DNS listen address")?;
    let runtime = ReplayRuntime::load(config, dns_listen, tcp_listen).await?;
    runtime.write_report().await?;
    info!(
        dns_listen = %dns_listen,
        tcp_listen = %tcp_listen,
        "dependency replay intercept listening"
    );
    tokio::select! {
        result = runtime.run_dns(dns_socket) => result,
        result = runtime.run_tcp(tcp_listener) => result,
        result = runtime.run_control() => result,
    }
}

pub type MysqlReplayConfig = ReplayConfig;

pub async fn run_mysql_replay(config: MysqlReplayConfig) -> Result<()> {
    run_replay(config).await
}

struct ReplayRuntime {
    state: Arc<Mutex<ReplayState>>,
    ca: Arc<MitmCa>,
    report_path: Option<PathBuf>,
    session_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
}

impl ReplayRuntime {
    async fn load(
        config: ReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
    ) -> Result<Self> {
        let root_dir = config.case_dir;
        let replay_artifact_dir = config
            .report_path
            .as_ref()
            .and_then(|path| path.parent())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root_dir.join(".replay"));
        let ca_cert_path = config
            .ca_cert_path
            .unwrap_or_else(|| replay_artifact_dir.join("replay-ca.pem"));
        let ca_key_path = config
            .ca_key_path
            .unwrap_or_else(|| replay_artifact_dir.join("replay-ca-key.pem"));
        let ca = Arc::new(MitmCa::load_or_generate(&ca_cert_path, &ca_key_path)?);
        let (mode, mut cases, active_case_id) = discover_replay_cases(&root_dir).await?;
        let bootstrap_path = find_upward(&root_dir, "bootstrap-dependencies.jsonl");
        let mut exchanges = Vec::new();
        let mut http_exchanges = Vec::new();
        let mut cache = cache::CacheReplayState::default();
        let mut kafka = kafka::KafkaReplayState::default();
        let mut targets = BTreeMap::new();
        let mut connection_identities = HashMap::new();
        let fake_cidr = Ipv4Cidr::parse(&config.fake_cidr)?;

        if let Some(path) = &bootstrap_path {
            load_dependency_file(
                path,
                ReplaySource::Bootstrap,
                None,
                &mut exchanges,
                &mut http_exchanges,
                &mut cache,
                &mut kafka,
                &mut targets,
                &mut connection_identities,
            )
            .await?;
        }
        for case in cases.values() {
            load_dependency_file(
                &case.dependencies_path,
                ReplaySource::Case,
                Some(&case.id),
                &mut exchanges,
                &mut http_exchanges,
                &mut cache,
                &mut kafka,
                &mut targets,
                &mut connection_identities,
            )
            .await?;
        }

        let targets = assign_fake_ips(targets, fake_cidr)?;
        if let Some(case_id) = &active_case_id
            && let Some(case) = cases.get_mut(case_id)
        {
            case.status = ReplayCaseStatus::Active;
        }

        let state = ReplayState {
            session_id: Uuid::new_v4(),
            dns_listen,
            tcp_listen,
            mode,
            root_dir,
            cases,
            active_case_id,
            bootstrap_path,
            targets,
            exchanges,
            http_exchanges,
            cache,
            kafka,
            events: ReplayEvents::default(),
            http_events: http::HttpReplayEvents::default(),
            report_write_lock: Arc::new(Mutex::new(())),
            ca_cert_path,
            http_ignore_query_params: config
                .http_ignore_query_params
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
        };
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            ca,
            report_path: config.report_path,
            session_path: config.session_path,
            control_socket_path: config.control_socket_path,
        })
    }

    async fn run_tcp(&self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, peer_addr) = listener
                .accept()
                .await
                .context("failed to accept dependency replay gateway client")?;
            let state = self.state.clone();
            let ca = self.ca.clone();
            let report_path = self.report_path.clone();
            tokio::spawn(async move {
                if let Err(err) =
                    handle_gateway_connection(stream, peer_addr, state, report_path, ca).await
                {
                    warn!(error = %err, "dependency replay connection failed");
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
                .context("failed to receive dependency replay DNS query")?;
            let query = buf[..len].to_vec();
            let socket = socket.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_dns_query(socket, state, query, peer).await {
                    warn!(error = %err, peer = %peer, "failed to handle dependency replay DNS query");
                }
            });
        }
    }

    async fn write_report(&self) -> Result<()> {
        write_report_snapshot(self.state.clone(), self.report_path.clone()).await
    }

    async fn run_control(&self) -> Result<()> {
        run_control_socket(
            self.state.clone(),
            self.report_path.clone(),
            self.session_path.clone(),
            self.control_socket_path.clone(),
        )
        .await
    }
}

#[derive(Debug)]
struct ReplayState {
    session_id: Uuid,
    dns_listen: SocketAddr,
    tcp_listen: SocketAddr,
    mode: ReplayMode,
    root_dir: PathBuf,
    cases: BTreeMap<String, ReplayCase>,
    active_case_id: Option<String>,
    bootstrap_path: Option<PathBuf>,
    targets: Vec<ReplayTarget>,
    exchanges: Vec<ReplayExchange>,
    http_exchanges: Vec<http::ReplayHttpExchange>,
    cache: cache::CacheReplayState,
    kafka: kafka::KafkaReplayState,
    events: ReplayEvents,
    http_events: http::HttpReplayEvents,
    report_write_lock: Arc<Mutex<()>>,
    ca_cert_path: PathBuf,
    http_ignore_query_params: Vec<String>,
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
            case_id: self.active_case_id.clone(),
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
            case_id: self.active_case_id.clone(),
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
            case_id: self.active_case_id.clone(),
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
        let active_case_id = self.active_case_id.clone();
        for (index, exchange) in self.exchanges.iter_mut().enumerate() {
            if exchange.consumed || exchange.record.command != command {
                continue;
            }
            if !active_case_matches(active_case_id.as_deref(), exchange) {
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
                case_id: exchange.case_id.clone(),
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
        let active_case_id = self.active_case_id.clone();
        for (index, exchange) in self.exchanges.iter_mut().enumerate() {
            if exchange.consumed || exchange.record.command != command {
                continue;
            }
            if !active_case_matches(active_case_id.as_deref(), exchange) {
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
            if !self.active_case_matches(exchange) {
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
            version: 3,
            mode: self.mode,
            dns_listen: self.dns_listen.to_string(),
            tcp_listen: self.tcp_listen.to_string(),
            case_dir: self.root_dir.display().to_string(),
            case_dependencies_path: self
                .cases
                .values()
                .next()
                .map(|case| case.dependencies_path.display().to_string())
                .unwrap_or_default(),
            active_case_id: self.active_case_id.clone(),
            cases: self.case_reports(),
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
            matched_http_exchanges: self.http_events.matched.clone(),
            unmatched_http_requests: self.http_events.unmatched.clone(),
            unsupported_http_exchanges: self.http_events.unsupported.clone(),
            unused_bootstrap_http_exchanges: self.unused_http_exchanges(ReplaySource::Bootstrap),
            unused_case_http_exchanges: self.unused_http_exchanges(ReplaySource::Case),
            protocols: ProtocolsReport {
                cache: self.cache.snapshot(),
                kafka: self.kafka.snapshot(),
            },
            ca_cert_path: self.ca_cert_path.display().to_string(),
            http_ignored_query_params: self.http_ignore_query_params.clone(),
        }
    }

    fn unused_exchanges(&self, source: ReplaySource) -> Vec<RecordedExchangeSummary> {
        self.exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.source == source && !exchange.consumed)
            .map(|(index, exchange)| RecordedExchangeSummary {
                index,
                case_id: exchange.case_id.clone(),
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
                command: exchange.record.command.clone(),
                sql: exchange.record.sql.clone(),
                status: exchange.record.response.status.clone(),
            })
            .collect()
    }

    fn active_case_matches(&self, exchange: &ReplayExchange) -> bool {
        active_case_matches(self.active_case_id.as_deref(), exchange)
    }

    fn case_reports(&self) -> Vec<ReplayCaseReport> {
        self.cases
            .values()
            .map(|case| ReplayCaseReport {
                case_id: case.id.clone(),
                case_dir: case.dir.display().to_string(),
                dependencies_path: case.dependencies_path.display().to_string(),
                status: case.status,
            })
            .collect()
    }
}

async fn handle_gateway_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
    ca: Arc<MitmCa>,
) -> Result<()> {
    let target = replay_target_for_stream(&stream, &state).await;
    match target.as_ref().map(|target| target.protocol) {
        Some(ReplayProtocol::Http) | Some(ReplayProtocol::Https) => {
            http::handle_http_replay_connection(
                stream,
                peer_addr,
                target.context("HTTP replay connection has no target")?,
                state,
                report_path,
                ca,
            )
            .await
        }
        Some(ReplayProtocol::Redis) => {
            cache::handle_redis_connection(
                stream,
                target.context("Redis replay connection has no target")?,
                state,
                report_path,
            )
            .await
        }
        Some(ReplayProtocol::Memcached) => {
            cache::handle_memcached_connection(
                stream,
                target.context("Memcached replay connection has no target")?,
                state,
                report_path,
            )
            .await
        }
        Some(ReplayProtocol::Kafka) => {
            kafka::handle_connection(
                stream,
                target.context("Kafka replay connection has no target")?,
                state,
                report_path,
            )
            .await
        }
        Some(ReplayProtocol::Mysql) | None => {
            let target = target.map(|target| TargetKey {
                host: target.host,
                port: target.port,
            });
            handle_replay_connection(stream, peer_addr, target, state, report_path).await
        }
    }
}

async fn replay_target_for_stream(
    stream: &TcpStream,
    state: &Arc<Mutex<ReplayState>>,
) -> Option<ReplayTarget> {
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
            return Some(target.clone());
        }
    }
    if state.targets.len() == 1 {
        let target = &state.targets[0];
        return Some(target.clone());
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
