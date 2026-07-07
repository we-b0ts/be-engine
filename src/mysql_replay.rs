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

#[derive(Debug, Default)]
struct ReplayEvents {
    connections: usize,
    connection_events: Vec<ConnectionReport>,
    builtin_queries: Vec<QueryReport>,
    matched_queries: Vec<MatchedQueryReport>,
    unmatched_queries: Vec<QueryReport>,
    unsupported_commands: Vec<QueryReport>,
    metadata_warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct ReplayExchange {
    source: ReplaySource,
    identity: MysqlDependencyIdentity,
    record: RecordedMysqlExchange,
    consumed: bool,
}

#[derive(Debug, Clone)]
struct MatchedExchange {
    #[allow(dead_code)]
    source: ReplaySource,
    #[allow(dead_code)]
    index: usize,
    record: RecordedMysqlExchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReplaySource {
    Bootstrap,
    Case,
}

#[derive(Debug, Serialize)]
struct ReplayReport {
    version: u8,
    dns_listen: String,
    tcp_listen: String,
    case_dir: String,
    case_dependencies_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bootstrap_dependencies_path: Option<String>,
    targets: Vec<ReplayTarget>,
    connections: usize,
    connection_events: Vec<ConnectionReport>,
    builtin_queries: Vec<QueryReport>,
    matched_queries: Vec<MatchedQueryReport>,
    unmatched_queries: Vec<QueryReport>,
    unsupported_commands: Vec<QueryReport>,
    metadata_warnings: Vec<String>,
    unused_bootstrap_exchanges: Vec<RecordedExchangeSummary>,
    unused_case_exchanges: Vec<RecordedExchangeSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct ConnectionReport {
    peer_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct QueryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Vec<RecordedMysqlValue>>,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recorded_source: Option<ReplaySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recorded_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct MatchedQueryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    source: ReplaySource,
    index: usize,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Vec<RecordedMysqlValue>>,
    status: String,
}

#[derive(Debug, Clone, Serialize)]
struct RecordedExchangeSummary {
    index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<String>,
    status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
struct TargetKey {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayTarget {
    host: String,
    port: u16,
    fake_ip: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MysqlDependencyIdentity {
    target: TargetKey,
    database: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Clone)]
struct ReplaySessionIdentity {
    target: Option<TargetKey>,
    database: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
enum DependencyRecord {
    MysqlConnection(Box<RecordedMysqlConnection>),
    MysqlExchange(Box<RecordedMysqlExchange>),
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedMysqlConnection {
    id: Uuid,
    target_host: Option<String>,
    target_port: Option<u16>,
    target_addr: Option<String>,
    database: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedMysqlExchange {
    connection_id: Option<Uuid>,
    target_host: Option<String>,
    target_port: Option<u16>,
    target_addr: Option<String>,
    database: Option<String>,
    username: Option<String>,
    command: String,
    sql: Option<String>,
    params: Option<Vec<RecordedMysqlValue>>,
    response: RecordedMysqlResponse,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedMysqlResponse {
    status: String,
    error_code: Option<u16>,
    error_message: Option<String>,
    affected_rows: Option<u64>,
    last_insert_id: Option<u64>,
    #[serde(default)]
    columns: Vec<RecordedMysqlColumn>,
    #[serde(default)]
    rows: Vec<Vec<RecordedMysqlValue>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedMysqlColumn {
    name: String,
    table: Option<String>,
    column: Option<String>,
    family: String,
    sql_type: String,
    unsigned: Option<bool>,
    bits: Option<u16>,
    nullable: Option<bool>,
    scale: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct RecordedMysqlValue {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<ReplayBodyCapture>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct ReplayBodyCapture {
    encoding: String,
    data: String,
}

#[derive(Debug, Clone)]
struct StatementMetadata {
    param_count: usize,
    columns: Vec<RecordedMysqlColumn>,
}

#[derive(Debug, Clone)]
struct PreparedStatement {
    sql: String,
    param_count: usize,
    last_param_types: Vec<BoundParamType>,
}

#[derive(Debug, Clone)]
struct BoundParamType {
    type_code: u8,
    unsigned: bool,
}

#[derive(Debug, Clone, Copy)]
enum ResultRowEncoding {
    Text,
    Binary,
}

async fn load_dependency_file(
    path: &Path,
    source: ReplaySource,
    exchanges: &mut Vec<ReplayExchange>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    connection_identities: &mut HashMap<Uuid, MysqlDependencyIdentity>,
) -> Result<()> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read dependency replay file {}", path.display()))?;
    let mut records = Vec::new();
    for (line_index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: DependencyRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "failed to parse dependency replay line {} in {}",
                line_index + 1,
                path.display()
            )
        })?;
        records.push(record);
    }

    for record in &records {
        let DependencyRecord::MysqlConnection(connection) = record else {
            continue;
        };
        if let Some(identity) = identity_from_connection(connection) {
            let target = identity.target.clone();
            targets
                .entry(target.clone())
                .or_insert_with(|| ReplayTarget {
                    host: target.host.clone(),
                    port: target.port,
                    fake_ip: Ipv4Addr::UNSPECIFIED,
                });
            connection_identities.insert(connection.id, identity);
        }
    }

    for record in records {
        let DependencyRecord::MysqlExchange(exchange) = record else {
            continue;
        };
        if exchange.command == "COM_STMT_PREPARE" && exchange.response.status == "stmt_prepare" {
            continue;
        }
        let identity = identity_from_exchange(&exchange)
            .or_else(|| {
                exchange
                    .connection_id
                    .and_then(|connection_id| connection_identities.get(&connection_id).cloned())
            })
            .with_context(|| {
                format!(
                    "mysql_exchange in {} lacks business target/database identity for SQL {:?}",
                    path.display(),
                    exchange.sql
                )
            })?;
        targets
            .entry(identity.target.clone())
            .or_insert_with(|| ReplayTarget {
                host: identity.target.host.clone(),
                port: identity.target.port,
                fake_ip: Ipv4Addr::UNSPECIFIED,
            });
        exchanges.push(ReplayExchange {
            source,
            identity,
            record: *exchange,
            consumed: false,
        });
    }
    Ok(())
}

fn find_upward(start: &Path, filename: &str) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join(filename);
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

fn identity_from_connection(
    connection: &RecordedMysqlConnection,
) -> Option<MysqlDependencyIdentity> {
    let target = target_from_connection(connection)?;
    Some(MysqlDependencyIdentity {
        target,
        database: normalize_optional(&connection.database),
        username: normalize_optional(&connection.username),
    })
}

fn identity_from_exchange(exchange: &RecordedMysqlExchange) -> Option<MysqlDependencyIdentity> {
    let target = target_from_exchange(exchange)?;
    Some(MysqlDependencyIdentity {
        target,
        database: normalize_optional(&exchange.database),
        username: normalize_optional(&exchange.username),
    })
}

fn target_from_connection(connection: &RecordedMysqlConnection) -> Option<TargetKey> {
    if let (Some(host), Some(port)) = (&connection.target_host, connection.target_port) {
        return Some(TargetKey {
            host: normalize_host(host),
            port,
        });
    }
    if let Some(target_addr) = &connection.target_addr
        && let Some(target) = target_from_addr(target_addr)
    {
        return Some(target);
    }
    None
}

fn target_from_exchange(exchange: &RecordedMysqlExchange) -> Option<TargetKey> {
    if let (Some(host), Some(port)) = (&exchange.target_host, exchange.target_port) {
        return Some(TargetKey {
            host: normalize_host(host),
            port,
        });
    }
    if let Some(target_addr) = &exchange.target_addr
        && let Some(target) = target_from_addr(target_addr)
    {
        return Some(target);
    }
    None
}

fn target_from_addr(value: &str) -> Option<TargetKey> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(TargetKey {
            host: normalize_host(&addr.ip().to_string()),
            port: addr.port(),
        });
    }
    let (host, port) = value.rsplit_once(':')?;
    Some(TargetKey {
        host: normalize_host(host.trim_start_matches('[').trim_end_matches(']')),
        port: port.parse().ok()?,
    })
}

fn assign_fake_ips(
    targets: BTreeMap<TargetKey, ReplayTarget>,
    fake_cidr: Ipv4Cidr,
) -> Result<Vec<ReplayTarget>> {
    let mut out = Vec::with_capacity(targets.len());
    for (offset, (_, mut target)) in targets.into_iter().enumerate() {
        let offset = u32::try_from(offset + 1).context("too many replay targets")?;
        target.fake_ip = fake_cidr
            .ip_at(offset)
            .ok_or_else(|| anyhow!("fake CIDR exhausted by replay targets"))?;
        out.push(target);
    }
    Ok(out)
}

fn identity_matches_exchange(
    session: &ReplaySessionIdentity,
    exchange: &MysqlDependencyIdentity,
) -> bool {
    session.target.as_ref() == Some(&exchange.target)
        && normalize_identity_value(session.database.as_deref())
            == normalize_identity_value(exchange.database.as_deref())
        && normalize_identity_value(session.username.as_deref())
            == normalize_identity_value(exchange.username.as_deref())
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_identity_value(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn normalize_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[derive(Debug)]
struct DnsQuestion {
    domain: String,
    qtype: u16,
    qclass: u16,
    question_end: usize,
}

async fn handle_dns_query(
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<ReplayState>>,
    query: Vec<u8>,
    peer: SocketAddr,
) -> Result<()> {
    let question = parse_dns_question(&query)?;
    let fake_ip = if question.qtype == 1 && question.qclass == 1 {
        let state = state.lock().await;
        state
            .targets
            .iter()
            .find(|target| normalize_host(&target.host) == question.domain)
            .map(|target| target.fake_ip)
    } else {
        None
    };
    let response = match fake_ip {
        Some(fake_ip) => build_dns_a_response(&query, question.question_end, fake_ip)?,
        None => build_dns_empty_response(&query, question.question_end)?,
    };
    socket
        .send_to(&response, peer)
        .await
        .context("failed to send MySQL replay DNS response")?;
    Ok(())
}

fn parse_dns_question(packet: &[u8]) -> Result<DnsQuestion> {
    if packet.len() < 12 {
        return Err(anyhow!("DNS packet too short"));
    }
    let qdcount = read_be_u16(packet, 4)?;
    if qdcount == 0 {
        return Err(anyhow!("DNS packet has no questions"));
    }
    let (domain, offset) = read_dns_name(packet, 12)?;
    let qtype = read_be_u16(packet, offset)?;
    let qclass = read_be_u16(packet, offset + 2)?;
    Ok(DnsQuestion {
        domain: normalize_host(&domain),
        qtype,
        qclass,
        question_end: offset + 4,
    })
}

fn build_dns_empty_response(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    let mut response = Vec::with_capacity(question_end);
    response.extend_from_slice(query.get(0..2).ok_or_else(|| anyhow!("missing DNS id"))?);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(
        query
            .get(12..question_end)
            .ok_or_else(|| anyhow!("missing DNS question"))?,
    );
    Ok(response)
}

fn build_dns_a_response(query: &[u8], question_end: usize, fake_ip: Ipv4Addr) -> Result<Vec<u8>> {
    let mut response = build_dns_empty_response(query, question_end)?;
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0xC00C_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&fake_ip.octets());
    Ok(response)
}

fn read_dns_name(packet: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut consumed_end = None;
    let mut jumps = 0;

    loop {
        let len = *packet
            .get(cursor)
            .ok_or_else(|| anyhow!("DNS name out of bounds"))?;
        if len & 0xC0 == 0xC0 {
            let next = *packet
                .get(cursor + 1)
                .ok_or_else(|| anyhow!("DNS compression pointer out of bounds"))?;
            let pointer = (((len & 0x3F) as usize) << 8) | next as usize;
            consumed_end.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps += 1;
            if jumps > 16 {
                return Err(anyhow!("too many DNS compression jumps"));
            }
            continue;
        }
        if len == 0 {
            let end = consumed_end.unwrap_or(cursor + 1);
            return Ok((labels.join("."), end));
        }
        cursor += 1;
        let label = packet
            .get(cursor..cursor + len as usize)
            .ok_or_else(|| anyhow!("DNS label out of bounds"))?;
        labels.push(String::from_utf8_lossy(label).to_string());
        cursor += len as usize;
    }
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Cidr {
    network: u32,
    size: u32,
}

impl Ipv4Cidr {
    fn parse(value: &str) -> Result<Self> {
        let (ip, prefix) = value
            .split_once('/')
            .ok_or_else(|| anyhow!("CIDR must contain / prefix: {value}"))?;
        let ip = ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 CIDR address {ip}"))?;
        let prefix = prefix
            .parse::<u32>()
            .with_context(|| format!("invalid IPv4 CIDR prefix {prefix}"))?;
        if !(1..=30).contains(&prefix) {
            return Err(anyhow!("IPv4 CIDR prefix must be between 1 and 30"));
        }
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(ip) & mask;
        let size = 1_u32 << (32 - prefix);
        Ok(Self { network, size })
    }

    fn ip_at(&self, offset: u32) -> Option<Ipv4Addr> {
        if offset >= self.size {
            return None;
        }
        Some(Ipv4Addr::from(self.network + offset))
    }
}

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

async fn write_response(
    stream: &mut TcpStream,
    response: &RecordedMysqlResponse,
    row_encoding: ResultRowEncoding,
) -> Result<()> {
    match response.status.as_str() {
        "resultset" => {
            write_resultset(stream, &response.columns, &response.rows, row_encoding).await
        }
        "ok" => {
            write_packet(
                stream,
                MysqlPacket {
                    sequence_id: 1,
                    payload: ok_payload(
                        response.affected_rows.unwrap_or_default(),
                        response.last_insert_id.unwrap_or_default(),
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

async fn write_stmt_prepare_ok(
    stream: &mut TcpStream,
    statement_id: u32,
    metadata: &StatementMetadata,
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
    sequence_id += 1;

    for index in 0..metadata.param_count {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: column_definition_payload(&RecordedMysqlColumn {
                    name: format!("param_{}", index + 1),
                    table: None,
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
        sequence_id += 1;
    }
    if metadata.param_count > 0 {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: eof_payload(),
            },
        )
        .await?;
        sequence_id += 1;
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
        sequence_id += 1;
    }
    if !metadata.columns.is_empty() {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: eof_payload(),
            },
        )
        .await?;
    }
    Ok(())
}

async fn write_resultset(
    stream: &mut TcpStream,
    columns: &[RecordedMysqlColumn],
    rows: &[Vec<RecordedMysqlValue>],
    row_encoding: ResultRowEncoding,
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
    sequence_id += 1;

    for column in columns {
        write_packet(
            stream,
            MysqlPacket {
                sequence_id,
                payload: column_definition_payload(column),
            },
        )
        .await?;
        sequence_id += 1;
    }
    write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: eof_payload(),
        },
    )
    .await?;
    sequence_id += 1;

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
        sequence_id += 1;
    }
    write_packet(
        stream,
        MysqlPacket {
            sequence_id,
            payload: eof_payload(),
        },
    )
    .await
}

async fn write_packet(stream: &mut TcpStream, packet: MysqlPacket) -> Result<()> {
    stream
        .write_all(&packet.to_wire_bytes())
        .await
        .context("failed to write MySQL replay packet")
}

fn handshake_packet(connection_id: u32) -> MysqlPacket {
    let capabilities = CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_PROTOCOL_41
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

fn mysql_replay_auth_plugin_data_len() -> u8 {
    u8::try_from(MYSQL_REPLAY_AUTH_PLUGIN_DATA_1.len() + MYSQL_REPLAY_AUTH_PLUGIN_DATA_2.len() + 1)
        .expect("MySQL replay auth plugin data length fits u8")
}

fn ok_payload(affected_rows: u64, last_insert_id: u64) -> Vec<u8> {
    let mut payload = vec![0x00];
    payload.extend_from_slice(&lenenc_int(affected_rows));
    payload.extend_from_slice(&lenenc_int(last_insert_id));
    payload.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload
}

fn err_payload(code: u16, message: &str) -> Vec<u8> {
    let mut payload = vec![0xff];
    payload.extend_from_slice(&code.to_le_bytes());
    payload.extend_from_slice(b"#HY000");
    payload.extend_from_slice(message.as_bytes());
    payload
}

fn eof_payload() -> Vec<u8> {
    let mut payload = vec![0xfe];
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    payload
}

fn stmt_prepare_ok_payload(statement_id: u32, column_count: u16, param_count: u16) -> Vec<u8> {
    let mut payload = vec![0x00];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.extend_from_slice(&column_count.to_le_bytes());
    payload.extend_from_slice(&param_count.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload
}

fn column_definition_payload(column: &RecordedMysqlColumn) -> Vec<u8> {
    let type_code = column_type_code(column);
    let charset = if type_code == MYSQL_TYPE_VAR_STRING && column.family == "binary" {
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
        column.table.as_deref().unwrap_or_default().as_bytes(),
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

fn text_row_payload(row: &[RecordedMysqlValue]) -> Result<Vec<u8>> {
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

fn binary_row_payload(
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

fn encode_binary_value(
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
            payload.extend_from_slice(&value_as_i64(value)?.to_le_bytes());
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

fn parse_binary_value(
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

fn builtin_response(sql: &str, database: Option<&str>) -> Option<RecordedMysqlResponse> {
    let normalized = normalize_sql(sql);
    if is_builtin_ok(&normalized) {
        return Some(RecordedMysqlResponse {
            status: "ok".to_string(),
            error_code: None,
            error_message: None,
            affected_rows: Some(0),
            last_insert_id: Some(0),
            columns: Vec::new(),
            rows: Vec::new(),
        });
    }
    if normalized == "select database()" {
        return Some(single_string_result("DATABASE()", database.unwrap_or("")));
    }
    if normalized.contains("version()") || normalized.contains("@@version") {
        return Some(single_string_result(
            "VERSION()",
            "8.0.0-traffic-recorder-replay",
        ));
    }
    if normalized.starts_with("show warnings") {
        return Some(RecordedMysqlResponse {
            status: "resultset".to_string(),
            error_code: None,
            error_message: None,
            affected_rows: None,
            last_insert_id: None,
            columns: vec![
                string_column("Level"),
                integer_column("Code"),
                string_column("Message"),
            ],
            rows: Vec::new(),
        });
    }
    if normalized.starts_with("show variables") {
        return Some(RecordedMysqlResponse {
            status: "resultset".to_string(),
            error_code: None,
            error_message: None,
            affected_rows: None,
            last_insert_id: None,
            columns: vec![string_column("Variable_name"), string_column("Value")],
            rows: Vec::new(),
        });
    }
    None
}

fn is_builtin_ok(normalized_sql: &str) -> bool {
    normalized_sql.starts_with("set ")
        || matches!(
            normalized_sql,
            "begin" | "start transaction" | "commit" | "rollback"
        )
}

fn single_string_result(name: &str, value: &str) -> RecordedMysqlResponse {
    RecordedMysqlResponse {
        status: "resultset".to_string(),
        error_code: None,
        error_message: None,
        affected_rows: None,
        last_insert_id: None,
        columns: vec![string_column(name)],
        rows: vec![vec![mysql_json("string", Value::String(value.to_string()))]],
    }
}

fn string_column(name: &str) -> RecordedMysqlColumn {
    RecordedMysqlColumn {
        name: name.to_string(),
        table: None,
        column: None,
        family: "string".to_string(),
        sql_type: "VARCHAR".to_string(),
        unsigned: None,
        bits: None,
        nullable: Some(true),
        scale: None,
    }
}

fn integer_column(name: &str) -> RecordedMysqlColumn {
    RecordedMysqlColumn {
        name: name.to_string(),
        table: None,
        column: None,
        family: "integer".to_string(),
        sql_type: "INT".to_string(),
        unsigned: Some(false),
        bits: Some(32),
        nullable: Some(true),
        scale: None,
    }
}

fn params_match(
    recorded: Option<&[RecordedMysqlValue]>,
    actual: Option<&[RecordedMysqlValue]>,
) -> bool {
    match (recorded, actual) {
        (None, None) => true,
        (Some(recorded), Some(actual)) if recorded.len() == actual.len() => recorded
            .iter()
            .zip(actual)
            .all(|(left, right)| left == right),
        _ => false,
    }
}

fn normalize_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut last_was_space = false;
    for ch in sql.chars() {
        let ch = if ch == '`' { continue } else { ch };
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            last_was_space = false;
        }
    }
    let mut compact = out.trim().to_string();
    for pattern in [" = ", " =", "= ", " ,", " (", "( ", " )", ") "] {
        compact = compact.replace(pattern, pattern.trim());
    }
    compact
}

fn count_sql_placeholders(sql: &str) -> usize {
    sql.chars().filter(|ch| *ch == '?').count()
}

fn looks_like_select(sql: &str) -> bool {
    normalize_sql(sql).starts_with("select")
}

fn column_type_code(column: &RecordedMysqlColumn) -> u8 {
    let sql_type = column.sql_type.to_ascii_uppercase();
    match sql_type.as_str() {
        "TINYINT" => MYSQL_TYPE_TINY,
        "SMALLINT" => MYSQL_TYPE_SHORT,
        "MEDIUMINT" => MYSQL_TYPE_INT24,
        "INT" | "INTEGER" => MYSQL_TYPE_LONG,
        "BIGINT" => MYSQL_TYPE_LONGLONG,
        "YEAR" => MYSQL_TYPE_YEAR,
        "FLOAT" => MYSQL_TYPE_FLOAT,
        "DOUBLE" => MYSQL_TYPE_DOUBLE,
        "DECIMAL" | "NUMERIC" => MYSQL_TYPE_NEWDECIMAL,
        "DATE" => MYSQL_TYPE_DATE,
        "TIME" => MYSQL_TYPE_TIME,
        "DATETIME" => MYSQL_TYPE_DATETIME,
        "TIMESTAMP" => MYSQL_TYPE_TIMESTAMP,
        "JSON" => MYSQL_TYPE_JSON,
        "BIT" => MYSQL_TYPE_BIT,
        "NULL" => MYSQL_TYPE_NULL,
        "GEOMETRY" => MYSQL_TYPE_GEOMETRY,
        "BINARY" => MYSQL_TYPE_STRING,
        "VARBINARY" => MYSQL_TYPE_VAR_STRING,
        _ => match column.family.as_str() {
            "integer" => {
                if column.bits == Some(64) {
                    MYSQL_TYPE_LONGLONG
                } else {
                    MYSQL_TYPE_LONG
                }
            }
            "decimal" => MYSQL_TYPE_NEWDECIMAL,
            "float" => MYSQL_TYPE_DOUBLE,
            "date" => MYSQL_TYPE_DATE,
            "time" => MYSQL_TYPE_TIME,
            "datetime" => MYSQL_TYPE_DATETIME,
            "binary" | "string" | "json" => MYSQL_TYPE_VAR_STRING,
            "null" => MYSQL_TYPE_NULL,
            _ => MYSQL_TYPE_VAR_STRING,
        },
    }
}

fn column_length(column: &RecordedMysqlColumn) -> u32 {
    match column_type_code(column) {
        MYSQL_TYPE_TINY => 4,
        MYSQL_TYPE_SHORT | MYSQL_TYPE_YEAR => 6,
        MYSQL_TYPE_INT24 | MYSQL_TYPE_LONG => 11,
        MYSQL_TYPE_LONGLONG => 20,
        MYSQL_TYPE_FLOAT => 12,
        MYSQL_TYPE_DOUBLE => 22,
        MYSQL_TYPE_DATE => 10,
        MYSQL_TYPE_TIME => 16,
        MYSQL_TYPE_DATETIME | MYSQL_TYPE_TIMESTAMP => 26,
        _ => 1024,
    }
}

fn mysql_value_bytes(value: &RecordedMysqlValue) -> Result<Vec<u8>> {
    if let Some(raw) = &value.raw {
        return match raw.encoding.as_str() {
            "base64" => STANDARD
                .decode(&raw.data)
                .context("failed to decode recorded MySQL raw base64 value"),
            "utf8" => Ok(raw.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported recorded raw value encoding {other}")),
        };
    }
    let Some(value) = &value.value else {
        return Ok(Vec::new());
    };
    Ok(match value {
        Value::String(value) => value.as_bytes().to_vec(),
        Value::Number(value) => value.to_string().into_bytes(),
        Value::Bool(value) => {
            if *value {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            }
        }
        other => {
            serde_json::to_vec(other).context("failed to serialize recorded MySQL JSON value")?
        }
    })
}

fn value_as_i64(value: &RecordedMysqlValue) -> Result<i64> {
    if let Some(Value::Number(number)) = &value.value {
        if let Some(value) = number.as_i64() {
            return Ok(value);
        }
        if let Some(value) = number.as_u64() {
            return i64::try_from(value).context("recorded unsigned integer does not fit i64");
        }
    }
    let text = value_as_str(value)?;
    text.parse::<i64>()
        .with_context(|| format!("recorded value `{text}` is not an integer"))
}

fn value_as_f64(value: &RecordedMysqlValue) -> Result<f64> {
    if let Some(Value::Number(number)) = &value.value
        && let Some(value) = number.as_f64()
    {
        return Ok(value);
    }
    let text = value_as_str(value)?;
    text.parse::<f64>()
        .with_context(|| format!("recorded value `{text}` is not a float"))
}

fn value_as_str(value: &RecordedMysqlValue) -> Result<&str> {
    if let Some(Value::String(value)) = &value.value {
        return Ok(value);
    }
    Err(anyhow!("recorded value is not a string"))
}

fn binary_datetime_bytes(value: &str) -> Result<Vec<u8>> {
    let (date, time) = value.split_once(' ').unwrap_or((value, "00:00:00"));
    let mut date_parts = date.split('-');
    let year = date_parts
        .next()
        .unwrap_or("0")
        .parse::<u16>()
        .context("invalid recorded datetime year")?;
    let month = date_parts
        .next()
        .unwrap_or("0")
        .parse::<u8>()
        .context("invalid recorded datetime month")?;
    let day = date_parts
        .next()
        .unwrap_or("0")
        .parse::<u8>()
        .context("invalid recorded datetime day")?;
    let (hms, micros) = time.split_once('.').unwrap_or((time, "0"));
    let mut time_parts = hms.split(':');
    let hour = time_parts.next().unwrap_or("0").parse::<u8>()?;
    let minute = time_parts.next().unwrap_or("0").parse::<u8>()?;
    let second = time_parts.next().unwrap_or("0").parse::<u8>()?;
    let micros = micros.parse::<u32>().unwrap_or_default();
    let mut out = Vec::new();
    if micros > 0 {
        out.push(11);
    } else if hour > 0 || minute > 0 || second > 0 {
        out.push(7);
    } else {
        out.push(4);
    }
    out.extend_from_slice(&year.to_le_bytes());
    out.push(month);
    out.push(day);
    if out[0] >= 7 {
        out.push(hour);
        out.push(minute);
        out.push(second);
    }
    if out[0] == 11 {
        out.extend_from_slice(&micros.to_le_bytes());
    }
    Ok(out)
}

fn binary_time_bytes(value: &str) -> Result<Vec<u8>> {
    let negative = value.starts_with('-');
    let value = value.trim_start_matches('-');
    let (hms, micros) = value.split_once('.').unwrap_or((value, "0"));
    let mut parts = hms.split(':');
    let total_hours = parts.next().unwrap_or("0").parse::<u32>()?;
    let minute = parts.next().unwrap_or("0").parse::<u8>()?;
    let second = parts.next().unwrap_or("0").parse::<u8>()?;
    let days = total_hours / 24;
    let hour = (total_hours % 24) as u8;
    let micros = micros.parse::<u32>().unwrap_or_default();
    let mut out = Vec::new();
    if micros > 0 {
        out.push(12);
    } else {
        out.push(8);
    }
    out.push(u8::from(negative));
    out.extend_from_slice(&days.to_le_bytes());
    out.push(hour);
    out.push(minute);
    out.push(second);
    if micros > 0 {
        out.extend_from_slice(&micros.to_le_bytes());
    }
    Ok(out)
}

fn parse_binary_datetime(payload: &[u8], offset: usize) -> Option<(String, usize)> {
    let len = *payload.get(offset)? as usize;
    let start = offset + 1;
    match len {
        0 => Some(("0000-00-00 00:00:00".to_string(), start)),
        4 => {
            let year = read_u16_le(payload, start)?;
            let month = *payload.get(start + 2)?;
            let day = *payload.get(start + 3)?;
            Some((format!("{year:04}-{month:02}-{day:02}"), start + 4))
        }
        7 | 11 => {
            let year = read_u16_le(payload, start)?;
            let month = *payload.get(start + 2)?;
            let day = *payload.get(start + 3)?;
            let hour = *payload.get(start + 4)?;
            let minute = *payload.get(start + 5)?;
            let second = *payload.get(start + 6)?;
            if len == 11 {
                let micros = read_u32_le(payload, start + 7)?;
                Some((
                    format!(
                        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}"
                    ),
                    start + 11,
                ))
            } else {
                Some((
                    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"),
                    start + 7,
                ))
            }
        }
        _ => None,
    }
}

fn parse_binary_time(payload: &[u8], offset: usize) -> Option<(String, usize)> {
    let len = *payload.get(offset)? as usize;
    let start = offset + 1;
    match len {
        0 => Some(("00:00:00".to_string(), start)),
        8 | 12 => {
            let negative = *payload.get(start)? != 0;
            let days = read_u32_le(payload, start + 1)?;
            let hour = *payload.get(start + 5)? as u32 + days * 24;
            let minute = *payload.get(start + 6)?;
            let second = *payload.get(start + 7)?;
            let sign = if negative { "-" } else { "" };
            if len == 12 {
                let micros = read_u32_le(payload, start + 8)?;
                Some((
                    format!("{sign}{hour:02}:{minute:02}:{second:02}.{micros:06}"),
                    start + 12,
                ))
            } else {
                Some((
                    format!("{sign}{hour:02}:{minute:02}:{second:02}"),
                    start + 8,
                ))
            }
        }
        _ => None,
    }
}

fn read_lenenc_bytes(bytes: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let (len, offset) = read_lenenc_int(bytes, offset)?;
    let len = len as usize;
    Some((bytes.get(offset..offset + len)?, offset + len))
}

fn read_lenenc_int(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(offset)?;
    match first {
        0xfc => Some((read_u16_le(bytes, offset + 1)? as u64, offset + 3)),
        0xfd => {
            let b1 = *bytes.get(offset + 1)? as u64;
            let b2 = *bytes.get(offset + 2)? as u64;
            let b3 = *bytes.get(offset + 3)? as u64;
            Some((b1 | (b2 << 8) | (b3 << 16), offset + 4))
        }
        0xfe => Some((read_u64_le(bytes, offset + 1)?, offset + 9)),
        0xfb => None,
        value => Some((value as u64, offset + 1)),
    }
}

fn lenenc_int(value: u64) -> Vec<u8> {
    match value {
        0..=250 => vec![value as u8],
        251..=0xffff => {
            let mut out = vec![0xfc];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        0x1_0000..=0xff_ffff => {
            vec![
                0xfd,
                (value & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                ((value >> 16) & 0xff) as u8,
            ]
        }
        _ => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&value.to_le_bytes());
            out
        }
    }
}

fn lenenc_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = lenenc_int(value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_be_bytes([
        *bytes
            .get(offset)
            .ok_or_else(|| anyhow!("u16 out of bounds"))?,
        *bytes
            .get(offset + 1)
            .ok_or_else(|| anyhow!("u16 out of bounds"))?,
    ]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn null_bitmap_bit(bitmap: &[u8], index: usize) -> bool {
    let byte_index = index / 8;
    let bit = index % 8;
    bitmap
        .get(byte_index)
        .is_some_and(|byte| byte & (1 << bit) != 0)
}

fn set_null_bitmap_bit(bitmap: &mut [u8], bit_index: usize) {
    let byte_index = bit_index / 8;
    let bit = bit_index % 8;
    if let Some(byte) = bitmap.get_mut(byte_index) {
        *byte |= 1 << bit;
    }
}

fn mysql_null() -> RecordedMysqlValue {
    RecordedMysqlValue {
        kind: "null".to_string(),
        value: None,
        raw: None,
    }
}

fn mysql_json(kind: &str, value: Value) -> RecordedMysqlValue {
    RecordedMysqlValue {
        kind: kind.to_string(),
        value: Some(value),
        raw: None,
    }
}

fn mysql_bytes_or_utf8(bytes: &[u8], force_bytes: bool) -> RecordedMysqlValue {
    if !force_bytes && let Ok(value) = std::str::from_utf8(bytes) {
        return mysql_json("string", Value::String(value.to_string()));
    }
    RecordedMysqlValue {
        kind: "bytes".to_string(),
        value: None,
        raw: Some(ReplayBodyCapture {
            encoding: "base64".to_string(),
            data: STANDARD.encode(bytes),
        }),
    }
}

async fn write_report_snapshot(
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    let Some(report_path) = report_path else {
        return Ok(());
    };
    let report = {
        let state = state.lock().await;
        state.snapshot_report()
    };
    if let Some(parent) = report_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create replay report dir {}", parent.display()))?;
    }
    let mut payload =
        serde_json::to_vec_pretty(&report).context("failed to serialize replay report")?;
    payload.push(b'\n');
    tokio::fs::write(&report_path, payload)
        .await
        .with_context(|| format!("failed to write replay report {}", report_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn handshake_packet_auth_plugin_is_sqlx_compatible() {
        let packet = handshake_packet(7);
        assert_eq!(packet.sequence_id, 0);

        let mut offset = 0;
        assert_eq!(packet.payload[offset], 0x0a);
        offset += 1;
        offset += nul_terminated_len(&packet.payload[offset..]) + 1;
        offset += 4;
        assert_eq!(
            &packet.payload[offset..offset + MYSQL_REPLAY_AUTH_PLUGIN_DATA_1.len()],
            MYSQL_REPLAY_AUTH_PLUGIN_DATA_1
        );
        offset += MYSQL_REPLAY_AUTH_PLUGIN_DATA_1.len();
        assert_eq!(packet.payload[offset], 0);
        offset += 1;

        let capabilities_1 =
            u16::from_le_bytes([packet.payload[offset], packet.payload[offset + 1]]);
        offset += 2;
        offset += 1;
        offset += 2;
        let capabilities_2 =
            u16::from_le_bytes([packet.payload[offset], packet.payload[offset + 1]]);
        offset += 2;
        let capabilities = capabilities_1 as u32 | ((capabilities_2 as u32) << 16);
        assert_ne!(capabilities & CLIENT_SECURE_CONNECTION, 0);
        assert_ne!(capabilities & CLIENT_PLUGIN_AUTH, 0);

        let auth_plugin_data_len = packet.payload[offset];
        offset += 1;
        offset += 10;

        let sqlx_auth_plugin_data_2_len =
            std::cmp::max(auth_plugin_data_len.saturating_sub(9), 12) as usize;
        assert_eq!(
            sqlx_auth_plugin_data_2_len,
            MYSQL_REPLAY_AUTH_PLUGIN_DATA_2.len()
        );
        assert_eq!(
            &packet.payload[offset..offset + sqlx_auth_plugin_data_2_len],
            MYSQL_REPLAY_AUTH_PLUGIN_DATA_2
        );
        offset += sqlx_auth_plugin_data_2_len;
        assert_eq!(packet.payload[offset], 0);
        offset += 1;

        let plugin_len = nul_terminated_len(&packet.payload[offset..]);
        assert_eq!(
            &packet.payload[offset..offset + plugin_len],
            MYSQL_REPLAY_AUTH_PLUGIN
        );
        assert_eq!(offset + plugin_len + 1, packet.payload.len());
    }

    #[test]
    fn binary_replay_column_sets_binary_flag() {
        let payload = column_definition_payload(&RecordedMysqlColumn {
            name: "department_id".to_string(),
            table: Some("user".to_string()),
            column: Some("department_id".to_string()),
            family: "binary".to_string(),
            sql_type: "VARBINARY".to_string(),
            unsigned: None,
            bits: None,
            nullable: Some(true),
            scale: None,
        });
        let (type_code, flags) = replay_column_type_and_flags(&payload);

        assert_eq!(type_code, MYSQL_TYPE_VAR_STRING);
        assert_ne!(flags & MYSQL_FLAG_BINARY, 0);
    }

    #[tokio::test]
    async fn replays_text_query_from_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"appdb","username":"root","command":"COM_QUERY","sql":"SELECT id, name FROM user WHERE id = 1","response":{"status":"resultset","columns":[{"name":"id","table":"user","column":"id","family":"integer","sql_type":"INT","unsigned":false,"bits":32,"nullable":false},{"name":"name","table":"user","column":"name","family":"string","sql_type":"VARCHAR","nullable":false}],"rows":[[{"kind":"integer","value":1},{"kind":"string","value":"alice"}]]}}"#,
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [
                    vec![0x03],
                    b" select  id, name  from `user` where id = 1 ".to_vec(),
                ]
                .concat(),
            },
        )
        .await;

        let column_count = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(column_count.payload, vec![2]);
        let _id_column = read_packet(&mut client).await.unwrap().unwrap();
        let _name_column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(
            row.payload,
            [lenenc_bytes(b"1"), lenenc_bytes(b"alice")].concat()
        );
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();

        wait_for_report_contains(&report_path, r#""command": "COM_QUERY""#).await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["matched_queries"][0]["source"], "case");
        assert_eq!(report["matched_queries"][0]["command"], "COM_QUERY");
        assert!(report["unmatched_queries"].as_array().unwrap().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn builtin_query_consumes_matching_recorded_exchange() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"appdb","username":"root","command":"COM_QUERY","sql":"SET NAMES utf8","response":{"status":"ok","affected_rows":0,"last_insert_id":0}}"#,
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SET NAMES utf8".to_vec()].concat(),
            },
        )
        .await;
        let ok = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(ok.payload[0], 0x00);

        wait_for_report_contains(&report_path, r#""recorded_source": "case""#).await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["builtin_queries"][0]["command"], "COM_QUERY");
        assert_eq!(report["builtin_queries"][0]["sql"], "SET NAMES utf8");
        assert_eq!(report["builtin_queries"][0]["recorded_source"], "case");
        assert_eq!(report["builtin_queries"][0]["recorded_index"], 0);
        assert!(
            report["unused_case_exchanges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        task.abort();
    }

    #[tokio::test]
    async fn replays_prepared_execute_from_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"appdb","username":"root","command":"COM_STMT_EXECUTE","sql":"SELECT name FROM user WHERE id=?","params":[{"kind":"integer","value":42}],"response":{"status":"resultset","columns":[{"name":"name","table":"user","column":"name","family":"string","sql_type":"VARCHAR","nullable":false}],"rows":[[{"kind":"string","value":"alice"}]]}}"#,
        )
        .await
        .unwrap();
        let (addr, task) = spawn_replay(&case_dir, None).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x16], b" select name from user where id = ? ".to_vec()].concat(),
            },
        )
        .await;
        let prepare_ok = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(prepare_ok.payload[0], 0x00);
        let statement_id = read_u32_le(&prepare_ok.payload, 1).unwrap();
        assert_eq!(read_u16_le(&prepare_ok.payload, 5), Some(1));
        assert_eq!(read_u16_le(&prepare_ok.payload, 7), Some(1));
        let _param = read_packet(&mut client).await.unwrap().unwrap();
        let _param_eof = read_packet(&mut client).await.unwrap().unwrap();
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _column_eof = read_packet(&mut client).await.unwrap().unwrap();

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: stmt_execute_long_param(statement_id, 42),
            },
        )
        .await;
        let column_count = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(column_count.payload, vec![1]);
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(
            row.payload,
            [vec![0x00, 0x00], lenenc_bytes(b"alice")].concat()
        );
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn does_not_match_same_sql_on_different_database() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"otherdb","username":"root","command":"COM_QUERY","sql":"SELECT value FROM config","response":{"status":"resultset","columns":[{"name":"value","family":"string","sql_type":"VARCHAR","nullable":false}],"rows":[[{"kind":"string","value":"wrong-db"}]]}}"#,
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SELECT value FROM config".to_vec()].concat(),
            },
        )
        .await;
        let error = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(error.payload[0], 0xff);

        wait_for_report_contains(
            &report_path,
            r#""reason": "no recorded semantic dependency matched this SQL""#,
        )
        .await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["unmatched_queries"][0]["database"], "appdb");
        assert_eq!(report["unused_case_exchanges"][0]["database"], "otherdb");
        task.abort();
    }

    #[tokio::test]
    async fn loads_bootstrap_dependencies_from_parent_directory() {
        let temp = tempfile::tempdir().unwrap();
        let group_dir = temp.path().join("record-api").join("api-user");
        let case_dir = group_dir.join("case-id");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            group_dir.join("bootstrap-dependencies.jsonl"),
            r#"{"event_type":"mysql_exchange","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","database":"appdb","username":"root","command":"COM_QUERY","sql":"SELECT value FROM app_config","response":{"status":"resultset","columns":[{"name":"value","family":"string","sql_type":"VARCHAR","nullable":false}],"rows":[[{"kind":"string","value":"on"}]]}}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SELECT value FROM app_config".to_vec()].concat(),
            },
        )
        .await;
        assert_eq!(
            read_packet(&mut client).await.unwrap().unwrap().payload,
            vec![1]
        );
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(row.payload, lenenc_bytes(b"on"));
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();

        wait_for_report_contains(&report_path, r#""source": "bootstrap""#).await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(
            report["bootstrap_dependencies_path"],
            group_dir
                .join("bootstrap-dependencies.jsonl")
                .display()
                .to_string()
        );
        assert_eq!(report["matched_queries"][0]["source"], "bootstrap");
        task.abort();
    }

    #[tokio::test]
    async fn discovers_target_from_mysql_connection_and_reports_mapping() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        let connection_id = Uuid::new_v4();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            format!(
                r#"{{"event_type":"mysql_connection","id":"{connection_id}","target_host":"mysql-user.internal","target_port":3306,"target_addr":"mysql-user.internal:3306","upstream_addr":"10.1.2.3:3306","database":"appdb","username":"root"}}
{{"event_type":"mysql_exchange","connection_id":"{connection_id}","command":"COM_QUERY","sql":"SELECT id FROM user","response":{{"status":"resultset","columns":[{{"name":"id","family":"integer","sql_type":"INT","nullable":false}}],"rows":[[{{"kind":"integer","value":7}}]]}}}}"#
            ),
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = connect_login(addr).await;

        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SELECT id FROM user".to_vec()].concat(),
            },
        )
        .await;
        assert_eq!(
            read_packet(&mut client).await.unwrap().unwrap().payload,
            vec![1]
        );
        let _column = read_packet(&mut client).await.unwrap().unwrap();
        let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
        let row = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(row.payload, lenenc_bytes(b"7"));
        let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();

        wait_for_report_contains(&report_path, "mysql-user.internal").await;
        let report: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&report_path).await.unwrap()).unwrap();
        assert_eq!(report["targets"][0]["host"], "mysql-user.internal");
        assert_eq!(report["targets"][0]["port"], 3306);
        assert_eq!(report["targets"][0]["fake_ip"], "198.18.0.1");
        assert_eq!(
            report["matched_queries"][0]["target"]["host"],
            "mysql-user.internal"
        );
        task.abort();
    }

    #[tokio::test]
    async fn replay_dns_answers_recorded_mysql_target() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(
            case_dir.join("dependencies.jsonl"),
            format!(
                r#"{{"event_type":"mysql_connection","id":"{}","target_host":"mysql-user.internal","target_port":3306,"target_addr":"mysql-user.internal:3306","upstream_addr":"10.1.2.3:3306"}}"#,
                Uuid::new_v4()
            ),
        )
        .await
        .unwrap();
        let dns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns_socket.local_addr().unwrap();
        let runtime = MysqlReplayRuntime::load(
            MysqlReplayConfig {
                case_dir,
                dns_listen: dns_addr,
                tcp_listen: "127.0.0.1:0".parse().unwrap(),
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path: None,
            },
            dns_addr,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let task = tokio::spawn(async move {
            let _ = runtime.run_dns(dns_socket).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&dns_query("mysql-user.internal"), dns_addr)
            .await
            .unwrap();
        let mut buf = [0_u8; 512];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        assert!(
            buf[..len]
                .windows(4)
                .any(|window| window == [198, 18, 0, 1])
        );
        task.abort();
    }

    async fn spawn_replay(
        case_dir: &Path,
        report_path: Option<PathBuf>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runtime = MysqlReplayRuntime::load(
            MysqlReplayConfig {
                case_dir: case_dir.to_path_buf(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path,
            },
            "127.0.0.1:0".parse().unwrap(),
            addr,
        )
        .await
        .unwrap();
        runtime.write_report().await.unwrap();
        let task = tokio::spawn(async move {
            let _ = runtime.run_tcp(listener).await;
        });
        (addr, task)
    }

    async fn connect_login(addr: SocketAddr) -> TcpStream {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let handshake = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(handshake.sequence_id, 0);
        write_packet_bytes(
            &mut client,
            MysqlPacket {
                sequence_id: 1,
                payload: login_payload("appdb"),
            },
        )
        .await;
        let ok = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(ok.payload[0], 0x00);
        client
    }

    async fn write_packet_bytes(stream: &mut TcpStream, packet: MysqlPacket) {
        stream.write_all(&packet.to_wire_bytes()).await.unwrap();
    }

    fn nul_terminated_len(bytes: &[u8]) -> usize {
        bytes
            .iter()
            .position(|byte| *byte == 0)
            .expect("missing NUL terminator")
    }

    fn replay_column_type_and_flags(payload: &[u8]) -> (u8, u16) {
        let mut offset = 0;
        for _ in 0..6 {
            let (_, next) = read_lenenc_bytes(payload, offset).expect("lenenc column field");
            offset = next;
        }
        let (_, offset) = read_lenenc_int(payload, offset).expect("column fixed length marker");
        let type_code = *payload.get(offset + 6).expect("column type code");
        let flags = u16::from_le_bytes([
            *payload.get(offset + 7).expect("column flags low byte"),
            *payload.get(offset + 8).expect("column flags high byte"),
        ]);
        (type_code, flags)
    }

    fn login_payload(database: &str) -> Vec<u8> {
        let flags = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_CONNECT_WITH_DB
            | CLIENT_PLUGIN_AUTH;
        let mut payload = Vec::new();
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&[0; 23]);
        payload.extend_from_slice(b"root\0");
        payload.push(0);
        payload.extend_from_slice(database.as_bytes());
        payload.push(0);
        payload.extend_from_slice(b"mysql_native_password\0");
        payload
    }

    fn stmt_execute_long_param(statement_id: u32, value: u32) -> Vec<u8> {
        let mut payload = vec![0x17];
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.push(0);
        payload.push(1);
        payload.push(MYSQL_TYPE_LONG);
        payload.push(0);
        payload.extend_from_slice(&value.to_le_bytes());
        payload
    }

    fn dns_query(domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234_u16.to_be_bytes());
        packet.extend_from_slice(&0x0100_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    async fn wait_for_report_contains(path: &Path, expected: &str) {
        for _ in 0..50 {
            if tokio::fs::read_to_string(path)
                .await
                .is_ok_and(|raw| raw.contains(expected))
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("replay report was not written");
    }
}
