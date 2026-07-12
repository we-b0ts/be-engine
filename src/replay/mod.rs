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
#[cfg(test)]
mod command_protocol_tests;
mod control;
mod dependencies;
mod dns;
mod http;
mod kafka;
#[cfg(test)]
#[path = "tests.rs"]
mod legacy_tests;
mod memcached;
mod model;
mod mysql;
mod redis;
mod report;

use control::*;
use dependencies::*;
use dns::*;
use model::*;
use mysql::*;
use report::*;

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
        let mut mysql = MysqlReplayState::default();
        let mut http_exchanges = Vec::new();
        let mut redis = redis::RedisReplayState::default();
        let mut memcached = memcached::MemcachedReplayState::default();
        let mut kafka = kafka::KafkaReplayState::default();
        let mut targets = BTreeMap::new();
        let mut connection_identities = HashMap::new();
        let fake_cidr = Ipv4Cidr::parse(&config.fake_cidr)?;

        if let Some(path) = &bootstrap_path {
            load_dependency_file(
                path,
                ReplaySource::Bootstrap,
                None,
                &mut mysql.exchanges,
                &mut http_exchanges,
                &mut redis,
                &mut memcached,
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
                &mut mysql.exchanges,
                &mut http_exchanges,
                &mut redis,
                &mut memcached,
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
            mysql,
            http_exchanges,
            redis,
            memcached,
            kafka,
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
    mysql: mysql::MysqlReplayState,
    http_exchanges: Vec<http::ReplayHttpExchange>,
    redis: redis::RedisReplayState,
    memcached: memcached::MemcachedReplayState,
    kafka: kafka::KafkaReplayState,
    http_events: http::HttpReplayEvents,
    report_write_lock: Arc<Mutex<()>>,
    ca_cert_path: PathBuf,
    http_ignore_query_params: Vec<String>,
}

impl ReplayState {
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
            connections: self.mysql.events.connections,
            connection_events: self.mysql.events.connection_events.clone(),
            builtin_queries: self.mysql.events.builtin_queries.clone(),
            matched_queries: self.mysql.events.matched_queries.clone(),
            unmatched_queries: self.mysql.events.unmatched_queries.clone(),
            unsupported_commands: self.mysql.events.unsupported_commands.clone(),
            metadata_warnings: self.mysql.events.metadata_warnings.clone(),
            unused_bootstrap_exchanges: self.unused_exchanges(ReplaySource::Bootstrap),
            unused_case_exchanges: self.unused_exchanges(ReplaySource::Case),
            matched_http_exchanges: self.http_events.matched.clone(),
            unmatched_http_requests: self.http_events.unmatched.clone(),
            unsupported_http_exchanges: self.http_events.unsupported.clone(),
            unused_bootstrap_http_exchanges: self.unused_http_exchanges(ReplaySource::Bootstrap),
            unused_case_http_exchanges: self.unused_http_exchanges(ReplaySource::Case),
            protocols: ProtocolsReport {
                redis: self.redis.snapshot(),
                memcached: self.memcached.snapshot(),
                kafka: self.kafka.snapshot(),
            },
            ca_cert_path: self.ca_cert_path.display().to_string(),
            http_ignored_query_params: self.http_ignore_query_params.clone(),
        }
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
            redis::handle_connection(
                stream,
                target.context("Redis replay connection has no target")?,
                state,
                report_path,
            )
            .await
        }
        Some(ReplayProtocol::Memcached) => {
            memcached::handle_connection(
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
            mysql::handle_connection(stream, peer_addr, target, state, report_path).await
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
