use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::pending;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

use crate::MitmCa;
use crate::request_headers::validate_request_file;
mod assertion;
mod auto_protocol;
mod command_matching;
#[cfg(test)]
mod command_protocol_tests;
mod control;
mod dependencies;
mod dns;
mod egress_counter;
mod exchange;
pub use egress_counter::{
    ReplayEgressCounterReader, ReplayEgressCounterSnapshot, ReplayEgressRejections,
};
#[cfg(test)]
mod global_dependency_tests;
mod http;
pub(crate) use http::cross_case as http_cross_case;
pub use http::cross_case::HttpCrossCaseSelector;
pub(crate) use http::unordered as http_unordered;
pub use http::unordered::HttpUnorderedSelector;
mod kafka;
#[cfg(test)]
#[path = "tests.rs"]
mod legacy_tests;
mod memcached;
mod model;
mod motan;
mod mysql;
mod network_access;
mod policy;
pub(crate) use policy::replace_request_rule_section;
mod redis;
pub(crate) mod report;
#[cfg(test)]
mod test_support;

use control::*;
use dependencies::*;
use dns::*;
use exchange::*;
use model::*;
use mysql::*;
use policy::*;
use report::*;
pub(crate) use report::{BackgroundReclassification, reclassify_background_dependencies};
#[cfg(test)]
use test_support::write_test_recording_network_manifest;

const SO_ORIGINAL_DST: libc::c_int = 80;
pub(crate) const UNRECORDED_ENDPOINT_REASON: &str = "访问了录制时没有访问过的域名:port";

#[derive(Debug, Clone)]
pub struct ReplayConfig {
    pub case_dir: PathBuf,
    pub selected_case_ids: Vec<String>,
    pub dns_listen: SocketAddr,
    pub tcp_listen: SocketAddr,
    pub fake_cidr: String,
    pub report_path: Option<PathBuf>,
    pub session_path: Option<PathBuf>,
    pub control_socket_path: Option<PathBuf>,
    pub ca_cert_path: Option<PathBuf>,
    pub ca_key_path: Option<PathBuf>,
    pub policy_path: Option<PathBuf>,
    pub http_ignore_query_params: Vec<String>,
    pub process_owned_dependencies: Vec<crate::BackgroundDependencyRuleConfig>,
    pub allowed_unused_http: Option<ReplayAllowedUnusedHttpConfig>,
}

pub const DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS: u64 = 10;

#[derive(Debug, Clone, Copy)]
pub struct ReplayLifecycleConfig {
    pub case_dependency_post_response_window: std::time::Duration,
}

impl Default for ReplayLifecycleConfig {
    fn default() -> Self {
        Self {
            case_dependency_post_response_window: std::time::Duration::from_millis(
                DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS,
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplayAllowedUnusedHttpConfig {
    pub config_path: PathBuf,
    pub hosts: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct ReplayControlConfig {
    pub session_path: PathBuf,
    pub command: String,
    pub case_id: Option<String>,
    pub fail_on_dirty: bool,
    pub fail_on_incomplete: bool,
    pub wait_timeout: Option<std::time::Duration>,
}

pub type MysqlReplayControlConfig = ReplayControlConfig;

pub(crate) use assertion::hessian2::is_hessian2_body;
pub(crate) use assertion::protobuf::is_protobuf_body;
pub(crate) use assertion::{
    ComparisonResponseAssertionOptions, ComparisonResponseObservation, assert_comparison_response,
    read_actual_response_body, read_comparison_response_observation, read_expected_response_body,
};
pub use assertion::{
    Hessian2BodyDifference, Hessian2BodyDifferenceKind, Hessian2JoinedStringCandidate,
    Hessian2ValuePathCandidate, JsonJoinedStringCandidate, ProtobufBodyDifference,
    ProtobufBodyDifferenceKind, ProtobufFieldPathCandidate, ProtobufJoinedStringCandidate,
    ResponseAssertionCaseReport, ResponseAssertionOptions, ResponseBodyAssertionReport,
    ResponseBodyDifferenceDetail, ResponseBodyJoinedStringCandidate,
    ResponseBodyUnorderedPathCandidate, ResponseDifference, ResponseDifferenceKind,
    ResponseGatewayProtocol, assert_recorded_response,
};
pub(crate) use policy::render_validated_replay_policy;
pub(crate) use policy::response_locations_overlap;
pub use policy::{
    ComparisonResponseRuleFeedback, ComparisonSourceMatch, ComparisonVerificationPolicy,
    Hessian2JoinedStringPath, Hessian2UnorderedPath, Hessian2ValuePath, HttpCrossCaseFeedback,
    HttpCrossCasePlan, HttpCrossCaseReport, MemcachedTimestampRuleFeedback,
    MemcachedTimestampRulePlan, MemcachedTimestampRuleReport, MysqlTimeRuleFeedback,
    MysqlTimeRulePlan, MysqlTimeRuleReport, MysqlTimeSelector, ProfileTargetMissingFeedback,
    ProfileTargetMissingPlan, ProfileTargetMissingReport, ProtobufFieldPath,
    ProtobufJoinedStringFieldType, ProtobufJoinedStringPath, ProtobufRepeatedElementType,
    ProtobufUnorderedPath, ReplayPolicyInitOptions, ReplayPolicyInitResult,
    ReplayPolicyValidationReport, ResponseBodyCodec, ResponseBodyJoinedStringPath,
    ResponseBodyRuleEvidence, ResponseBodyRuleEvidenceKind, ResponseBodyRuleFeedback,
    ResponseBodyRulePlan, ResponseBodyRuleReport, ResponseBodyRuleVerificationOutcome,
    ResponseBodyUnorderedPath, ResponseDurationUnit, ResponseRuleFeedback, ResponseRuleKind,
    ResponseRulePlan, ResponseRuleReport, ResponseTimeRule, ResponseTimestampFormat,
    initialize_replay_policy, plan_comparison_response_rule, plan_http_cross_case,
    plan_memcached_timestamp_rule, plan_mysql_time_rule, plan_profile_target_missing,
    plan_response_body_rule, plan_response_rule, validate_replay_policy,
};
pub(crate) use redis::snapshot_overlay::inspect_case_source_snapshot_overlay;
pub use report::aggregate::{
    ReplayAggregateCounts, ReplayAggregateOptions, ReplayAggregateReport, aggregate_replay_reports,
    aggregate_replay_reports_with_options,
};

pub async fn run_replay_control(config: ReplayControlConfig) -> Result<Value> {
    send_control_request(config).await
}

pub async fn run_mysql_replay_control(config: MysqlReplayControlConfig) -> Result<Value> {
    run_replay_control(config).await
}

pub(crate) fn allocate_control_socket() -> PathBuf {
    #[cfg(unix)]
    let temporary_root = PathBuf::from("/tmp");
    #[cfg(not(unix))]
    let temporary_root = std::env::temp_dir();

    temporary_root.join(format!("trp-e2e-{}.sock", Uuid::new_v4().simple()))
}

pub async fn run_replay(config: ReplayConfig) -> Result<()> {
    run_replay_with_lifecycle(config, ReplayLifecycleConfig::default()).await
}

pub async fn run_replay_with_lifecycle(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
) -> Result<()> {
    run_replay_with_counters(config, lifecycle, None).await
}

pub async fn run_replay_with_counters(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
    counter_reader: Option<ReplayEgressCounterReader>,
) -> Result<()> {
    validate_replay_request_headers(&config).await?;
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
    let runtime =
        ReplayRuntime::load_with_lifecycle(config, dns_listen, tcp_listen, lifecycle).await?;
    runtime.state.lock().await.egress_counter_reader = counter_reader;
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
        result = runtime.run_report_writer() => result,
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
    report_writer: ReplayReportWriter,
    session_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
}

impl ReplayRuntime {
    #[cfg(test)]
    async fn load(
        config: ReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
    ) -> Result<Self> {
        Self::load_with_lifecycle(
            config,
            dns_listen,
            tcp_listen,
            ReplayLifecycleConfig::default(),
        )
        .await
    }

    async fn load_with_lifecycle(
        config: ReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
        lifecycle: ReplayLifecycleConfig,
    ) -> Result<Self> {
        let root_dir = config.case_dir;
        let process_owned_dependencies = &config.process_owned_dependencies;
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
        let selected_case_ids = config
            .selected_case_ids
            .into_iter()
            .collect::<BTreeSet<_>>();
        let (mode, mut cases, active_case_id) =
            discover_replay_cases(&root_dir, &selected_case_ids).await?;
        let ca = Arc::new(MitmCa::load_or_generate(&ca_cert_path, &ca_key_path)?);
        let (global_path, global_debug_path) = find_run_level_dependencies(&root_dir);
        let mut mysql = MysqlReplayState::default();
        let mut http_exchanges = Vec::new();
        let mut http_blackholes = Vec::new();
        let mut redis = redis::RedisReplayState::default();
        let mut memcached = memcached::MemcachedReplayState::default();
        let mut kafka = kafka::KafkaReplayState::default();
        let mut motan = motan::MotanReplayState::default();
        let mut targets = BTreeMap::new();
        let mut connection_identities = HashMap::new();
        let fake_cidr = Ipv4Cidr::parse(&config.fake_cidr)?;
        let total_cases = cases.len();
        let mut next_progress_percent = 5;
        info!(
            loaded_cases = 0,
            total_cases,
            progress_percent = 0,
            case_source = %root_dir.display(),
            "loading replay case dependencies"
        );

        if let Some(path) = &global_path {
            load_dependency_file(
                path,
                ReplaySource::Global,
                None,
                &mut mysql.exchanges,
                &mut http_exchanges,
                &mut http_blackholes,
                &mut redis,
                &mut memcached,
                &mut kafka,
                &mut motan,
                &mut targets,
                &mut connection_identities,
                process_owned_dependencies,
            )
            .await?;
        }
        if let Some(path) = global_debug_path {
            load_motan_debug_file(&path, &mut motan, &mut targets).await?;
        }
        for (index, case) in cases.values().enumerate() {
            load_dependency_file(
                &case.dependencies_path,
                ReplaySource::Case,
                Some(&case.id),
                &mut mysql.exchanges,
                &mut http_exchanges,
                &mut http_blackholes,
                &mut redis,
                &mut memcached,
                &mut kafka,
                &mut motan,
                &mut targets,
                &mut connection_identities,
                process_owned_dependencies,
            )
            .await?;
            load_motan_debug_file(
                &case.dir.join("dependencies-debug.jsonl"),
                &mut motan,
                &mut targets,
            )
            .await?;
            let loaded_cases = index + 1;
            let progress_percent = loaded_cases.saturating_mul(100) / total_cases.max(1);
            if progress_percent >= next_progress_percent || loaded_cases == total_cases {
                info!(
                    loaded_cases,
                    total_cases,
                    progress_percent,
                    case_source = %root_dir.display(),
                    "loading replay case dependencies"
                );
                next_progress_percent = (progress_percent / 5 + 1).saturating_mul(5);
            }
        }
        let shared_root = root_dir.clone();
        let shared_policy = config.policy_path.clone();
        let shared_cases = cases.clone();
        let (http_exchanges, mut targets) = tokio::task::spawn_blocking(move || -> Result<_> {
            http_cross_case::load(
                &shared_root,
                shared_policy.as_deref(),
                &shared_cases,
                &mut http_exchanges,
                &mut targets,
            )?;
            Ok((http_exchanges, targets))
        })
        .await
        .context("HTTP cross-case preload task failed")??;
        redis.apply_snapshot_overlays(&root_dir, process_owned_dependencies);

        let recording_network_path =
            network_access::apply_recorded_endpoint_allowlist(&root_dir, &mut targets)?;
        let targets = assign_fake_ips(targets, fake_cidr)?;
        let occupied_fake_ips = targets.iter().map(|target| target.fake_ip).collect();
        if let Some(case_id) = &active_case_id
            && let Some(case) = cases.get_mut(case_id)
        {
            case.status = ReplayCaseStatus::Active;
        }

        let http_ignore_query_params = config
            .http_ignore_query_params
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let mut replay_policy = config
            .policy_path
            .as_deref()
            .map(|path| ReplayPolicyRuntime::load(path, &cases))
            .transpose()?;
        if let Some(policy) = &mut replay_policy {
            for exchange in mysql
                .exchanges
                .iter()
                .filter(|exchange| exchange.source == ReplaySource::Case)
            {
                policy.observe_recorded_mysql_exchange(
                    exchange.case_id.as_deref(),
                    &ReplaySessionIdentity {
                        target: Some(exchange.identity.target.clone()),
                        database: exchange.identity.database.clone(),
                        username: exchange.identity.username.clone(),
                    },
                    &exchange.record.command,
                    exchange.record.sql.as_deref(),
                );
            }
            http::observe_recorded_policy_exchanges(policy, &http_exchanges);
            memcached::observe_recorded_policy_exchanges(policy, &memcached);
            policy.reject_http_ignore_overlap(&http_ignore_query_params)?;
        }

        let state = ReplayState {
            egress_counter_reader: None,
            egress_counter_starts: BTreeMap::new(),
            egress_rejections: BTreeMap::new(),
            session_id: Uuid::new_v4(),
            started_at: Utc::now(),
            finalized_at: None,
            dns_listen,
            tcp_listen,
            mode,
            root_dir,
            cases,
            active_case_id,
            case_dependency_post_response_window: lifecycle.case_dependency_post_response_window,
            global_path,
            targets,
            mysql,
            http_exchanges,
            http_blackholes,
            redis,
            memcached,
            kafka,
            motan,
            http_events: http::HttpReplayEvents::default(),
            report_write_lock: Arc::new(Mutex::new(())),
            ca_cert_path,
            replay_policy,
            http_ignore_query_params,
            allowed_unused_http: config.allowed_unused_http,
            recording_network_path: Some(recording_network_path),
            fake_cidr,
            unrecorded_domain_ips: BTreeMap::new(),
            unrecorded_ip_domains: BTreeMap::new(),
            occupied_fake_ips,
            next_unrecorded_fake_offset: 1,
            unrecorded_targets: Vec::new(),
        };
        let report_writer = ReplayReportWriter::new(config.report_path.clone());
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            ca,
            report_path: config.report_path,
            report_writer,
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
            let report_writer = self.report_writer.clone();
            tokio::spawn(async move {
                if let Err(err) =
                    handle_gateway_connection(stream, peer_addr, state, report_writer, ca).await
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
        self.report_writer.flush(self.state.clone()).await
    }

    async fn run_report_writer(&self) -> Result<()> {
        self.report_writer.run(self.state.clone()).await
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

fn find_run_level_dependencies(root: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    (
        find_upward(root, "global-dependencies.jsonl"),
        find_upward(root, "global-dependencies-debug.jsonl"),
    )
}

async fn validate_replay_request_headers(config: &ReplayConfig) -> Result<()> {
    let selected_case_ids = config
        .selected_case_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let (_, cases, _) = discover_replay_cases(&config.case_dir, &selected_case_ids).await?;
    for case in cases.values() {
        validate_request_file(&case.dir.join("request.json")).with_context(|| {
            format!(
                "encrypted request header preflight failed for case {}",
                case.id
            )
        })?;
    }
    Ok(())
}

#[derive(Debug)]
struct ReplayState {
    egress_counter_reader: Option<ReplayEgressCounterReader>,
    egress_counter_starts: BTreeMap<String, egress_counter::Sample>,
    egress_rejections: BTreeMap<String, ReplayEgressRejections>,
    session_id: Uuid,
    started_at: DateTime<Utc>,
    finalized_at: Option<DateTime<Utc>>,
    dns_listen: SocketAddr,
    tcp_listen: SocketAddr,
    mode: ReplayMode,
    root_dir: PathBuf,
    cases: BTreeMap<String, ReplayCase>,
    active_case_id: Option<String>,
    case_dependency_post_response_window: std::time::Duration,
    global_path: Option<PathBuf>,
    targets: Vec<ReplayTarget>,
    mysql: mysql::MysqlReplayState,
    http_exchanges: Vec<http::ReplayHttpExchange>,
    http_blackholes: Vec<http::ReplayHttpBlackhole>,
    redis: redis::RedisReplayState,
    memcached: memcached::MemcachedReplayState,
    kafka: kafka::KafkaReplayState,
    motan: motan::MotanReplayState,
    http_events: http::HttpReplayEvents,
    report_write_lock: Arc<Mutex<()>>,
    ca_cert_path: PathBuf,
    replay_policy: Option<ReplayPolicyRuntime>,
    http_ignore_query_params: Vec<String>,
    allowed_unused_http: Option<ReplayAllowedUnusedHttpConfig>,
    recording_network_path: Option<PathBuf>,
    fake_cidr: Ipv4Cidr,
    unrecorded_domain_ips: BTreeMap<String, Ipv4Addr>,
    unrecorded_ip_domains: BTreeMap<Ipv4Addr, String>,
    occupied_fake_ips: BTreeSet<Ipv4Addr>,
    next_unrecorded_fake_offset: u32,
    unrecorded_targets: Vec<UnrecordedTargetReport>,
}

impl ReplayState {
    fn snapshot_report(&self) -> ReplayReport {
        let unused_case_http_exchanges = self.unused_http_exchanges(ReplaySource::Case, false);
        let allowed_unused_case_http_exchanges =
            self.unused_http_exchanges(ReplaySource::Case, true);
        ReplayReport {
            egress_rejections: self.egress_rejections.values().cloned().collect(),
            version: 6,
            session_id: self.session_id.to_string(),
            started_at: self.started_at,
            finalized_at: self.finalized_at,
            finalized: self.finalized_at.is_some(),
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
            selected_case_ids: self.cases.keys().cloned().collect(),
            global_dependencies_path: self
                .global_path
                .as_ref()
                .map(|path| path.display().to_string()),
            recording_network_path: self
                .recording_network_path
                .as_ref()
                .map(|path| path.display().to_string()),
            targets: self.targets.clone(),
            unrecorded_targets: self.unrecorded_targets.clone(),
            success_detail_limit: SUCCESS_DETAIL_LIMIT,
            connections: self.mysql.events.connections,
            connection_events: self.mysql.events.connection_events.clone(),
            builtin_query_count: self.mysql.events.builtin_query_count,
            builtin_queries: self.mysql.events.builtin_queries.clone(),
            matched_query_count: self.mysql.events.matched_query_count,
            matched_queries: self.mysql.events.matched_queries.clone(),
            unmatched_queries: self.mysql.events.unmatched_queries.clone(),
            unsupported_commands: self.mysql.events.unsupported_commands.clone(),
            metadata_warnings: self.mysql.events.metadata_warnings.clone(),
            unused_global_exchanges: self.unused_exchanges(ReplaySource::Global),
            unused_case_exchanges: self.unused_exchanges(ReplaySource::Case),
            allowed_unused_mysql_rollback_exchanges: self.allowed_unused_rollbacks(),
            allowed_unused_mysql_autocommit_exchanges: self.allowed_unused_autocommit(),
            matched_http_exchange_count: self.http_events.matched_count,
            matched_http_exchanges: self.http_events.matched.clone(),
            unmatched_http_requests: self.http_events.unmatched.clone(),
            unsupported_http_exchanges: self.http_events.unsupported.clone(),
            unused_global_http_exchanges: self.unused_http_exchanges(ReplaySource::Global, false),
            unused_case_http_exchanges,
            allowed_unused_case_http_exchanges,
            protocols: ProtocolsReport {
                redis: self.redis.snapshot(),
                memcached: self.memcached.snapshot(),
                kafka: self.kafka.snapshot(),
                motan: self.motan.snapshot(),
            },
            ca_cert_path: self.ca_cert_path.display().to_string(),
            replay_policy: self.replay_policy.as_ref().map(ReplayPolicyRuntime::report),
            http_ignored_query_params: self.http_ignore_query_params.clone(),
            allowed_unused_http: self.allowed_unused_http.as_ref().map(|config| {
                ReplayAllowedUnusedHttpReport {
                    config: config.config_path.display().to_string(),
                    hosts: config.hosts.iter().cloned().collect(),
                }
            }),
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
    report_writer: ReplayReportWriter,
    ca: Arc<MitmCa>,
) -> Result<()> {
    let target = match replay_destination_for_stream(&stream, &state).await {
        ReplayDestination::Recorded(target) => Some(target),
        ReplayDestination::Unrecorded(target) => {
            if !network_access::wait_for_unrecorded_payload(&stream).await? {
                return Ok(());
            }
            let mut replay = state.lock().await;
            replay.record_unrecorded_target(target.clone());
            drop(replay);
            report_writer.flush(state.clone()).await?;
            return Err(anyhow!(
                "target exchanged data with dependency endpoint {}:{} that was not accessed during recording",
                target.host,
                target.port
            ));
        }
        ReplayDestination::Unknown => None,
    };
    match target.as_ref().map(|target| target.protocol) {
        Some(ReplayProtocol::Auto) => {
            let target = target.context("auto replay connection has no target")?;
            match auto_protocol::detect(&stream).await? {
                ReplayProtocol::Redis => {
                    redis::handle_connection(stream, target, state, report_writer).await
                }
                ReplayProtocol::Memcached => {
                    memcached::handle_connection(stream, target, state, report_writer).await
                }
                protocol @ (ReplayProtocol::Http | ReplayProtocol::Https) => {
                    let mut target = target.clone();
                    target.protocol = protocol;
                    http::handle_http_replay_connection(
                        stream,
                        peer_addr,
                        target,
                        state,
                        report_writer,
                        ca,
                    )
                    .await
                }
                protocol => Err(anyhow!(
                    "auto replay target resolved to unsupported protocol {protocol:?}"
                )),
            }
        }
        Some(ReplayProtocol::Http) | Some(ReplayProtocol::Https) => {
            http::handle_http_replay_connection(
                stream,
                peer_addr,
                target.context("HTTP replay connection has no target")?,
                state,
                report_writer,
                ca,
            )
            .await
        }
        Some(ReplayProtocol::Redis) => {
            redis::handle_connection(
                stream,
                target.context("Redis replay connection has no target")?,
                state,
                report_writer,
            )
            .await
        }
        Some(ReplayProtocol::Memcached) => {
            memcached::handle_connection(
                stream,
                target.context("Memcached replay connection has no target")?,
                state,
                report_writer,
            )
            .await
        }
        Some(ReplayProtocol::Kafka) => {
            kafka::handle_connection(
                stream,
                target.context("Kafka replay connection has no target")?,
                state,
                report_writer,
            )
            .await
        }
        Some(ReplayProtocol::Motan) => {
            motan::handle_connection(
                stream,
                target.context("Motan replay connection has no target")?,
                state,
                report_writer,
            )
            .await
        }
        Some(ReplayProtocol::Mysql) => {
            let target = target.map(|target| TargetKey {
                host: target.host,
                port: target.port,
            });
            mysql::handle_connection(stream, peer_addr, target, state, report_writer, ca).await
        }
        None => {
            let registered_targets = state.lock().await.targets.len();
            #[cfg(test)]
            if registered_targets == 0 {
                return mysql::handle_connection(stream, peer_addr, None, state, report_writer, ca)
                    .await;
            }
            let original = original_dst(&stream)
                .map(|addr| addr.to_string())
                .unwrap_or_else(|error| format!("unavailable ({error})"));
            Err(anyhow!(
                "no replay target is registered for intercepted destination {original}; \
                 loaded {registered_targets} target mappings"
            ))
        }
    }
}

enum ReplayDestination {
    Recorded(ReplayTarget),
    Unrecorded(TargetKey),
    Unknown,
}

async fn replay_destination_for_stream(
    stream: &TcpStream,
    state: &Arc<Mutex<ReplayState>>,
) -> ReplayDestination {
    let original = original_dst(stream).ok();
    let state = state.lock().await;
    if let Some(target) = exact_replay_target_for_original(original, &state.targets) {
        return ReplayDestination::Recorded(target);
    }
    if let Some(SocketAddr::V4(addr)) = original
        && let Some(target) = state.unrecorded_target_for(*addr.ip(), addr.port())
    {
        return ReplayDestination::Unrecorded(target);
    }
    #[cfg(test)]
    if state.targets.len() == 1 {
        return ReplayDestination::Recorded(state.targets[0].clone());
    }
    ReplayDestination::Unknown
}

#[cfg(test)]
fn replay_target_for_original(
    original: Option<SocketAddr>,
    targets: &[ReplayTarget],
) -> Option<ReplayTarget> {
    if let Some(target) = exact_replay_target_for_original(original, targets) {
        return Some(target);
    }
    if targets.len() == 1 {
        let target = &targets[0];
        return Some(target.clone());
    }
    None
}

fn exact_replay_target_for_original(
    original: Option<SocketAddr>,
    targets: &[ReplayTarget],
) -> Option<ReplayTarget> {
    if let Some(SocketAddr::V4(addr)) = original {
        let ip = *addr.ip();
        let port = addr.port();
        if let Some(target) = targets
            .iter()
            .find(|target| target.fake_ip == ip && target.port == port)
        {
            return Some(target.clone());
        }
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

pub use policy::{
    HttpUnorderedFeedback, HttpUnorderedPlan, HttpUnorderedReport, plan_http_unordered,
};
