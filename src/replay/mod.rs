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
mod adapters;
pub(crate) mod admission;
mod assertion;
mod auto_protocol;
mod candidate_selection;
mod case_index;
mod command_matching;
#[cfg(test)]
mod command_protocol_tests;
mod connect_failure;
mod contract_value;
mod lifecycle_cleanup;
pub(crate) use memcached::contracts::{
    source_witness as memcached_source_witness, validate_witness as memcached_validate_witness,
};
pub(crate) use policy::validate_finite_sharing as validate_native_finite_sharing;
pub(crate) use policy::{NativeSourceCase, validate_native_source_dependencies};
pub(crate) use report::source_owned_match;
mod control;
pub(crate) use redis::request_fingerprint as redis_request_fingerprint;
mod attribution;
mod deferred;
mod dependencies;
mod loading;
mod loading_config;
mod reconciliation;
pub use loading_config::ReplayDependencyLoading;
pub(crate) use reconciliation::validate_completed_receipt;
mod dns;
mod egress_counter;
mod exchange;
mod global;
mod global_source;
#[cfg(test)]
mod global_test_support;
mod snapshot;
mod startup;
mod target_observation;
pub use egress_counter::{
    ReplayEgressCounterReader, ReplayEgressCounterSnapshot, ReplayEgressRejections,
};
#[cfg(test)]
mod global_dependency_tests;
mod http;
pub(crate) use http::contracts::{
    multipart_witness_matches as http_multipart_witness_matches,
    source_witness as http_source_witness, validate_witness as http_validate_witness,
    witness_metadata_matches as http_witness_metadata_matches, witness_value as http_witness_value,
};
pub(crate) use http::cross_case as http_cross_case;
pub use http::cross_case::HttpCrossCaseSelector;
pub(crate) use http::diagnosis as http_request_diagnosis;
#[cfg(test)]
pub(crate) use http::tests::{
    snapshot_http_replay, spawn_coordinator_http_replay, write_http_case,
};
pub(crate) use http::unordered as http_unordered;
mod kafka;
#[cfg(test)]
#[path = "tests.rs"]
mod legacy_tests;
mod memcached;
mod model;
mod motan;
mod mysql;
pub(crate) use mysql::contracts::automatic::Metadata as MysqlInferenceMetadata;
pub(crate) use mysql::contracts::source_witness as mysql_source_witness;
pub(crate) use mysql::contracts::time_copies::global::delivered_witness_time_copies as mysql_global_delivered_time_copies;
pub(crate) use mysql::contracts::{
    IdentityPreflight as MysqlIdentityPreflight, mysql_witness_sql_value,
    normalize_identity_witnesses as mysql_normalize_identity_witnesses,
};
pub(crate) use policy::mysql_native_witness_matches;
pub(crate) use policy::validate_mysql_value_selector;
mod execution_plan;
mod native_index;
mod network_access;
mod policy;
mod preparation;
pub(crate) use policy::replace_request_rule_section;
pub(crate) use policy::request_contract::redis_bulk_payload;
pub(crate) use policy::request_contract::{
    RedisFieldValue, RedisTimeRead, redis_delivered_global_time_copies,
    redis_delivered_scalar_time_copies, redis_field_values, redis_time_position,
};
mod redis;
pub(crate) mod report;
#[cfg(test)]
mod test_support;

use case_index::*;
use control::*;
pub(crate) use dependencies::validate_index_record;
use dependencies::*;
use dns::*;
use exchange::*;
use model::*;
use mysql::*;
use policy::*;
#[cfg(test)]
pub(crate) use report::reclassify_background_dependencies;
use report::*;
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

pub const DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS: u64 = 0;
pub const DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS: u64 = 2_000;
pub const DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS: u64 = 5;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStreamTiming {
    Fast,
    #[default]
    Recorded,
}

#[derive(Debug, Clone, Copy)]
pub struct ReplayLifecycleConfig {
    pub pre_match: bool,
    pub stream_timing: Option<ReplayStreamTiming>,
    pub stream_interval_cap_ms: u64,
    pub case_no_progress_timeout: std::time::Duration,
    pub request_timeout: std::time::Duration,
    pub case_dependency_post_response_window: std::time::Duration,
    pub dependency_loading: ReplayDependencyLoading,
}

impl Default for ReplayLifecycleConfig {
    fn default() -> Self {
        Self {
            pre_match: false,
            stream_timing: None,
            stream_interval_cap_ms: DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS,
            case_no_progress_timeout: std::time::Duration::from_millis(
                DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS,
            ),
            request_timeout: std::time::Duration::from_millis(
                crate::config::HttpGatewayConfig::default().request_timeout_ms,
            ),
            dependency_loading: ReplayDependencyLoading::default(),
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

pub use assertion::ResponseHeaderDateCandidate;
pub(crate) use assertion::hessian2::is_hessian2_body;
pub(crate) use assertion::protobuf::is_protobuf_body;
pub use assertion::{
    DocxBodyDifference, DocxBodyDifferenceKind, Hessian2BodyDifference, Hessian2BodyDifferenceKind,
    Hessian2JoinedStringCandidate, Hessian2ValuePathCandidate, JsonJoinedStringCandidate,
    ProtobufBodyDifference, ProtobufBodyDifferenceKind, ProtobufFieldPathCandidate,
    ProtobufJoinedStringCandidate, ResponseAssertionCaseReport, ResponseAssertionOptions,
    ResponseBodyAssertionReport, ResponseBodyDifferenceDetail, ResponseBodyJoinedStringCandidate,
    ResponseBodyUnorderedPathCandidate, ResponseDifference, ResponseDifferenceKind,
    ResponseGatewayProtocol, assert_recorded_response,
};
pub(crate) use assertion::{
    ResponseAssertionRuntime, read_actual_response_body, read_expected_response_body,
};
pub(crate) use policy::ReplayEvidencePolicyFreshness;
pub use policy::ResponseHeaderDateRule;
pub use policy::{CaseCondition, JsonCondition};
pub use policy::{
    DocxTimestampRule, Hessian2JoinedStringPath, Hessian2UnorderedPath, Hessian2ValuePath,
    HttpCrossCaseFeedback, HttpCrossCasePlan, HttpCrossCaseReport, MemcachedTimestampRuleFeedback,
    MemcachedTimestampRulePlan, MemcachedTimestampRuleReport, MysqlTimeRuleFeedback,
    MysqlTimeRulePlan, MysqlTimeRuleReport, MysqlTimeSelector, MysqlTimeValueSelector,
    ProtobufFieldPath, ProtobufJoinedStringFieldType, ProtobufJoinedStringPath,
    ProtobufRepeatedElementType, ProtobufUnorderedPath, RedisCrossCaseFeedback, RedisCrossCasePlan,
    RedisCrossCaseReport, ReplayPolicyInitOptions, ReplayPolicyInitResult,
    ReplayPolicyValidationReport, ResponseBodyCodec, ResponseBodyJoinedStringPath,
    ResponseBodyRuleEvidence, ResponseBodyRuleEvidenceKind, ResponseBodyRuleFeedback,
    ResponseBodyRulePlan, ResponseBodyRuleReport, ResponseBodyRuleVerificationOutcome,
    ResponseBodyUnorderedPath, ResponseDurationUnit, ResponseRuleFeedback, ResponseRuleKind,
    ResponseRulePlan, ResponseRuleReport, ResponseTimeRule, ResponseTimestampFormat,
    ResponseTimestampMode, initialize_replay_policy, plan_http_cross_case,
    plan_memcached_timestamp_rule, plan_mysql_time_rule, plan_redis_cross_case,
    plan_response_body_rule, plan_response_rule, validate_replay_policy,
};
pub use policy::{
    DynamicValueCapture, DynamicValueFormat, DynamicValueRule, DynamicValueTarget,
    DynamicValueType, PathSegmentCapture, PathSegmentField, RedisCaptureReference,
    RedisDerivedIdentity,
};
pub use policy::{
    DynamicValueMysqlTimeRule, DynamicValueRedisTimeRule, DynamicValueRuleFeedback,
    GeneratedValueRulePlan, GeneratedValueRuleReport, RedisJsonTimeValueSelector,
    ResponseHeaderDateRuleFeedback, plan_dynamic_value_mysql_time_rule,
    plan_dynamic_value_redis_time_rule, plan_dynamic_value_rule, plan_response_header_date_rule,
};
pub(crate) use redis::snapshot_overlay::inspect_case_source_snapshot_overlay;
pub(crate) use report::aggregate::aggregate_runner_replay_report;
pub use report::aggregate::{
    ReplayAggregateCounts, ReplayAggregateOptions, ReplayAggregateReport, aggregate_replay_reports,
    aggregate_replay_reports_with_options,
};
pub use report::global_evidence::{GlobalDependencyPage, read_global_dependency_page};

pub async fn run_replay_control(config: ReplayControlConfig) -> Result<Value> {
    send_control_request(config).await
}
pub(crate) use control::{
    FinalizationScope, check_response_identities, http_input_timing_observer,
    input_timing_observer, native_event_observer, register_derived_input,
};

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
    info!(
        dns_listen = %dns_listen,
        tcp_listen = %tcp_listen,
        "dependency replay intercept listening"
    );
    tokio::select! {
        result = runtime.run_dns(dns_socket) => result,
        result = runtime.run_tcp(tcp_listener) => result,
        result = runtime.run_control() => result,
        result = deferred::prefetch::run(runtime.state.clone()) => result,
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
    async fn run_tcp(&self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, peer_addr) = accept_replay_tcp_connection(&listener).await?;
            let state = self.state.clone();
            let ca = self.ca.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_gateway_connection(stream, peer_addr, state, ca).await {
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

    #[cfg(test)]
    async fn write_report(&self) -> Result<()> {
        write_report_snapshot(self.state.clone(), self.report_path.clone()).await
    }

    #[cfg(test)]
    async fn run_report_writer(&self) -> Result<()> {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.write_report().await?;
        }
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
        find_upward(root, "indexes/startup-scope.json").or({
            #[cfg(test)]
            {
                find_upward(root, "global-dependencies.jsonl")
            }
            #[cfg(not(test))]
            {
                None
            }
        }),
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
    admission_epoch: u64,
    case_execution_plans: BTreeMap<String, Arc<execution_plan::CaseExecutionPlan>>,
    batch_scope: Option<reconciliation::BatchScope>,
    startup_phase: startup::StartupPhase,
    dependency_attribution_snapshot: Option<String>,
    prepared_socketio_input: Option<control::input_timing::PreparedSource>,
    input_timing: Option<control::input_timing::Live>,
    http_input_timing: Option<Arc<control::http_input_timing::Timeline>>,
    stream_timing: Option<ReplayStreamTiming>,
    stream_interval_cap_ms: u64,
    http_ingress: http::ingress::HttpIngress,
    target_observations: target_observation::TargetObservations,
    case_cleanup: control::case_cleanup::CaseCleanup,
    connect_failures: connect_failure::Inventory,
    deferred: Option<Arc<deferred::DeferredDependencies>>,
    source_inventory_id: Option<String>,
    eager_source_facts: BTreeMap<String, Vec<report::unused_source::CaptureFact>>,
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
    target_stop_prepared: BTreeSet<String>,
    target_session_stopped: bool,
    dependency_tails: control::dependency_tail::CaseTails,
    case_dependency_post_response_window: std::time::Duration,
    global_path: Option<PathBuf>,
    regular_global: BTreeMap<String, report::global_evidence::regular::RegularBaseline>,
    targets: Vec<ReplayTarget>,
    mysql: mysql::MysqlReplayState,
    http_exchanges: Vec<http::ReplayHttpExchange>,
    http_case_exchange_index: CaseExchangeIndex,
    http_candidates: http::candidates::Candidates,
    http_blackholes: Vec<http::ReplayHttpBlackhole>,
    redis: redis::RedisReplayState,
    memcached: memcached::MemcachedReplayState,
    kafka: kafka::KafkaReplayState,
    motan: motan::MotanReplayState,
    http_events: http::HttpReplayEvents,
    ca_cert_path: PathBuf,
    replay_policy: Option<ReplayPolicyRuntime>,
    http_ignore_query_params: Vec<String>,
    allowed_unused_http: Option<ReplayAllowedUnusedHttpConfig>,
    recording_network_path: Option<PathBuf>,
    recorded_dns_only_domains: BTreeSet<String>,
    fake_cidr: Ipv4Cidr,
    unrecorded_domain_ips: BTreeMap<String, Ipv4Addr>,
    unrecorded_ip_domains: BTreeMap<Ipv4Addr, String>,
    occupied_fake_ips: BTreeSet<Ipv4Addr>,
    next_unrecorded_fake_offset: u32,
    unrecorded_targets: Vec<UnrecordedTargetReport>,
    unrecorded_case_ids: BTreeSet<String>,
}

async fn accept_replay_tcp_connection(listener: &TcpListener) -> Result<(TcpStream, SocketAddr)> {
    let (stream, peer_addr) = listener
        .accept()
        .await
        .context("failed to accept dependency replay gateway client")?;
    stream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY for dependency replay gateway client")?;
    Ok((stream, peer_addr))
}

async fn handle_gateway_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<Mutex<ReplayState>>,
    ca: Arc<MitmCa>,
) -> Result<()> {
    let stopping = state.lock().await.async_case_quiescing();
    if stopping {
        crate::dependency::termination::ConnectionControl::new(&stream)?.reset()?;
        return Ok(());
    }
    let target = match replay_destination_for_stream(&stream, &state).await {
        ReplayDestination::Recorded(target) => Some(target),
        ReplayDestination::Unrecorded {
            target,
            active_case,
        } => {
            if !network_access::wait_for_unrecorded_payload(&stream, active_case).await? {
                return Ok(());
            }
            let mut replay = state.lock().await;
            replay.record_unrecorded_target(target.clone());
            drop(replay);
            let action = if active_case {
                "connected to"
            } else {
                "exchanged data with"
            };
            return Err(anyhow!(
                "target {action} dependency endpoint {}:{} that was not accessed during recording",
                target.host,
                target.port
            ));
        }
        ReplayDestination::Unknown => None,
    };
    if let Some(target) = target.as_ref()
        && connect_failure::deliver(&mut stream, target, &state).await?
    {
        return Ok(());
    }
    match target.as_ref().map(|target| target.protocol) {
        Some(ReplayProtocol::Auto) => {
            let target = target.context("auto replay connection has no target")?;
            match auto_protocol::detect(&stream).await? {
                Some(ReplayProtocol::Redis) => {
                    redis::handle_connection(stream, target, state).await
                }
                Some(ReplayProtocol::Memcached) => {
                    memcached::handle_connection(stream, target, state).await
                }
                Some(protocol @ (ReplayProtocol::Http | ReplayProtocol::Https)) => {
                    let mut target = target.clone();
                    target.protocol = protocol;
                    http::handle_http_replay_connection(stream, peer_addr, target, state, ca).await
                }
                Some(protocol) => Err(anyhow!(
                    "auto replay target resolved to unsupported protocol {protocol:?}"
                )),
                None => Ok(()),
            }
        }
        Some(ReplayProtocol::Http) | Some(ReplayProtocol::Https) => {
            http::handle_http_replay_connection(
                stream,
                peer_addr,
                target.context("HTTP replay connection has no target")?,
                state,
                ca,
            )
            .await
        }
        Some(ReplayProtocol::Redis) => {
            redis::handle_connection(
                stream,
                target.context("Redis replay connection has no target")?,
                state,
            )
            .await
        }
        Some(ReplayProtocol::Memcached) => {
            memcached::handle_connection(
                stream,
                target.context("Memcached replay connection has no target")?,
                state,
            )
            .await
        }
        Some(ReplayProtocol::Kafka) => {
            kafka::handle_connection(
                stream,
                target.context("Kafka replay connection has no target")?,
                state,
            )
            .await
        }
        Some(ReplayProtocol::Motan) => {
            motan::handle_connection(
                stream,
                target.context("Motan replay connection has no target")?,
                state,
            )
            .await
        }
        Some(ReplayProtocol::Mysql) => {
            let target = target.map(|target| TargetKey {
                host: target.host,
                port: target.port,
            });
            mysql::handle_connection(stream, peer_addr, target, state, ca).await
        }
        None => {
            let registered_targets = state.lock().await.targets.len();
            #[cfg(test)]
            if registered_targets == 0 {
                return mysql::handle_connection(stream, peer_addr, None, state, ca).await;
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
    Unrecorded {
        target: TargetKey,
        active_case: bool,
    },
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
        return ReplayDestination::Unrecorded {
            target,
            active_case: state.active_case_id.is_some(),
        };
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

#[cfg(test)]
pub(crate) use policy::test_fixture::install_dependency_rule as install_dependency_rule_fixture;
#[cfg(test)]
pub(crate) use policy::test_fixture::redis_time::{RedisTimeShiftFeedback, RedisTimeShiftSelector};
#[cfg(test)]
pub(crate) use policy::test_fixture::write_policy as write_policy_fixture;
pub use redis::value::{RedisUnorderedField, RedisUnorderedSelector, RedisValueKeySelector};

pub(crate) use redis::value as redis_value;

mod json_order;
mod recording_evidence;
pub(crate) use recording_evidence::dependency_started_at;

pub use policy::{DependencyRequestRuleFeedback, plan_dependency_request_rule};

pub(crate) use policy::request_contract::discover as discover_dependency_request_candidates;

pub use policy::{ResponseJwtAlgorithm, ResponseJwtKeySource, ResponseJwtRule};

pub use policy::{ResponseJwtRuleFeedback, plan_response_jwt_rule};

pub(crate) use assertion::native::{
    NativeResponseContext, compare_body as native_response_body,
    compare_header as native_response_header, selected as native_response_selected,
};
pub(crate) use assertion::{
    ResponsePayloadPair, compare_interaction_global, decode_sse, response_payload_pair,
    response_rule_payload_pair,
};
pub(crate) use mysql::contracts::{
    request_candidates_related as mysql_request_candidates_related,
    validate_contract_candidate as mysql_validate_contract_candidate,
    validate_contract_witness as mysql_validate_contract_witness,
};
pub(crate) use policy::native_projection::validate_native_adapter;

pub(crate) use assertion::native::source_request_body as native_source_request_body;
pub(crate) use policy::native_projection::compiled_input_rules;

pub(crate) use redis::expiration::normalize as normalize_redis_expiration;

pub(crate) use mysql::contracts::automatic::validate_source_witness as mysql_validate_global_source_witness;
pub(crate) use mysql::contracts::automatic::validate_witness_with_time_copies as mysql_validate_global_witness_with_time_copies;
