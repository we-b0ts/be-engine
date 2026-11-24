use std::collections::{BTreeMap, BTreeSet};
use std::future::pending;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

pub(crate) use crate::MitmCa;
use crate::request_headers::validate_request_file;
mod adapters;
pub(crate) use adapters::ProtocolExchange;
pub(crate) use adapters::RecordedReference;
pub(crate) mod admission;
pub(crate) mod candidate_selection;
pub(crate) mod case_index;
pub(crate) mod command_matching;
#[cfg(test)]
mod command_protocol_tests;
pub(crate) mod connect_failure;
pub(crate) mod control;
pub(crate) mod lifecycle_cleanup;
pub(crate) mod native;
pub(crate) use control::primary_close::Timeline as PrimaryCloseTimeline;
mod attribution;
mod deferred;
pub(crate) use traffic_engine_replay::replay::dependencies;
mod loading;
#[cfg(test)]
use traffic_engine_replay::replay::loading_config;
mod dns;
mod reconciliation;
use traffic_engine_replay::replay::egress_counter;
use traffic_engine_replay::replay::exchange;
mod snapshot;
mod startup;
mod target_observation;
pub(crate) mod timers;
pub use egress_counter::{ReplayEgressCounterReader, ReplayEgressRejections};
pub(crate) use target_observation::TargetObservations;
pub use timers::ReplayTimerConfig;
#[cfg(test)]
mod global_dependency_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod legacy_tests;
pub(crate) use traffic_engine_replay::replay::execution_plan;
use traffic_engine_replay::replay::model;
pub(crate) mod native_index;
mod network_access;
pub mod policy;
mod preparation;
pub(crate) use traffic_replay::preparation::{PreparedProtocols, RunSequenceReference};
pub(crate) mod protocol_runtime;
use policy::{ReplayPolicy, RequestRuleRuntime};
use protocol_runtime::{InFlightScope, ReplayProtocolSet};
pub mod report;
pub(crate) mod sequence;
mod session;
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod test_support;

pub(crate) use control::*;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use dns::Ipv4Cidr;
use dns::*;
pub(crate) use exchange::ReplayExchangeStatus;
pub(crate) use model::register_replay_target;
pub(crate) use model::*;
pub(crate) use model::{ReplayCase, TargetKey};
pub(crate) use model::{ReplayProtocol, ReplayTarget};
pub(crate) use report::*;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use test_support::write_test_recording_network_manifest;

const SO_ORIGINAL_DST: libc::c_int = 80;
pub(crate) const UNRECORDED_ENDPOINT_REASON: &str = "访问了录制时没有访问过的域名:port";

pub use traffic_engine_replay::replay::{
    DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS, FAST_CASE_TIMEOUT, ReplayLifecycleConfig,
    ReplayStreamTiming, RuntimeConfig,
};
pub(crate) async fn run<P: ReplayProtocolSet>(
    config: RuntimeConfig,
    mut lifecycle: ReplayLifecycleConfig,
    counter_reader: Option<ReplayEgressCounterReader>,
    providers: Arc<crate::protocols::DependencyProviders>,
    loader: P::SourceLoader,
    timer_config: Option<ReplayTimerConfig>,
    session_events: bool,
) -> Result<()> {
    if session_events {
        lifecycle.stream_timing = Some(ReplayLifecycleConfig::EVENT_SESSION_STREAM_TIMING);
        lifecycle.stream_interval_cap_ms =
            ReplayLifecycleConfig::EVENT_SESSION_STREAM_INTERVAL_CAP_MS;
    }
    let timer_state = if let Some(timer) = &timer_config {
        ensure!(
            lifecycle.stream_timing == Some(ReplayStreamTiming::Fast),
            "Replay timers require fast stream timing"
        );
        ensure!(
            config.control_socket_path.as_ref() != Some(&timer.socket_path),
            "Replay timers require a separate socket from Case control"
        );
        timers::Timers::load(timer).await?
    } else {
        timers::Timers::default()
    };
    if session_events {
        ensure!(
            config.control_socket_path.is_some(),
            "session Replay requires a control socket"
        );
        ensure!(
            config.selected_case_ids.is_empty(),
            "session Replay cannot select Cases"
        );
    } else {
        validate_replay_request_headers(&config).await?;
    }
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
    let runtime = Runtime::<P>::from_source(
        config,
        (dns_listen, tcp_listen),
        lifecycle,
        providers,
        loader,
        timer_state,
        session_events,
    )
    .await?;
    let timer_listener = timer_config
        .as_ref()
        .map(|timer| timers::Listener::bind(&timer.socket_path))
        .transpose()?;
    let _prefetch_guard = {
        let mut state = runtime.state.lock().await;
        state.egress_counter_reader = counter_reader;
        state
            .session_events
            .as_ref()
            .and_then(|session| session.prefetch.as_ref())
            .map(|responses| responses.close_on_drop())
    };
    info!(
        dns_listen = %dns_listen,
        tcp_listen = %tcp_listen,
        "dependency replay intercept listening"
    );
    let outcome = tokio::select! {
        result = runtime.run_dns(dns_socket) => result,
        result = runtime.run_tcp(tcp_listener) => result,
        result = runtime.run_control() => result,
        result = async {
            match timer_listener {
                Some(listener) => listener.run(runtime.state.clone()).await,
                None => pending().await,
            }
        } => result,
        result = deferred::prefetch::run(runtime.state.clone()) => result,
    };
    if let Some(session) = &mut runtime.state.lock().await.session_events {
        session.stop_prefetch();
    }
    outcome
}
#[cfg(any(test, feature = "test-support"))]
pub(crate) use crate::adapters::runtime::{MysqlReplayConfig, ReplayAllowedUnusedHttpConfig};
#[cfg(any(test, feature = "test-support"))]
pub(crate) type ReplayRuntime = Runtime<crate::adapters::ReplayProtocols>;

pub(crate) struct Runtime<P: ReplayProtocolSet> {
    pub(crate) state: Arc<Mutex<RuntimeState<P>>>,
    pub(crate) ca: Arc<MitmCa>,
    pub(crate) report_path: Option<PathBuf>,
    pub(crate) session_path: Option<PathBuf>,
    pub(crate) control_socket_path: Option<PathBuf>,
}

impl<P: ReplayProtocolSet> Runtime<P> {
    pub(crate) async fn run_tcp(&self, listener: TcpListener) -> Result<()> {
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

    pub(crate) async fn run_dns(&self, socket: UdpSocket) -> Result<()> {
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

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) async fn write_report(&self) -> Result<()> {
        write_report_snapshot(self.state.clone(), self.report_path.clone()).await
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) async fn run_report_writer(&self) -> Result<()> {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.write_report().await?;
        }
    }

    pub(crate) async fn run_control(&self) -> Result<()> {
        run_control_socket(
            self.state.clone(),
            self.report_path.clone(),
            self.session_path.clone(),
            self.control_socket_path.clone(),
        )
        .await
    }
}

pub(crate) fn find_run_level_dependencies(root: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    (
        root.ancestors()
            .map(|dir| dir.join("indexes/startup-scope.json"))
            .find(|path| crate::dependency_index::scoped::exists(path))
            .or({
                #[cfg(any(test, feature = "test-support"))]
                {
                    find_upward(root, "global-dependencies.jsonl")
                }
                #[cfg(not(any(test, feature = "test-support")))]
                {
                    None
                }
            }),
        find_upward(root, "global-dependencies-debug.jsonl"),
    )
}

async fn validate_replay_request_headers(config: &RuntimeConfig) -> Result<()> {
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
pub(crate) struct RuntimeState<P: ReplayProtocolSet> {
    pub(crate) protocols: P,
    pub(crate) replay_policy: Option<P::Policy>,
    pub(crate) providers: Arc<crate::protocols::DependencyProviders>,
    pub(crate) native: native::Inventory,
    admission_epoch: u64,
    timers: timers::Timers,
    pub(crate) case_execution_plans: BTreeMap<String, Arc<execution_plan::CaseExecutionPlan>>,
    sequence_catalog: Option<sequence::Source>,
    pub(crate) active_sequence: Option<Arc<traffic_replay::SequenceRuntime>>,
    pub(crate) run_sequence: Option<sequence::RunBindings>,
    session_events: Option<session::Session>,
    sequence_missing: Vec<sequence::MissingDependency>,
    batch_scope: Option<reconciliation::BatchScope>,
    pub(crate) startup_phase: startup::StartupPhase,
    dependency_attribution_snapshot: Option<String>,
    prepared_socketio_input: Option<control::input_timing::PreparedSource>,
    pub(crate) input_timing: Option<control::input_timing::Live>,
    pub(crate) primary_close_timing: Option<Arc<PrimaryCloseTimeline>>,
    pub(crate) stream_timing: Option<ReplayStreamTiming>,
    pub(crate) stream_interval_cap_ms: u64,
    pub(crate) target_observations: target_observation::TargetObservations,
    case_cleanup: control::case_cleanup::CaseCleanup,
    connect_failures: connect_failure::Inventory,
    deferred: Option<Arc<deferred::DeferredDependencies>>,
    source_inventory_id: Option<String>,
    eager_source_facts: BTreeMap<String, Vec<report::unused_source::CaptureFact>>,
    egress_counter_reader: Option<ReplayEgressCounterReader>,
    egress_counter_starts: BTreeMap<String, egress_counter::Sample>,
    egress_rejections: BTreeMap<String, ReplayEgressRejections>,
    session_id: Uuid,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) finalized_at: Option<DateTime<Utc>>,
    dns_listen: SocketAddr,
    tcp_listen: SocketAddr,
    mode: ReplayMode,
    root_dir: PathBuf,
    pub(crate) cases: BTreeMap<String, ReplayCase>,
    pub(crate) active_case_id: Option<String>,
    pub(crate) target_stop_prepared: BTreeSet<String>,
    pub(crate) target_session_stopped: bool,
    pub(crate) dependency_tails: control::dependency_tail::CaseTails,
    pub(crate) case_dependency_post_response_window: std::time::Duration,
    global_path: Option<PathBuf>,
    pub(crate) regular_global: BTreeMap<String, report::global_evidence::regular::RegularBaseline>,
    pub(crate) targets: Vec<ReplayTarget>,
    pub(crate) ca_cert_path: PathBuf,
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

async fn handle_gateway_connection<P: ReplayProtocolSet>(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<Mutex<RuntimeState<P>>>,
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
    if target.is_none() {
        let registered_targets = state.lock().await.targets.len();
        #[cfg(any(test, feature = "test-support"))]
        if registered_targets == 0 {
            return RuntimeState::serve_connection(stream, peer_addr, None, state, ca).await;
        }
        let original = original_dst(&stream)
            .map(|addr| addr.to_string())
            .unwrap_or_else(|error| format!("unavailable ({error})"));
        return Err(anyhow!(
            "no replay target is registered for intercepted destination {original}; loaded {registered_targets} target mappings"
        ));
    }
    RuntimeState::serve_connection(stream, peer_addr, target, state, ca).await
}

enum ReplayDestination {
    Recorded(ReplayTarget),
    Unrecorded {
        target: TargetKey,
        active_case: bool,
    },
    Unknown,
}

async fn replay_destination_for_stream<P: ReplayProtocolSet>(
    stream: &TcpStream,
    state: &Arc<Mutex<RuntimeState<P>>>,
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
    #[cfg(any(test, feature = "test-support"))]
    if state.targets.len() == 1 {
        return ReplayDestination::Recorded(state.targets[0].clone());
    }
    ReplayDestination::Unknown
}

#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
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
pub(crate) use crate::adapters::ReplayState;
#[cfg(test)]
pub(crate) use crate::adapters::http;
#[cfg(test)]
pub(crate) use crate::adapters::runtime::ReplayConfig;
#[cfg(test)]
pub use loading_config::ReplayDependencyLoading;
#[cfg(test)]
pub use traffic_engine_replay::replay::MysqlReplayControlConfig;
#[cfg(test)]
pub use traffic_engine_replay::replay::ReplayControlConfig;
#[cfg(test)]
pub use traffic_engine_replay::replay::allocate_control_socket;
#[cfg(test)]
pub use traffic_engine_replay::replay::run_replay_control;
