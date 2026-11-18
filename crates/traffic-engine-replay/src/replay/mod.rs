pub use crate::MitmCa;
use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};
use uuid::Uuid;
pub mod attribution;
pub use attribution::{attribution_scope_key, prewarm_attribution_indexes};
pub mod adapters;
pub mod admission;
pub mod connect_failure;
pub mod control;
pub mod dependencies;
pub mod dns;
pub mod egress_counter;
pub mod exchange;
pub mod execution_plan;
pub mod global;
pub mod loading_config;
pub mod model;
pub mod native;
pub mod policy;
pub mod protocol_runtime;
pub mod reconciliation;
pub mod report;
pub use adapters::*;
pub use control::*;
pub use dependencies::{RecordedProxyError, target_from_addr};
use dns::Ipv4Cidr;
pub use egress_counter::*;
pub use exchange::*;
pub use loading_config::*;
pub use model::*;
pub use reconciliation::BatchReconciliation;
pub use reconciliation::validate_completed_receipt_with;
pub use report::global_evidence::GlobalDependencyPage;
pub use traffic_replay::preparation::{PreparedProtocols, RunSequenceReference};
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
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
    pub process_owned_dependencies: Vec<crate::BackgroundDependencyRuleConfig>,
}

pub use traffic_engine_config::replay::{
    DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS, ReplayStreamTiming,
};

pub const FAST_CASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

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
pub struct ReplayControlConfig {
    pub session_path: PathBuf,
    pub command: String,
    pub case_id: Option<String>,
    pub fail_on_dirty: bool,
    pub fail_on_incomplete: bool,
    pub wait_timeout: Option<std::time::Duration>,
}

pub type MysqlReplayControlConfig = ReplayControlConfig;

pub async fn run_replay_control(config: ReplayControlConfig) -> Result<Value> {
    send_control_request(config).await
}
pub use control::{
    FinalizationScope, input_timing_observer, native_event_observer, primary_close_observer,
    register_derived_input,
};

pub async fn run_mysql_replay_control(config: MysqlReplayControlConfig) -> Result<Value> {
    run_replay_control(config).await
}

pub fn allocate_control_socket() -> PathBuf {
    #[cfg(unix)]
    let temporary_root = PathBuf::from("/tmp");
    #[cfg(not(unix))]
    let temporary_root = std::env::temp_dir();

    temporary_root.join(format!("trp-e2e-{}.sock", Uuid::new_v4().simple()))
}

pub const UNRECORDED_ENDPOINT_REASON: &str = "访问了录制时没有访问过的域名:port";

pub mod recording_evidence;
pub use recording_evidence::dependency_started_at;

pub use traffic_engine_config::replay::{
    DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS,
    DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS,
};
