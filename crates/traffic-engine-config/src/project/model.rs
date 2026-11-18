use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
pub const DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS: u64 = 60;
pub const DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS: u64 = 180;
pub const MAX_TARGET_STARTUP_TIMEOUT_SECONDS: u64 = 30 * 60;
pub const DEFAULT_TARGET_REQUEST_TIMEOUT_SECONDS: u64 = 30;
pub const DEFAULT_MAX_FAILED_CASES_PER_API: usize = 10;
fn default_replay_startup_timeout_seconds() -> u64 {
    DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS
}

fn default_target_startup_timeout_seconds() -> u64 {
    DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS
}

fn default_request_timeout_allowance_seconds() -> u64 {
    DEFAULT_TARGET_REQUEST_TIMEOUT_SECONDS
}

fn default_replay_case_dependency_post_response_window_ms() -> u64 {
    crate::replay::DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS
}

fn default_replay_case_no_progress_timeout_ms() -> u64 {
    crate::replay::DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub version: u32,
    pub project: ProjectSettings,
    pub recorder: crate::config::AppConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSettings {
    pub policy: PathBuf,
    pub source: SourceProjectConfig,
    pub target: TargetProjectConfig,
    pub replay: ReplayProjectConfig,
    #[serde(default)]
    pub verification: VerificationProjectConfig,
    pub delivery: DeliveryProjectConfig,
    pub state: StateProjectConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProjectConfig {
    pub snapshot: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProjectConfig {
    pub dockerfile: PathBuf,
    #[serde(default = "default_target_startup_timeout_seconds")]
    pub startup_timeout_seconds: u64,
    pub startup: crate::startup::StartupConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_outputs: Vec<crate::runtime_output::RuntimeOutputConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayProjectConfig {
    #[serde(default = "pre_match_default")]
    pub pre_match: bool,
    #[serde(default)]
    pub socketio_timing: crate::interaction::replay::timing::SocketIoTiming,
    #[serde(default = "default_replay_case_no_progress_timeout_ms")]
    pub case_no_progress_timeout_ms: u64,
    #[serde(default = "default_replay_startup_timeout_seconds")]
    pub startup_timeout_seconds: u64,
    /// Additional wall time beyond the recorded Source response duration.
    #[serde(default = "default_request_timeout_allowance_seconds")]
    pub request_timeout_allowance_seconds: u64,
    #[serde(
        default = "crate::replay::ReplayDependencyLoading::managed_default",
        deserialize_with = "crate::replay::ReplayDependencyLoading::deserialize_managed"
    )]
    pub dependency_loading: crate::replay::ReplayDependencyLoading,
    #[serde(default = "default_replay_case_dependency_post_response_window_ms")]
    pub case_dependency_post_response_window_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationProjectConfig {
    #[serde(default = "default_max_failed_cases_per_api")]
    pub max_failed_cases_per_api: usize,
}

impl Default for VerificationProjectConfig {
    fn default() -> Self {
        Self {
            max_failed_cases_per_api: DEFAULT_MAX_FAILED_CASES_PER_API,
        }
    }
}

fn default_max_failed_cases_per_api() -> usize {
    DEFAULT_MAX_FAILED_CASES_PER_API
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryProjectConfig {
    pub pr_base: String,
    /// Agent-owned final quality tool; the engine never executes it.
    #[serde(default = "default_quality_check")]
    pub quality_check: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_paths: Vec<ManagedPathProjectConfig>,
}

pub fn default_quality_check() -> String {
    "cargo-clippy".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManagedPathProjectConfig {
    Path(PathBuf),
    BuildContext(ManagedBuildContextProjectConfig),
}

impl ManagedPathProjectConfig {
    pub fn path(&self) -> &Path {
        match self {
            Self::Path(path) => path,
            Self::BuildContext(config) => &config.path,
        }
    }

    pub fn build_context(&self) -> Option<&str> {
        match self {
            Self::Path(_) => None,
            Self::BuildContext(config) => Some(&config.build_context),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedBuildContextProjectConfig {
    pub path: PathBuf,
    pub build_context: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetBuildContext {
    pub name: String,
    pub root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateProjectConfig {
    #[serde(default = "default_runtime_root")]
    pub runtime_root: PathBuf,
}

fn default_runtime_root() -> PathBuf {
    PathBuf::from(crate::internal_runtime::PROJECT_RELATIVE_ROOT)
}

#[derive(Debug, Clone)]
pub struct ResolvedProjectConfig {
    pub replay_pre_match: bool,
    pub replay_stream_timing: Option<crate::replay::ReplayStreamTiming>,
    pub replay_stream_interval_cap_ms: u64,
    pub replay_socketio_timing: crate::interaction::replay::timing::SocketIoTiming,
    pub replay_case_no_progress_timeout: Duration,
    pub replay_loading: crate::replay::ReplayDependencyLoading,
    pub target_dockerfile: PathBuf,
    pub target_build_contexts: Vec<TargetBuildContext>,
    pub target_startup: crate::startup::StartupConfig,
    pub target_runtime_outputs: Vec<crate::runtime_output::RuntimeOutputConfig>,
    pub target_http_origin: String,
    pub target_port: u16,
    pub target_http_readiness_enabled: bool,
    pub target_readiness_path: String,
    pub target_readiness_status: u16,
    pub target_startup_timeout: Duration,
    pub target_request_timeout: Duration,
    pub target_max_response_bytes: usize,
    pub replay_policy: PathBuf,
    pub replay_case_dependency_post_response_window: Duration,
    pub max_failed_cases_per_api: usize,
    pub replay_startup_timeout: Duration,
    pub pr_base: String,
    pub quality_check: String,
    pub managed_paths: Vec<PathBuf>,
    pub recorder_config: PathBuf,
    pub source_traffic_policy: PathBuf,
    pub runner_owned_response_assertions: bool,
}

fn pre_match_default() -> bool {
    true
}
