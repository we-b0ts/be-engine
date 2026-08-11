use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use traffic_e2e::{
    DEFAULT_HTTP_GATEWAY_PORT, InspectedContainer, ManagedRecordingPreflightOptions, RecordingApi,
    RepositoryConfigInitOptions, RepositoryConfigInitResult, StartupConfig, StartupSnapshotReport,
    initialize_repository_config, run_managed_recording_preflight,
};

#[derive(Debug, Args)]
pub(super) struct ProjectInitArgs {
    #[command(subcommand)]
    pub(super) command: Option<ProjectInitCommand>,
    /// Existing genuine source application container to inspect and reproduce.
    #[arg(long)]
    source_container: Option<String>,
    /// Enable Breeze using the conventional `breeze` container, or provide a non-standard name.
    #[arg(long, num_args = 0..=1, default_missing_value = "breeze", value_name = "CONTAINER")]
    breeze: Option<String>,
    /// HTTP gateway port that receives traffic selected for recording.
    #[arg(long, default_value_t = DEFAULT_HTTP_GATEWAY_PORT)]
    pub(super) http_gateway_port: u16,
    /// Readiness path shared by source recording and target startup.
    #[arg(long, default_value = "/healthz")]
    readiness_path: String,
    /// Final HTTP status that indicates readiness.
    #[arg(long, default_value_t = 404)]
    readiness_status: u16,
    /// DNS server for queries not owned by the recorder.
    #[arg(long, default_value = "10.10.10.11:53")]
    upstream_dns: SocketAddr,
    /// Source-compatible absolute file or directory to snapshot; exact source mounts retain rw/ro.
    #[arg(long = "startup-mount", value_name = "ABSOLUTE_PATH")]
    startup_mounts: Vec<PathBuf>,
    /// Application-owned environment variable whose value is captured from the source container.
    #[arg(long = "startup-env", value_name = "NAME")]
    startup_environment: Vec<String>,
    /// Application-owned environment variable that receives the recorder-owned native HTTP port.
    #[arg(long, value_name = "NAME")]
    target_port_env: Option<String>,
    /// Application-owned environment variable that receives the Replay CA certificate path.
    #[arg(long, value_name = "NAME")]
    replay_ca_env: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(super) enum ProjectInitCommand {
    /// Validate the target container and source recording environment without advancing state.
    Preflight(ProjectPreflightArgs),
}

#[derive(Debug, Args)]
pub(super) struct ProjectPreflightArgs {
    /// Keep the disposable recording window open for at most this many seconds.
    #[arg(long, default_value = "60")]
    duration_seconds: NonZeroU64,
    /// Apply the fixed Platform Mesh no-fallback commands after source readiness.
    #[arg(
        long,
        default_value = "true",
        action = clap::ArgAction::Set,
        value_parser = parse_bool
    )]
    brz_no_fallback: bool,
    /// Record only this API; repeat for multiple METHOD/path selectors.
    #[arg(long = "api", value_name = "METHOD PATH_OR_PATTERN")]
    apis: Vec<RecordingApi>,
    /// Override the per-API case limit for every selected API.
    #[arg(long = "per-api-case-limit", value_name = "N", default_value = "1")]
    per_api_case_limit: NonZeroUsize,
}

#[derive(Debug, Serialize)]
struct ProjectInitReport {
    generated: Vec<PathBuf>,
    source_container: InspectedContainer,
    #[serde(skip_serializing_if = "Option::is_none")]
    breeze_container: Option<InspectedContainer>,
    http_gateway_port: u16,
    local_dir: PathBuf,
    gitignore: PathBuf,
    gitignore_updated: bool,
    startup: StartupSnapshotReport,
    target_dockerfile: PathBuf,
    target_image_tag: String,
    target_runtime_contract: &'static str,
    preflight_command: &'static str,
}

#[derive(Debug, Serialize)]
struct ProjectPreflightFailureReport {
    status: &'static str,
    failure: ProjectPreflightFailure,
    managed_by: &'static str,
}

#[derive(Debug, Serialize)]
struct ProjectPreflightFailure {
    stage: &'static str,
    reason: String,
}

pub(super) async fn run(target_root: PathBuf, args: ProjectInitArgs, pretty: bool) -> Result<()> {
    if let Some(command) = args.command {
        return match command {
            ProjectInitCommand::Preflight(args) => {
                let result = run_managed_recording_preflight(ManagedRecordingPreflightOptions {
                    target_root,
                    duration_seconds: args.duration_seconds,
                    breeze_no_fallback: args.brz_no_fallback,
                    apis: args.apis,
                    per_api_case_limit: Some(args.per_api_case_limit),
                })
                .await;
                match result {
                    Ok(result) => super::print_json(&result, pretty),
                    Err(error) => {
                        let reason = bounded_failure_reason(format!("{error:#}"));
                        let stage = if reason.contains("target_container preflight failed") {
                            "target_container"
                        } else if reason.contains("replay_network preflight failed") {
                            "replay_network"
                        } else {
                            "recording"
                        };
                        super::print_json(
                            &ProjectPreflightFailureReport {
                                status: "failed",
                                failure: ProjectPreflightFailure { stage, reason },
                                managed_by: "traffic-e2e",
                            },
                            pretty,
                        )?;
                        Err(error)
                    }
                }
            }
        };
    }
    let source_container = args
        .source_container
        .context("--source-container is required when creating repository configuration")?;
    let result = initialize_repository_config(RepositoryConfigInitOptions {
        target_root,
        source_container,
        breeze_container: args.breeze,
        http_gateway_port: args.http_gateway_port,
        readiness_path: args.readiness_path,
        readiness_status: args.readiness_status,
        upstream_dns: args.upstream_dns,
        startup: StartupConfig {
            mounts: args.startup_mounts,
            environment_from_source: args.startup_environment,
            port_environment: args.target_port_env,
            replay_ca_environment: args.replay_ca_env,
        },
    })?;
    super::print_json(&ProjectInitReport::from(result), pretty)
}

fn bounded_failure_reason(mut reason: String) -> String {
    const MAX_BYTES: usize = 2_048;
    if reason.len() <= MAX_BYTES {
        return reason;
    }
    let suffix = "… [truncated]";
    let mut end = MAX_BYTES - suffix.len();
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason.truncate(end);
    reason.push_str(suffix);
    reason
}

impl From<RepositoryConfigInitResult> for ProjectInitReport {
    fn from(result: RepositoryConfigInitResult) -> Self {
        Self {
            generated: result.generated,
            source_container: result.source_container,
            breeze_container: result.breeze_container,
            http_gateway_port: result.http_gateway_port,
            local_dir: result.local_dir,
            gitignore: result.gitignore,
            gitignore_updated: result.gitignore_updated,
            startup: result.startup,
            target_dockerfile: result.target_dockerfile,
            target_image_tag: result.target_image_tag,
            target_runtime_contract: result.target_runtime_contract,
            preflight_command: result.preflight_command,
        }
    }
}

fn parse_bool(value: &str) -> std::result::Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("value must be literal true or false".to_string()),
    }
}
