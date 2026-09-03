use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use traffic_e2e::{
    DEFAULT_HTTP_BACKEND_PORT, DEFAULT_HTTP_GATEWAY_PORT, KubernetesSourceOptions,
    ManagedRecordingPreflightOptions, RepositoryConfigInitOptions, RepositoryConfigInitResult,
    SourceSnapshotReport, StartupSnapshotReport, initialize_repository_config,
    run_managed_recording_preflight,
};

#[derive(Debug, Args)]
pub(super) struct ProjectInitArgs {
    #[command(subcommand)]
    pub(super) command: Option<ProjectInitCommand>,
    /// Running Kubernetes Pod whose application container is snapshotted during initialization.
    #[arg(long)]
    source_pod: Option<String>,
    /// Kubernetes namespace containing the source Pod.
    #[arg(long)]
    namespace: Option<String>,
    /// Regular Pod container to snapshot; omit when the Pod has exactly one regular container.
    #[arg(long)]
    pod_container: Option<String>,
    /// Kubeconfig used only while creating the source snapshot.
    #[arg(long, value_name = "PATH")]
    kubeconfig: Option<PathBuf>,
    /// Kubeconfig context used only while creating the source snapshot.
    #[arg(long)]
    context: Option<String>,
    /// kubectl executable used during initialization.
    #[arg(long, default_value = "kubectl", value_name = "PATH")]
    kubectl_binary: PathBuf,
    /// Native HTTP port listened to by the source and target backend processes.
    #[arg(long, default_value_t = DEFAULT_HTTP_BACKEND_PORT)]
    pub(super) http_backend_port: u16,
    /// HTTP gateway port that receives traffic selected for recording.
    #[arg(long, default_value_t = DEFAULT_HTTP_GATEWAY_PORT)]
    pub(super) http_gateway_port: u16,
    /// Readiness path shared by source recording and target startup.
    #[arg(long, default_value = "/healthz")]
    readiness_path: String,
    /// DNS server for queries not owned by the recorder.
    #[arg(long, default_value = "10.10.10.11:53")]
    upstream_dns: SocketAddr,
    /// Optional dotenv file used to initialize .traffic-e2e/local/target.env.
    #[arg(long, value_name = "PATH")]
    env_file: Option<PathBuf>,
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
}

#[derive(Debug, Serialize)]
struct ProjectInitReport {
    generated: Vec<PathBuf>,
    source_snapshot: SourceSnapshotReport,
    http_backend_port: u16,
    http_gateway_port: u16,
    local_dir: PathBuf,
    target_environment: PathBuf,
    gitignore: PathBuf,
    gitignore_updated: bool,
    dockerignore: PathBuf,
    dockerignore_updated: bool,
    startup: StartupSnapshotReport,
    recording_dockerfile: PathBuf,
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
                })
                .await;
                match result {
                    Ok(result) => super::print_json(&result, pretty),
                    Err(error) => {
                        let reason = bounded_failure_reason(format!("{error:#}"));
                        let stage = preflight_failure_stage(&reason);
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
    let source_pod = args
        .source_pod
        .context("--source-pod is required when creating repository configuration")?;
    let namespace = args
        .namespace
        .context("--namespace is required when creating repository configuration")?;
    let result = initialize_repository_config(RepositoryConfigInitOptions {
        target_root,
        source: KubernetesSourceOptions {
            pod: source_pod,
            namespace,
            container: args.pod_container,
            kubeconfig: args.kubeconfig,
            context: args.context,
            kubectl_binary: args.kubectl_binary,
        },
        http_backend_port: args.http_backend_port,
        http_gateway_port: args.http_gateway_port,
        readiness_path: args.readiness_path,
        upstream_dns: args.upstream_dns,
        env_file: args.env_file,
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

fn preflight_failure_stage(reason: &str) -> &'static str {
    if reason.contains("target_image preflight failed") {
        "target_image"
    } else if reason.contains("replay_network preflight failed") {
        "replay_network"
    } else if reason.contains("target_runtime preflight failed") {
        "target_runtime"
    } else {
        "recording"
    }
}

impl From<RepositoryConfigInitResult> for ProjectInitReport {
    fn from(result: RepositoryConfigInitResult) -> Self {
        Self {
            generated: result.generated,
            source_snapshot: result.source_snapshot,
            http_backend_port: result.http_backend_port,
            http_gateway_port: result.http_gateway_port,
            local_dir: result.local_dir,
            target_environment: result.target_environment,
            gitignore: result.gitignore,
            gitignore_updated: result.gitignore_updated,
            dockerignore: result.dockerignore,
            dockerignore_updated: result.dockerignore_updated,
            startup: result.startup,
            recording_dockerfile: result.recording_dockerfile,
            target_dockerfile: result.target_dockerfile,
            target_image_tag: result.target_image_tag,
            target_runtime_contract: result.target_runtime_contract,
            preflight_command: result.preflight_command,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::preflight_failure_stage;

    #[test]
    fn classifies_preflight_failure_stages() {
        assert_eq!(
            preflight_failure_stage("target_image preflight failed: build failed"),
            "target_image"
        );
        assert_eq!(
            preflight_failure_stage("replay_network preflight failed: DNS leaked"),
            "replay_network"
        );
        assert_eq!(
            preflight_failure_stage("target_runtime preflight failed: readiness timed out"),
            "target_runtime"
        );
        assert_eq!(
            preflight_failure_stage("source adaptor did not become ready"),
            "recording"
        );
    }
}
