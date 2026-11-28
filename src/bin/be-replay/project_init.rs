use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;
use traffic_e2e::{
    ContainerSourceOptions, DEFAULT_HTTP_BACKEND_PORT, DEFAULT_HTTP_GATEWAY_PORT,
    KubernetesSourceOptions, RepositoryConfigInitOptions, RepositoryConfigInitResult,
    SourceOptions, SourceSnapshotReport, StartupSnapshotReport, initialize_repository_config,
};

#[derive(Debug, Args)]
pub(super) struct ProjectInitArgs {
    /// Running Kubernetes Pod whose application container is snapshotted during initialization.
    #[arg(long, requires = "namespace", conflicts_with = "source_container")]
    source_pod: Option<String>,
    /// Local Docker container name or ID; running and stopped containers are supported.
    #[arg(long, conflicts_with = "source_pod")]
    source_container: Option<String>,
    /// Kubernetes namespace containing the source Pod.
    #[arg(long, requires = "source_pod", conflicts_with = "source_container")]
    namespace: Option<String>,
    /// Regular Pod container to snapshot; omit when the Pod has exactly one regular container.
    #[arg(long, requires = "source_pod", conflicts_with = "source_container")]
    pod_container: Option<String>,
    /// Kubeconfig used only while creating the source snapshot.
    #[arg(
        long,
        value_name = "PATH",
        requires = "source_pod",
        conflicts_with = "source_container"
    )]
    kubeconfig: Option<PathBuf>,
    /// Kubeconfig context used only while creating the source snapshot.
    #[arg(long, requires = "source_pod", conflicts_with = "source_container")]
    context: Option<String>,
    /// kubectl executable used during initialization.
    #[arg(
        long,
        default_value = "kubectl",
        value_name = "PATH",
        conflicts_with = "source_container"
    )]
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
    source_dockerfile: PathBuf,
    target_dockerfile: PathBuf,
    target_image_tag: String,
    target_runtime_contract: &'static str,
    preflight_command: &'static str,
}

pub(super) async fn run(target_root: PathBuf, args: ProjectInitArgs, pretty: bool) -> Result<()> {
    let source = match args.source_container {
        Some(container) => SourceOptions::Container(ContainerSourceOptions { container }),
        None => SourceOptions::Kubernetes(KubernetesSourceOptions {
            pod: args.source_pod.context("--source-pod or --source-container is required when creating repository configuration")?,
            namespace: args.namespace.context("--namespace is required with --source-pod")?,
            container: args.pod_container,
            kubeconfig: args.kubeconfig,
            context: args.context,
            kubectl_binary: args.kubectl_binary,
        }),
    };
    let result = initialize_repository_config(RepositoryConfigInitOptions {
        target_root,
        source,
        http_backend_port: args.http_backend_port,
        http_gateway_port: args.http_gateway_port,
        readiness_path: args.readiness_path,
        upstream_dns: args.upstream_dns,
        env_file: args.env_file,
    })?;
    super::print_json(&ProjectInitReport::from(result), pretty)
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
            source_dockerfile: result.source_dockerfile,
            target_dockerfile: result.target_dockerfile,
            target_image_tag: result.target_image_tag,
            target_runtime_contract: result.target_runtime_contract,
            preflight_command: result.preflight_command,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_accepts_a_container_and_rejects_mixed_providers() {
        use clap::Parser;
        assert!(
            super::super::Cli::try_parse_from(["test", "init", "--source-container", "local-app"])
                .is_ok()
        );
        for args in [
            vec!["--source-pod", "pod", "--namespace", "default"],
            vec!["--namespace", "default"],
            vec!["--pod-container", "app"],
            vec!["--kubeconfig", "/tmp/config"],
            vec!["--context", "cluster"],
            vec!["--kubectl-binary", "kubectl"],
        ] {
            let mut argv = vec!["test", "init", "--source-container", "local-app"];
            argv.extend(args);
            assert!(super::super::Cli::try_parse_from(argv).is_err());
        }
    }
}
