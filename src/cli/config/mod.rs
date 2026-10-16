use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use traffic_e2e::{
    ContainerSourceOptions, DEFAULT_HTTP_BACKEND_PORT, DEFAULT_HTTP_GATEWAY_PORT,
    KubernetesSourceOptions, RepositoryConfigInitOptions, SourceOptions,
    initialize_repository_config,
};

mod recorder;

#[derive(Debug, Args)]
pub(super) struct ConfigArgs {
    /// Target repository root containing .traffic-e2e.
    #[arg(long, default_value = ".", global = true)]
    target_root: PathBuf,
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Generate the repository project and unified traffic policy once.
    Init(InitArgs),
    /// Plan or apply evidence-backed recorder configuration changes.
    Recorder(recorder::RecorderArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Running Kubernetes Pod whose application container is snapshotted during initialization.
    #[arg(
        long,
        required_unless_present = "source_container",
        requires = "namespace",
        conflicts_with = "source_container"
    )]
    source_pod: Option<String>,
    /// Local Docker container name or ID; running and stopped containers are supported.
    #[arg(long, conflicts_with = "source_pod")]
    source_container: Option<String>,
    /// Kubernetes namespace containing the source Pod.
    #[arg(long, requires = "source_pod", conflicts_with = "source_container")]
    namespace: Option<String>,
    /// Regular Pod container to snapshot; omit when there is exactly one.
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
    http_backend_port: u16,
    /// HTTP gateway port that receives traffic selected for recording.
    #[arg(long, default_value_t = DEFAULT_HTTP_GATEWAY_PORT)]
    http_gateway_port: u16,
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

pub(super) fn run(args: ConfigArgs) -> Result<()> {
    match args.command {
        ConfigCommand::Init(init) => print_json(&initialize_repository_config(
            RepositoryConfigInitOptions {
                target_root: args.target_root,
                source: match init.source_container {
                    Some(container) => {
                        SourceOptions::Container(ContainerSourceOptions { container })
                    }
                    None => SourceOptions::Kubernetes(KubernetesSourceOptions {
                        pod: init
                            .source_pod
                            .context("--source-pod or --source-container is required")?,
                        namespace: init
                            .namespace
                            .context("--namespace is required with --source-pod")?,
                        container: init.pod_container,
                        kubeconfig: init.kubeconfig,
                        context: init.context,
                        kubectl_binary: init.kubectl_binary,
                    }),
                },
                http_backend_port: init.http_backend_port,
                http_gateway_port: init.http_gateway_port,
                readiness_path: init.readiness_path,
                upstream_dns: init.upstream_dns,
                env_file: init.env_file,
            },
        )?),
        ConfigCommand::Recorder(command) => recorder::run(args.target_root, command),
    }
}

pub(super) fn print_json(value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout(), value)?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        config: ConfigArgs,
    }

    #[test]
    fn init_accepts_a_container_and_rejects_mixed_providers() {
        use clap::Parser;
        assert!(
            TestCli::try_parse_from(["test", "init", "--source-container", "local-app"]).is_ok()
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
            assert!(TestCli::try_parse_from(argv).is_err());
        }
    }

    #[test]
    fn init_uses_repository_conventions_by_default() {
        let parsed = TestCli::try_parse_from([
            "test",
            "init",
            "--source-pod",
            "friendship",
            "--namespace",
            "wb-plat-ide",
        ])
        .unwrap();
        let ConfigCommand::Init(init) = parsed.config.command else {
            panic!("expected init command");
        };
        assert_eq!(init.http_backend_port, DEFAULT_HTTP_BACKEND_PORT);
        assert_eq!(init.http_gateway_port, DEFAULT_HTTP_GATEWAY_PORT);
        assert_eq!(init.readiness_path, "/healthz");
        assert_eq!(init.upstream_dns, "10.10.10.11:53".parse().unwrap());
    }

    #[test]
    fn init_does_not_accept_derived_runtime_inputs() {
        assert!(
            TestCli::try_parse_from([
                "test",
                "init",
                "--source-pod",
                "friendship",
                "--namespace",
                "wb-plat-ide",
                "--source-http-port",
                "8081",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "init",
                "--source-pod",
                "friendship",
                "--namespace",
                "wb-plat-ide",
                "--target-port",
                "8081",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "init",
                "--source-pod",
                "friendship",
                "--namespace",
                "wb-plat-ide",
                "--readiness-status",
                "204",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "init",
                "--source-pod",
                "friendship",
                "--namespace",
                "wb-plat-ide",
                "--breeze",
            ])
            .is_err()
        );
    }

    #[test]
    fn init_accepts_explicit_http_ports() {
        let parsed = TestCli::try_parse_from([
            "test",
            "init",
            "--source-pod",
            "source",
            "--namespace",
            "wb-plat-ide",
            "--http-backend-port",
            "8081",
            "--http-gateway-port",
            "18181",
        ])
        .unwrap();
        let ConfigCommand::Init(init) = parsed.config.command else {
            panic!("expected init command");
        };
        assert_eq!(init.http_backend_port, 8_081);
        assert_eq!(init.http_gateway_port, 18_181);
    }
}
