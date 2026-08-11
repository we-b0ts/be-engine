use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    DEFAULT_HTTP_GATEWAY_PORT, RepositoryConfigInitOptions, initialize_repository_config,
};

mod comparison;
mod recorder;
mod replay;

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
    /// Generate the repository's project, recorder, and verification configuration once.
    Init(InitArgs),
    /// Plan or apply evidence-backed recorder configuration changes.
    Recorder(recorder::RecorderArgs),
    /// Configure dependency replay and response rules inherited by comparison.
    Replay(replay::ReplayArgs),
    /// Configure additional comparison-only response rules.
    Comparison(comparison::ComparisonArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Existing genuine source application container to inspect and reproduce.
    #[arg(long)]
    source_container: String,
    /// Enable Breeze using the conventional `breeze` container, or provide a non-standard name.
    #[arg(long, num_args = 0..=1, default_missing_value = "breeze", value_name = "CONTAINER")]
    breeze: Option<String>,
    /// Source HTTP port used by the managed recorder.
    #[arg(long, default_value_t = 8080)]
    source_http_port: u16,
    /// Target HTTP port used for replay and comparison.
    #[arg(long, default_value_t = 8080)]
    target_port: u16,
    /// HTTP gateway port that receives traffic selected for recording.
    #[arg(long, default_value_t = DEFAULT_HTTP_GATEWAY_PORT)]
    http_gateway_port: u16,
    /// Readiness path shared by source recording and target startup.
    #[arg(long, default_value = "/healthz")]
    readiness_path: String,
    /// Final HTTP status that indicates readiness.
    #[arg(long, default_value_t = 404)]
    readiness_status: u16,
    /// DNS server for queries not owned by the recorder.
    #[arg(long, default_value = "10.10.10.11:53")]
    upstream_dns: SocketAddr,
    /// Source-compatible absolute file or directory to copy and mount read-only.
    #[arg(long = "startup-mount", value_name = "ABSOLUTE_PATH")]
    startup_mounts: Vec<PathBuf>,
    /// Application-owned environment variable captured from the source container.
    #[arg(long = "startup-env", value_name = "NAME")]
    startup_environment: Vec<String>,
    /// Application-owned environment variable that receives the configured target port.
    #[arg(long, value_name = "NAME")]
    target_port_env: Option<String>,
    /// Application-owned environment variable that receives the Replay CA path.
    #[arg(long, value_name = "NAME")]
    replay_ca_env: Option<String>,
}

pub(super) fn run(args: ConfigArgs) -> Result<()> {
    match args.command {
        ConfigCommand::Init(init) => print_json(&initialize_repository_config(
            RepositoryConfigInitOptions {
                target_root: args.target_root,
                source_container: init.source_container,
                breeze_container: init.breeze,
                source_http_port: init.source_http_port,
                target_port: init.target_port,
                http_gateway_port: init.http_gateway_port,
                readiness_path: init.readiness_path,
                readiness_status: init.readiness_status,
                upstream_dns: init.upstream_dns,
                startup: traffic_e2e::StartupConfig {
                    mounts: init.startup_mounts,
                    environment_from_source: init.startup_environment,
                    port_environment: init.target_port_env,
                    replay_ca_environment: init.replay_ca_env,
                },
            },
        )?),
        ConfigCommand::Recorder(command) => recorder::run(args.target_root, command),
        ConfigCommand::Replay(command) => replay::run(args.target_root, command),
        ConfigCommand::Comparison(command) => comparison::run(args.target_root, command),
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
    fn init_uses_repository_conventions_by_default() {
        let parsed = TestCli::try_parse_from([
            "test",
            "init",
            "--source-container",
            "friendship",
            "--breeze",
        ])
        .unwrap();
        let ConfigCommand::Init(init) = parsed.config.command else {
            panic!("expected init command");
        };
        assert_eq!(init.breeze.as_deref(), Some("breeze"));
        assert_eq!(init.source_http_port, 8080);
        assert_eq!(init.target_port, 8080);
        assert_eq!(init.http_gateway_port, DEFAULT_HTTP_GATEWAY_PORT);
        assert_eq!(init.readiness_path, "/healthz");
        assert_eq!(init.readiness_status, 404);
        assert_eq!(init.upstream_dns, "10.10.10.11:53".parse().unwrap());
    }

    #[test]
    fn init_accepts_a_non_standard_breeze_container_as_the_flag_value() {
        let parsed = TestCli::try_parse_from([
            "test",
            "init",
            "--source-container",
            "source",
            "--breeze=custom-breeze",
            "--http-gateway-port",
            "18181",
        ])
        .unwrap();
        let ConfigCommand::Init(init) = parsed.config.command else {
            panic!("expected init command");
        };
        assert_eq!(init.breeze.as_deref(), Some("custom-breeze"));
        assert_eq!(init.http_gateway_port, 18_181);
    }
}
