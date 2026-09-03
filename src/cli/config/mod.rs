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
                source_container: init.source_container,
                breeze_container: init.breeze,
                http_gateway_port: init.http_gateway_port,
                readiness_path: init.readiness_path,
                upstream_dns: init.upstream_dns,
                env_file: init.env_file,
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
                "--source-container",
                "friendship",
                "--source-http-port",
                "8081",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "init",
                "--source-container",
                "friendship",
                "--target-port",
                "8081",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "init",
                "--source-container",
                "friendship",
                "--readiness-status",
                "204",
            ])
            .is_err()
        );
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
