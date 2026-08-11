use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{MotanProtocolConfigOptions, enable_repository_motan_protocol};

#[derive(Debug, Args)]
pub(super) struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Configure one recording and replay protocol.
    Protocol(ProtocolArgs),
}

#[derive(Debug, Args)]
struct ProtocolArgs {
    #[command(subcommand)]
    command: ProtocolCommand,
}

#[derive(Debug, Subcommand)]
enum ProtocolCommand {
    /// Enable or converge one protocol configuration.
    Enable(ProtocolEnableArgs),
}

#[derive(Debug, Args)]
struct ProtocolEnableArgs {
    #[command(subcommand)]
    command: ProtocolEnableCommand,
}

#[derive(Debug, Subcommand)]
enum ProtocolEnableCommand {
    /// Enable Motan1 and Motan2 gateway recording support.
    Motan(MotanProtocolArgs),
}

#[derive(Debug, Args)]
struct MotanProtocolArgs {
    /// Host port on which the managed Motan recording gateway listens.
    #[arg(long)]
    gateway_port: u16,
}

pub(super) fn run(target_root: PathBuf, args: ConfigArgs, pretty: bool) -> Result<()> {
    match args.command {
        ConfigCommand::Protocol(args) => match args.command {
            ProtocolCommand::Enable(args) => match args.command {
                ProtocolEnableCommand::Motan(args) => {
                    let result = enable_repository_motan_protocol(MotanProtocolConfigOptions {
                        target_root,
                        gateway_port: args.gateway_port,
                    })?;
                    super::print_json(&result, pretty)
                }
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::{Cli, RewriteCommand};

    #[test]
    fn parses_nested_motan_protocol_enable_command() {
        let cli = Cli::try_parse_from([
            "backend-rewrite",
            "config",
            "protocol",
            "enable",
            "motan",
            "--gateway-port",
            "18081",
        ])
        .unwrap();

        assert!(matches!(cli.command, RewriteCommand::Config(_)));
        assert!(
            Cli::try_parse_from([
                "backend-rewrite",
                "config",
                "protocol",
                "enable",
                "motan",
                "--source-port",
                "8080",
                "--gateway-port",
                "18081",
            ])
            .is_err()
        );
    }
}
