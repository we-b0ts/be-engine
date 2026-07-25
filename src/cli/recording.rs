use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{RecordingWaitConfig, wait_for_recording_listeners, wait_for_recording_ready};

#[derive(Debug, Args)]
pub(super) struct RecordingArgs {
    #[command(subcommand)]
    command: RecordingCommand,
}

#[derive(Debug, Subcommand)]
enum RecordingCommand {
    /// Wait until Recorder initialization and all enabled listeners are ready.
    WaitListeners(WaitArgs),
    /// Wait until Recorder listeners and source application readiness succeed.
    WaitReady(WaitArgs),
}

#[derive(Debug, Args)]
struct WaitArgs {
    /// Unix socket published by the running Recorder process.
    #[arg(long)]
    control_socket: PathBuf,
    /// Maximum time to wait for the requested lifecycle state.
    #[arg(
        long,
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    timeout_seconds: u64,
}

pub(super) async fn run(args: RecordingArgs) -> Result<()> {
    let (args, wait_for_listeners) = match args.command {
        RecordingCommand::WaitListeners(args) => (args, true),
        RecordingCommand::WaitReady(args) => (args, false),
    };
    let config = RecordingWaitConfig {
        control_socket_path: args.control_socket,
        timeout: Duration::from_secs(args.timeout_seconds),
    };
    let response = if wait_for_listeners {
        wait_for_recording_listeners(config).await?
    } else {
        wait_for_recording_ready(config).await?
    };
    super::output::stdout_line(format_args!("{}", serde_json::to_string_pretty(&response)?))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        recording: RecordingArgs,
    }

    #[test]
    fn parses_bounded_recording_wait_timeouts() {
        for command in ["wait-listeners", "wait-ready"] {
            let parsed = TestCli::try_parse_from([
                "test",
                command,
                "--control-socket",
                "/tmp/recording.sock",
            ])
            .unwrap();
            let args = match parsed.recording.command {
                RecordingCommand::WaitListeners(args) | RecordingCommand::WaitReady(args) => args,
            };
            assert_eq!(args.timeout_seconds, 300);

            assert!(
                TestCli::try_parse_from([
                    "test",
                    command,
                    "--control-socket",
                    "/tmp/recording.sock",
                    "--timeout-seconds",
                    "0",
                ])
                .is_err()
            );
        }
    }
}
