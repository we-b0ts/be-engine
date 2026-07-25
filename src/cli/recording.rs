use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{RecordingWaitConfig, wait_for_recording_ready};

#[derive(Debug, Args)]
pub(super) struct RecordingArgs {
    #[command(subcommand)]
    command: RecordingCommand,
}

#[derive(Debug, Subcommand)]
enum RecordingCommand {
    /// Wait until Recorder listeners and source application readiness succeed.
    WaitReady(WaitReadyArgs),
}

#[derive(Debug, Args)]
struct WaitReadyArgs {
    /// Unix socket published by the running Recorder process.
    #[arg(long)]
    control_socket: PathBuf,
    /// Maximum time to wait for ready-to-record state.
    #[arg(
        long,
        default_value_t = 180,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    timeout_seconds: u64,
}

pub(super) async fn run(args: RecordingArgs) -> Result<()> {
    match args.command {
        RecordingCommand::WaitReady(args) => {
            let response = wait_for_recording_ready(RecordingWaitConfig {
                control_socket_path: args.control_socket,
                timeout: Duration::from_secs(args.timeout_seconds),
            })
            .await?;
            super::output::stdout_line(format_args!("{}", serde_json::to_string_pretty(&response)?))
        }
    }
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
    fn parses_bounded_wait_ready_timeout() {
        let parsed = TestCli::try_parse_from([
            "test",
            "wait-ready",
            "--control-socket",
            "/tmp/recording.sock",
        ])
        .unwrap();
        let RecordingCommand::WaitReady(args) = parsed.recording.command;
        assert_eq!(args.timeout_seconds, 180);

        assert!(
            TestCli::try_parse_from([
                "test",
                "wait-ready",
                "--control-socket",
                "/tmp/recording.sock",
                "--timeout-seconds",
                "0",
            ])
            .is_err()
        );
    }
}
