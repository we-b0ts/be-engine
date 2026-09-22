use std::ffi::OsString;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use traffic_e2e::{RecordingApi, SourceRecordingOptions, run_source_recording};

#[derive(Debug, Args)]
pub(super) struct RecordSourceArgs {
    /// Target repository containing .traffic-e2e/project.yaml.
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    /// Explicit 14-digit UTC run identifier. A current UTC identifier is generated when omitted.
    #[arg(long, value_parser = parse_run_id)]
    run_id: Option<String>,
    /// Record for this many seconds after Source readiness succeeds.
    #[arg(long, default_value = "60")]
    duration_seconds: NonZeroU64,
    /// Maximum time to wait for Recorder listeners and Source readiness.
    #[arg(long, default_value = "300")]
    startup_timeout_seconds: NonZeroU64,
    /// Record only this API; repeat for multiple METHOD/path selectors.
    #[arg(long = "api", value_name = "METHOD PATH_OR_PATTERN")]
    apis: Vec<RecordingApi>,
    /// Override the per-API case limit for every selected API.
    #[arg(long = "per-api-case-limit", value_name = "N")]
    per_api_case_limit: Option<NonZeroUsize>,
    /// Source working directory; relative paths are resolved under target-root.
    #[arg(long)]
    source_workdir: Option<PathBuf>,
    /// Source command and arguments. Source runs as the fixed 998:998 traffic identity.
    #[arg(last = true, required = true, num_args = 1..)]
    source_command: Vec<OsString>,
}

pub(super) async fn run(args: RecordSourceArgs) -> Result<()> {
    let report = run_source_recording(SourceRecordingOptions {
        target_root: args.target_root,
        run_id: args.run_id,
        duration_seconds: args.duration_seconds,
        startup_timeout_seconds: args.startup_timeout_seconds,
        apis: args.apis,
        per_api_case_limit: args.per_api_case_limit,
        source_working_directory: args.source_workdir,
        source_command: args.source_command,
    })
    .await?;
    serde_json::to_writer_pretty(std::io::stdout(), &report)?;
    println!();
    Ok(())
}

fn parse_run_id(value: &str) -> std::result::Result<String, String> {
    if value.len() == 14
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && chrono::NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S").is_ok()
    {
        Ok(value.to_string())
    } else {
        Err("run ID must contain exactly 14 ASCII digits (YYYYMMDDHHMMSS)".to_string())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        record_source: RecordSourceArgs,
    }

    #[test]
    fn parses_source_command_and_recording_scope() {
        let parsed = TestCli::try_parse_from([
            "test",
            "--duration-seconds",
            "30",
            "--api",
            "POST /api/widgets",
            "--",
            "/app/source",
            "--port",
            "7171",
        ])
        .unwrap();
        assert_eq!(parsed.record_source.duration_seconds.get(), 30);
        assert_eq!(parsed.record_source.apis.len(), 1);
        assert_eq!(
            parsed.record_source.source_command,
            ["/app/source", "--port", "7171"].map(OsString::from)
        );
    }

    #[test]
    fn requires_a_source_command_and_positive_timeouts() {
        assert!(TestCli::try_parse_from(["test"]).is_err());
        assert!(
            TestCli::try_parse_from(["test", "--duration-seconds", "0", "--", "/bin/true"])
                .is_err()
        );
        assert!(
            TestCli::try_parse_from(["test", "--startup-timeout-seconds", "0", "--", "/bin/true"])
                .is_err()
        );
    }
}
