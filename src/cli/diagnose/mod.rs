use std::net::SocketAddr;
use std::path::PathBuf;
use std::{env, io};

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    AppConfig, AppState, CaseGroupOptions, ReplayAggregateOptions, ReplayAllowedUnusedHttpConfig,
    ReplayConfig, ReplayControlConfig, aggregate_replay_reports_with_options, ensure_case_group,
    run_replay, run_replay_control,
};
use uuid::Uuid;

#[derive(Debug, Args)]
pub(super) struct DiagnoseArgs {
    #[command(subcommand)]
    command: DiagnoseCommand,
}

#[derive(Debug, Subcommand)]
enum DiagnoseCommand {
    /// Inspect or manage host interception rules.
    Interception(super::interception::InterceptionArgs),
    /// Run the low-level recorder service without local interception setup.
    Recorder(RecorderArgs),
    /// Run the low-level dependency replay service without interception setup.
    Replay(ReplayArgs),
    /// Control a running low-level replay session.
    ReplayControl(ReplayControlArgs),
    /// Aggregate exact replay reports for selected cases and sessions.
    ReplayAggregate(ReplayAggregateArgs),
    /// Persist and validate canonical case grouping evidence.
    CaseGroup(CaseGroupArgs),
}

#[derive(Debug, Args)]
struct RecorderArgs {
    #[arg(short, long, default_value = "config/project.example.yaml")]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct CaseGroupArgs {
    #[command(subcommand)]
    command: CaseGroupCommand,
}

#[derive(Debug, Subcommand)]
enum CaseGroupCommand {
    Ensure(CaseGroupEnsureArgs),
}

#[derive(Debug, Args)]
struct CaseGroupEnsureArgs {
    #[arg(long)]
    case_source: PathBuf,
    #[arg(long)]
    case_dir: PathBuf,
    #[arg(long)]
    method: String,
    #[arg(long)]
    source_route: String,
    #[arg(
        long,
        help = "Recorder path pattern: '*' matches one segment; trailing '**' matches one or more remaining segments"
    )]
    pattern: Option<String>,
    #[arg(long)]
    source_revision: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    recorder_config: Option<PathBuf>,
    #[arg(long)]
    rule: Option<String>,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long = "case-id")]
    case_ids: Vec<String>,
    #[arg(long, default_value = traffic_e2e::DEFAULT_DNS_MOCK_LISTEN)]
    dns_listen: SocketAddr,
    #[arg(long, default_value = traffic_e2e::DEFAULT_TCP_GATEWAY_LISTEN)]
    tcp_listen: SocketAddr,
    #[arg(long, default_value = traffic_e2e::DEFAULT_FAKE_CIDR)]
    fake_cidr: String,
    #[arg(long)]
    report: Option<PathBuf>,
    #[arg(long)]
    session: Option<PathBuf>,
    #[arg(long)]
    control_socket: Option<PathBuf>,
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    #[arg(long)]
    ca_key: Option<PathBuf>,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long = "http-ignore-query-param")]
    http_ignore_query_params: Vec<String>,
    #[arg(long, requires = "recording_rule")]
    recorder_config: Option<PathBuf>,
    #[arg(long, requires = "recorder_config")]
    recording_rule: Option<String>,
}

#[derive(Debug, Args)]
struct ReplayControlArgs {
    #[arg(long, env = "TRP_REPLAY_SESSION")]
    session: Option<PathBuf>,
    #[command(subcommand)]
    command: ReplayControlCommand,
}

#[derive(Debug, Args)]
struct ReplayAggregateArgs {
    #[arg(long)]
    case_source: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    fail_on_dirty: bool,
    #[arg(long)]
    fail_on_incomplete: bool,
    #[arg(long = "case-id")]
    case_ids: Vec<String>,
    #[arg(long = "session-id")]
    session_ids: Vec<Uuid>,
}

#[derive(Debug, Subcommand)]
enum ReplayControlCommand {
    WaitReady,
    Status,
    Cases,
    Begin {
        case_id: String,
    },
    End {
        case_id: String,
        #[arg(long)]
        fail_on_dirty: bool,
    },
    Report {
        #[arg(long)]
        fail_on_dirty: bool,
        #[arg(long)]
        fail_on_incomplete: bool,
    },
    Finalize {
        #[arg(long)]
        fail_on_dirty: bool,
        #[arg(long)]
        fail_on_incomplete: bool,
    },
    Stop,
}

pub(super) async fn run(args: DiagnoseArgs) -> Result<()> {
    match args.command {
        DiagnoseCommand::Interception(args) => super::interception::run(args),
        DiagnoseCommand::Recorder(args) => run_recorder(args.config).await,
        DiagnoseCommand::Replay(args) => run_replay_command(args).await,
        DiagnoseCommand::ReplayControl(args) => run_replay_control_command(args).await,
        DiagnoseCommand::ReplayAggregate(args) => run_replay_aggregate_command(args),
        DiagnoseCommand::CaseGroup(args) => run_case_group(args),
    }
}

fn run_case_group(args: CaseGroupArgs) -> Result<()> {
    match args.command {
        CaseGroupCommand::Ensure(args) => {
            let result = ensure_case_group(CaseGroupOptions {
                case_source: args.case_source,
                case_dir: args.case_dir,
                method: args.method,
                source_route: args.source_route,
                pattern: args.pattern,
                source_revision: args.source_revision,
                output: args.output,
                recorder_config: args.recorder_config,
                rule: args.rule,
            })?;
            serde_json::to_writer_pretty(io::stdout(), &result)?;
            println!();
            Ok(())
        }
    }
}

fn run_replay_aggregate_command(args: ReplayAggregateArgs) -> Result<()> {
    let options = ReplayAggregateOptions {
        case_ids: args.case_ids.into_iter().collect(),
        session_ids: args
            .session_ids
            .into_iter()
            .map(|session_id| session_id.to_string())
            .collect(),
    };
    let aggregate = aggregate_replay_reports_with_options(&args.case_source, &options)?;
    let mut payload = serde_json::to_vec_pretty(&aggregate)?;
    payload.push(b'\n');
    if let Some(output) = args.output {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&output, payload)?;
    } else {
        use std::io::Write;
        io::stdout().write_all(&payload)?;
    }
    if args.fail_on_incomplete && !aggregate.is_complete() {
        anyhow::bail!("aggregate replay report has unreported or unfinished cases");
    }
    if args.fail_on_dirty && aggregate.is_dirty() {
        anyhow::bail!("aggregate replay report contains dirty dependency evidence");
    }
    Ok(())
}

async fn run_replay_command(args: ReplayArgs) -> Result<()> {
    let process_owned_dependencies = args
        .recorder_config
        .as_deref()
        .map(|path| AppConfig::load(path).map(|config| config.process_owned_dependencies))
        .transpose()?
        .unwrap_or_default();
    let allowed_unused_http = load_allowed_unused_http(args.recorder_config, args.recording_rule)?;
    run_replay(ReplayConfig {
        case_dir: args.case,
        selected_case_ids: args.case_ids,
        dns_listen: args.dns_listen,
        tcp_listen: args.tcp_listen,
        fake_cidr: args.fake_cidr,
        report_path: args.report,
        session_path: args.session,
        control_socket_path: args.control_socket,
        ca_cert_path: args.ca_cert,
        ca_key_path: args.ca_key,
        policy_path: args.policy,
        http_ignore_query_params: args.http_ignore_query_params,
        process_owned_dependencies,
        allowed_unused_http,
    })
    .await
}

fn load_allowed_unused_http(
    recorder_config: Option<PathBuf>,
    recording_rule: Option<String>,
) -> Result<Option<ReplayAllowedUnusedHttpConfig>> {
    let (Some(config_path), Some(recording_rule)) = (recorder_config, recording_rule) else {
        return Ok(None);
    };
    let config_path = config_path.canonicalize()?;
    let config = AppConfig::load(&config_path)?;
    let matches = config
        .http_gateway
        .rules
        .iter()
        .filter(|rule| rule.name.as_deref() == Some(recording_rule.as_str()))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        matches.len() == 1,
        "expected exactly one [[http_gateway.rules]] entry named {:?}, found {}",
        recording_rule,
        matches.len()
    );
    Ok(Some(ReplayAllowedUnusedHttpConfig {
        config_path,
        recording_rule,
        hosts: matches[0]
            .allowed_unused_http_hosts
            .iter()
            .cloned()
            .collect(),
    }))
}

async fn run_replay_control_command(args: ReplayControlArgs) -> Result<()> {
    let response = run_replay_control(replay_control_config(args)?).await?;
    serde_json::to_writer_pretty(io::stdout(), &response)?;
    println!();
    Ok(())
}

async fn run_recorder(config_path: PathBuf) -> Result<()> {
    let config = AppConfig::load(&config_path)?;
    let state = AppState::new(config).await?;
    state.run().await
}

fn replay_control_config(args: ReplayControlArgs) -> Result<ReplayControlConfig> {
    let session_path = args.session.unwrap_or_else(default_replay_session_path);
    let (command, case_id, fail_on_dirty, fail_on_incomplete) = match args.command {
        ReplayControlCommand::WaitReady => ("wait_ready".to_string(), None, false, false),
        ReplayControlCommand::Status => ("status".to_string(), None, false, false),
        ReplayControlCommand::Cases => ("cases".to_string(), None, false, false),
        ReplayControlCommand::Begin { case_id } => {
            ("begin".to_string(), Some(case_id), false, false)
        }
        ReplayControlCommand::End {
            case_id,
            fail_on_dirty,
        } => ("end".to_string(), Some(case_id), fail_on_dirty, false),
        ReplayControlCommand::Report {
            fail_on_dirty,
            fail_on_incomplete,
        } => (
            "report".to_string(),
            None,
            fail_on_dirty,
            fail_on_incomplete,
        ),
        ReplayControlCommand::Finalize {
            fail_on_dirty,
            fail_on_incomplete,
        } => (
            "finalize".to_string(),
            None,
            fail_on_dirty,
            fail_on_incomplete,
        ),
        ReplayControlCommand::Stop => ("stop".to_string(), None, false, false),
    };
    Ok(ReplayControlConfig {
        session_path,
        command,
        case_id,
        fail_on_dirty,
        fail_on_incomplete,
        wait_timeout: None,
    })
}

fn default_replay_session_path() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".replay")
        .join("session.json")
}
