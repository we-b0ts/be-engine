use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use traffic_recorder_proxy::{
    AppConfig, AppState, CaseGroupOptions, ReplayAggregateOptions, ReplayAllowedUnusedHttpConfig,
    ReplayConfig, ReplayControlConfig, ResponseRuleFeedback, ResponseRuleKind,
    aggregate_replay_reports_with_options, ensure_case_group, plan_response_rule, run_replay,
    run_replay_control, validate_replay_policy,
};
use uuid::Uuid;

mod e2e_run;
mod recorder_config;

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(
        short,
        long,
        global = true,
        default_value = "config/recorder.example.toml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    CaseGroup(CaseGroupArgs),
    E2eRun(e2e_run::E2eRunArgs),
    Replay(ReplayArgs),
    ReplayControl(ReplayControlArgs),
    ReplayAggregate(ReplayAggregateArgs),
    ReplayPolicy(ReplayPolicyArgs),
    RecorderConfig(recorder_config::RecorderConfigArgs),
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
    #[arg(long, default_value = "127.0.0.153:15353")]
    dns_listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:15001")]
    tcp_listen: SocketAddr,
    #[arg(long, default_value = "198.18.0.0/15")]
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

#[derive(Debug, Args)]
struct ReplayPolicyArgs {
    #[command(subcommand)]
    command: ReplayPolicyCommand,
}

#[derive(Debug, Subcommand)]
enum ReplayPolicyCommand {
    Validate {
        #[arg(long)]
        policy: PathBuf,
    },
    ResponseRule {
        #[command(subcommand)]
        command: ResponseRuleCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ResponseRuleCommand {
    Plan(ResponseRuleArgs),
    Apply(ResponseRuleArgs),
}

#[derive(Debug, Args)]
struct ResponseRuleArgs {
    #[arg(long)]
    policy: PathBuf,
    #[arg(long, value_enum)]
    kind: ResponseRuleKindArg,
    #[arg(long)]
    api: String,
    #[arg(long = "json-pointer", required = true)]
    json_pointers: Vec<String>,
    #[arg(long)]
    assertion_report: PathBuf,
    #[arg(long)]
    aggregate_report: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ResponseRuleKindArg {
    Dynamic,
    Unordered,
}

impl From<ResponseRuleKindArg> for ResponseRuleKind {
    fn from(value: ResponseRuleKindArg) -> Self {
        match value {
            ResponseRuleKindArg::Dynamic => Self::Dynamic,
            ResponseRuleKindArg::Unordered => Self::Unordered,
        }
    }
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

pub(crate) async fn run() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::CaseGroup(args)) => run_case_group(args),
        Some(Command::E2eRun(args)) => e2e_run::run(args).await,
        Some(Command::Replay(args)) => run_replay_command(args).await,
        Some(Command::ReplayControl(args)) => run_replay_control_command(args).await,
        Some(Command::ReplayAggregate(args)) => run_replay_aggregate_command(args),
        Some(Command::ReplayPolicy(args)) => run_replay_policy_command(args),
        Some(Command::RecorderConfig(args)) => recorder_config::run(cli.config, args),
        None => run_recorder(cli.config).await,
    }
}

fn run_replay_policy_command(args: ReplayPolicyArgs) -> Result<()> {
    match args.command {
        ReplayPolicyCommand::Validate { policy } => {
            let report = validate_replay_policy(&policy)?;
            serde_json::to_writer_pretty(io::stdout(), &report)?;
            println!();
            Ok(())
        }
        ReplayPolicyCommand::ResponseRule { command } => {
            let (args, apply) = match command {
                ResponseRuleCommand::Plan(args) => (args, false),
                ResponseRuleCommand::Apply(args) => (args, true),
            };
            let plan = plan_response_rule(ResponseRuleFeedback {
                policy_path: args.policy,
                kind: args.kind.into(),
                api: args.api,
                json_pointers: args.json_pointers,
                assertion_report: args.assertion_report,
                aggregate_report: args.aggregate_report,
            })?;
            if apply {
                serde_json::to_writer_pretty(io::stdout(), &plan.apply()?)?;
            } else {
                serde_json::to_writer_pretty(io::stdout(), plan.report())?;
            }
            println!();
            Ok(())
        }
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
    })
}

fn default_replay_session_path() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".replay")
        .join("session.json")
}
