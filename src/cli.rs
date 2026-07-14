use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use traffic_recorder_proxy::{
    AppConfig, AppState, CasePathPatternAuthority, CasePathPatternFeedback, CasePathPatternReport,
    ReplayAggregateOptions, ReplayConfig, ReplayControlConfig,
    aggregate_replay_reports_with_options, plan_case_path_pattern_feedback, run_replay,
    run_replay_control,
};
use uuid::Uuid;

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
    Replay(ReplayArgs),
    ReplayControl(ReplayControlArgs),
    ReplayAggregate(ReplayAggregateArgs),
    RecorderConfig(RecorderConfigArgs),
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
    #[arg(long = "http-ignore-query-param")]
    http_ignore_query_params: Vec<String>,
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

#[derive(Debug, Args)]
struct RecorderConfigArgs {
    #[command(subcommand)]
    command: RecorderConfigCommand,
}

#[derive(Debug, Subcommand)]
enum RecorderConfigCommand {
    CasePathPatterns(CasePathPatternsArgs),
}

#[derive(Debug, Args)]
struct CasePathPatternsArgs {
    #[command(subcommand)]
    command: CasePathPatternsCommand,
}

#[derive(Debug, Subcommand)]
enum CasePathPatternsCommand {
    Plan(PatternFeedbackArgs),
    Apply(ApplyPatternFeedbackArgs),
}

#[derive(Debug, Args)]
struct PatternFeedbackArgs {
    #[arg(long)]
    rule: String,
    #[arg(long)]
    source_revision: String,
    #[arg(long)]
    case_source: String,
    #[arg(long, value_enum, default_value_t = AuthorityArg::Focused)]
    authority: AuthorityArg,
    #[arg(long = "pattern")]
    patterns: Vec<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct ApplyPatternFeedbackArgs {
    #[command(flatten)]
    feedback: PatternFeedbackArgs,
    #[arg(long)]
    allow_delete: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AuthorityArg {
    Focused,
    Authoritative,
}

impl From<AuthorityArg> for CasePathPatternAuthority {
    fn from(authority: AuthorityArg) -> Self {
        match authority {
            AuthorityArg::Focused => Self::Focused,
            AuthorityArg::Authoritative => Self::Authoritative,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

pub(crate) async fn run() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Replay(args)) => run_replay_command(args).await,
        Some(Command::ReplayControl(args)) => run_replay_control_command(args).await,
        Some(Command::ReplayAggregate(args)) => run_replay_aggregate_command(args),
        Some(Command::RecorderConfig(args)) => run_recorder_config(cli.config, args),
        None => run_recorder(cli.config).await,
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
        http_ignore_query_params: args.http_ignore_query_params,
    })
    .await
}

async fn run_replay_control_command(args: ReplayControlArgs) -> Result<()> {
    let response = run_replay_control(replay_control_config(args)?).await?;
    serde_json::to_writer_pretty(io::stdout(), &response)?;
    println!();
    Ok(())
}

fn run_recorder_config(config: PathBuf, args: RecorderConfigArgs) -> Result<()> {
    match args.command {
        RecorderConfigCommand::CasePathPatterns(args) => match args.command {
            CasePathPatternsCommand::Plan(args) => {
                let format = args.format;
                let plan = plan_case_path_pattern_feedback(feedback(config, args))?;
                print_pattern_report(plan.report(), format)
            }
            CasePathPatternsCommand::Apply(args) => {
                let format = args.feedback.format;
                let plan = plan_case_path_pattern_feedback(feedback(config, args.feedback))?;
                let report = plan.apply(args.allow_delete)?;
                print_pattern_report(&report, format)
            }
        },
    }
}

fn feedback(config_path: PathBuf, args: PatternFeedbackArgs) -> CasePathPatternFeedback {
    CasePathPatternFeedback {
        config_path,
        rule_name: args.rule,
        source_revision: args.source_revision,
        case_source: args.case_source,
        authority: args.authority.into(),
        patterns: args.patterns,
    }
}

fn print_pattern_report(report: &CasePathPatternReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout(), report)?;
            println!();
        }
        OutputFormat::Human => {
            println!("config: {}", report.config.display());
            println!("rule: {}", report.rule);
            println!("authority: {}", report.authority);
            println!("no_candidates: {}", report.no_candidates);
            println!("changed: {}", report.changed);
            println!("applied: {}", report.applied);
            println!("added: {}", report.added.len());
            println!("removed: {}", report.removed.len());
            if !report.diff.is_empty() {
                print!("{}", report.diff);
            }
        }
    }
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
