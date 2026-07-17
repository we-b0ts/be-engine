use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use traffic_recorder_proxy::{
    AppConfig, AppState, CaseGroupOptions, CasePathPatternAuthority, CasePathPatternFeedback,
    CasePathPatternReport, ReplayAggregateOptions, ReplayConfig, ReplayControlConfig,
    VerifiedApiExcludeEnsureReport, VerifiedApiExcludeFeedback, VerifiedApiExcludeReport,
    aggregate_replay_reports_with_options, ensure_case_group, ensure_verified_api_exclude,
    plan_case_path_pattern_feedback, plan_verified_api_exclude, run_replay, run_replay_control,
    validate_replay_policy,
};
use uuid::Uuid;

mod e2e_run;

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
    RecorderConfig(RecorderConfigArgs),
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
    #[arg(long)]
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
    VerifiedExcludes(VerifiedExcludesArgs),
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
struct VerifiedExcludesArgs {
    #[command(subcommand)]
    command: VerifiedExcludesCommand,
}

#[derive(Debug, Subcommand)]
enum VerifiedExcludesCommand {
    Plan(VerifiedExcludeArgs),
    Apply(VerifiedExcludeArgs),
    Ensure(VerifiedExcludeArgs),
}

#[derive(Debug, Args)]
struct VerifiedExcludeArgs {
    #[arg(long)]
    rule: String,
    #[arg(long)]
    method: String,
    #[arg(long)]
    pattern: String,
    #[arg(long)]
    aggregate_report: PathBuf,
    #[arg(long)]
    assertion_report: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
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
        Some(Command::CaseGroup(args)) => run_case_group(args),
        Some(Command::E2eRun(args)) => e2e_run::run(args).await,
        Some(Command::Replay(args)) => run_replay_command(args).await,
        Some(Command::ReplayControl(args)) => run_replay_control_command(args).await,
        Some(Command::ReplayAggregate(args)) => run_replay_aggregate_command(args),
        Some(Command::ReplayPolicy(args)) => run_replay_policy_command(args),
        Some(Command::RecorderConfig(args)) => run_recorder_config(cli.config, args),
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
        RecorderConfigCommand::VerifiedExcludes(args) => match args.command {
            VerifiedExcludesCommand::Plan(args) => {
                let format = args.format;
                let plan = plan_verified_api_exclude(verified_exclude_feedback(config, args))?;
                print_verified_exclude_report(plan.report(), format)
            }
            VerifiedExcludesCommand::Apply(args) => {
                let format = args.format;
                let plan = plan_verified_api_exclude(verified_exclude_feedback(config, args))?;
                let report = plan.apply()?;
                print_verified_exclude_report(&report, format)
            }
            VerifiedExcludesCommand::Ensure(args) => {
                let format = args.format;
                let report = ensure_verified_api_exclude(verified_exclude_feedback(config, args))?;
                print_verified_exclude_ensure_report(&report, format)
            }
        },
    }
}

fn verified_exclude_feedback(
    config_path: PathBuf,
    args: VerifiedExcludeArgs,
) -> VerifiedApiExcludeFeedback {
    VerifiedApiExcludeFeedback {
        config_path,
        rule_name: args.rule,
        method: args.method,
        path_pattern: args.pattern,
        aggregate_report: args.aggregate_report,
        assertion_report: args.assertion_report,
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

fn print_verified_exclude_report(
    report: &VerifiedApiExcludeReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout(), report)?;
            println!();
        }
        OutputFormat::Human => {
            println!("config: {}", report.config.display());
            println!("api: {} {}", report.method, report.path_pattern);
            println!("rule: {}", report.rule);
            println!("threshold: {}", report.threshold);
            println!(
                "consecutive_successes: {}",
                report.consecutive_success_case_ids.len()
            );
            println!("eligible: {}", report.eligible);
            println!("changed: {}", report.changed);
            println!("applied: {}", report.applied);
            if !report.blockers.is_empty() {
                println!("blockers: {}", report.blockers.join(", "));
            }
            if !report.diff.is_empty() {
                print!("{}", report.diff);
            }
        }
    }
    Ok(())
}

fn print_verified_exclude_ensure_report(
    report: &VerifiedApiExcludeEnsureReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout(), report)?;
            println!();
        }
        OutputFormat::Human => {
            println!("status: {}", report.status);
            println!("config: {}", report.plan.config.display());
            println!("api: {} {}", report.plan.method, report.plan.path_pattern);
            println!("rule: {}", report.plan.rule);
            println!("threshold: {}", report.plan.threshold);
            println!(
                "consecutive_successes: {}",
                report.plan.consecutive_success_case_ids.len()
            );
            println!("initial_changed: {}", report.plan.changed);
            println!("apply_performed: {}", report.apply.is_some());
            if let Some(verification) = &report.verification {
                println!("verification_changed: {}", verification.changed);
            }
            if !report.plan.diff.is_empty() {
                print!("{}", report.plan.diff);
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
