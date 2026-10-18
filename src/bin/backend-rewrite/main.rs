mod review;
use std::io::Write;
use std::path::PathBuf;
mod rule;
mod rule_args;
use rule_args::RulePlanArgs;
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use traffic_e2e::{
    RewriteCaseDependenciesOptions, RewriteCasePatternApplyOptions, RewriteContext,
    RewriteNextOptions, RewriteRevalidationRequestOptions, RewriteRouteCause, RewriteRouteOptions,
    RewriteTargetQualityOptions, RewriteWorkerConfirmOptions, RewriteWorkerReportOptions,
    RewriteWorkerTransferOptions, apply_rewrite_case_patterns, confirm_rewrite_worker,
    inventory_rewrite, query_rewrite_case_dependencies, recover_rewrite, report_rewrite_worker,
    request_rewrite_revalidation, resume_rewrite_replay_planning, retry_rewrite_operation,
    route_rewrite, start_rewrite_next, start_rewrite_target_quality, status_rewrite,
    transfer_rewrite_worker, verify_rewrite_repair,
};

mod config_protocol;
mod evidence;
mod expert;
mod implementer;
mod project_init;
mod purpose;
mod recorder_capture;
mod regression;
mod repository_analysis;
mod startup;

#[derive(Debug, Parser)]
#[command(
    name = "backend-rewrite",
    author,
    version = traffic_e2e::BINARY_VERSION,
    about = "Coordinate backend rewrites through bounded traffic evidence",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Default coordinator log filter when RUST_LOG is not set.
    #[arg(
        long,
        global = true,
        env = "TRAFFIC_E2E_LOG_LEVEL",
        default_value = "info",
        value_name = "FILTER"
    )]
    log_level: String,
    /// Pretty-print JSON for human inspection; compact JSON is the default.
    #[arg(long, global = true)]
    pretty: bool,
    /// Target repository root.
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    #[command(subcommand)]
    command: RewriteCommand,
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();
    let log_filter = match log_filter(&cli.log_level) {
        Ok(filter) => filter,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_writer(std::io::stderr)
        .init();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&error);
            ExitCode::FAILURE
        }
    }
}

fn log_filter(default_filter: &str) -> Result<EnvFilter> {
    if std::env::var_os("RUST_LOG").is_some() {
        Ok(EnvFilter::try_from_default_env()?)
    } else {
        Ok(EnvFilter::try_new(default_filter)?)
    }
}

fn report_error(error: &anyhow::Error) {
    eprintln!("Error: {error:?}");
}

#[derive(Debug, Subcommand)]
enum RewriteCommand {
    /// Initialize one target repository for a backend rewrite.
    Init(project_init::ProjectInitArgs),
    /// Inspect or update target startup environment and mount inputs.
    Startup(startup::StartupArgs),
    /// Apply an idempotent, typed update to initialized repository configuration.
    Config(config_protocol::ConfigArgs),
    /// Advance deterministic stages and return the only allowed next action.
    Next(NextArgs),
    /// Show bounded coordinator state without advancing it.
    Status(StatusArgs),
    /// Wait at most 30 seconds, then reconcile task-runtime events and refresh status.
    Wait {
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=30))]
        seconds: u64,
    },
    /// Show the full stable API inventory without advancing it.
    Inventory,
    /// Start a user-authorized regression round from the configured pr_base branch.
    #[command(hide = true)]
    Regression(regression::RegressionArgs),
    /// Confirm the user purpose when entering from pr_base.
    Purpose(purpose::PurposeArgs),
    /// Inspect bounded dependency evidence from one published case.
    Case(CaseArgs),
    /// Apply one coordinator-requested batch of API case path patterns.
    CasePattern(CasePatternArgs),
    /// Inspect or apply incremental source-backed API grouping before Replay.
    RepositoryAnalysis(repository_analysis::RepositoryAnalysisArgs),
    /// Dispatch fixed implementers and report explicit batch activity or deliveries.
    Implementer(implementer::ImplementerArgs),
    /// Inspect an issue overview or execute one returned bounded evidence query.
    Evidence(evidence::EvidenceArgs),
    /// Plan/apply/recover self-contained rules using current Source-backed evidence.
    Rule(RuleArgs),
    /// Plan or apply one source-proven Breeze resource capture rule.
    RecorderCapture(recorder_capture::RecorderCaptureArgs),
    /// Submit a source-backed non-target-code attribution for controlled routing.
    Route(RouteArgs),
    /// Verify one coordinator-issued system repair acceptance.
    Repair(RepairArgs),
    /// Confirm the runtime identity of one dispatched or resumed API subagent.
    Worker(WorkerArgs),
    /// Confirm one API diagnostic expert or acknowledge forwarding its report.
    Expert(expert::ExpertArgs),
    /// Check complete delivery quality and admit published integration reports.
    Review(review::ReviewArgs),
    /// Retry a failed detached coordinator operation after its cause is resolved.
    Operation(OperationArgs),
    /// Schedule selected stale APIs before the deferred final verification batch.
    Verification(VerificationArgs),
    /// Validate existing quality receipts for legacy coordinator operations.
    TargetQuality(TargetQualityArgs),
    /// Remove only a stale coordinator lock after its process has exited.
    Recover,
}

#[derive(Debug, Args)]
struct NextArgs {
    /// Execute only this API scope; omit to let the engine select work and honor local auto_next.
    #[arg(long, value_name = "PATH_OR_PATTERN")]
    api: Option<traffic_e2e::RewriteApiSelector>,
    /// Source registration route for the active dynamic API when requested by the coordinator.
    #[arg(long)]
    source_route: Option<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// API work item whose action should be reconstructed while other AI work proceeds.
    #[arg(long, value_name = "PATH_OR_PATTERN")]
    api: Option<traffic_e2e::RewriteApiSelector>,
}

#[derive(Debug, Args)]
struct CaseArgs {
    #[command(subcommand)]
    command: CaseCommand,
}

#[derive(Debug, Args)]
struct CasePatternArgs {
    #[command(subcommand)]
    command: CasePatternCommand,
}

#[derive(Debug, Subcommand)]
enum CasePatternCommand {
    /// Apply every identified pattern; an empty JSON array confirms all candidates are static.
    Apply(CasePatternApplyArgs),
}

#[derive(Debug, Args)]
struct CasePatternApplyArgs {
    /// Opaque batch id returned by case_pattern_identification_required.
    batch_id: String,
    /// Complete JSON array of identified path patterns.
    #[arg(
        long,
        env = "BACKEND_REWRITE_CASE_PATH_PATTERNS_JSON",
        hide_env_values = true
    )]
    patterns_json: String,
}

#[derive(Debug, Subcommand)]
enum CaseCommand {
    /// Summarize dependency targets, or inspect one target returned by the summary.
    Dependencies(CaseDependenciesArgs),
}

#[derive(Debug, Args)]
struct CaseDependenciesArgs {
    /// Coordinator-returned immutable case directory.
    case_dir: PathBuf,
    /// Opaque target id returned by the dependency summary.
    target_id: Option<String>,
}

#[derive(Debug, Args)]
struct RuleArgs {
    #[command(subcommand)]
    command: RuleCommand,
}

#[derive(Debug, Subcommand)]
enum RuleCommand {
    /// Validate current evidence and preview one request or response rule.
    Plan(Box<RulePlanArgs>),
    /// Atomically apply the persisted, evidence-validated pending plan.
    Apply(RuleApplyArgs),
    /// Retire a plan whose evidence is missing and request fresh Replay without applying it.
    Recover(RuleApplyArgs),
}

#[derive(Debug, Args)]
struct RuleApplyArgs {
    #[arg(required_unless_present = "plan", conflicts_with = "plan")]
    plan_id: Option<String>,
    #[arg(long, value_name = "PLAN_ID")]
    plan: Option<String>,
}

impl RuleApplyArgs {
    fn identifier(&self) -> &str {
        self.plan
            .as_deref()
            .or(self.plan_id.as_deref())
            .expect("clap requires a plan ID")
    }
}

#[derive(Debug, Args)]
struct RouteArgs {
    /// Source-backed reason for leaving target implementation work.
    #[arg(long, value_enum)]
    cause: RouteCauseArg,
    /// Coordinator-issued evidence id for the active issue.
    #[arg(long)]
    evidence_id: String,
    /// One-line source file/symbol proof for the reported cause.
    #[arg(long)]
    source_ref: String,
    /// Missing-resource hostname[:port], or literal IP:port for unrecorded-ip.
    #[arg(
        long,
        value_name = "ENDPOINT",
        required_if_eq_any([("cause", "missing-recorded-resource"), ("cause", "unrecorded-ip")]),
        conflicts_with = "required_change"
    )]
    endpoint: Option<String>,
    /// Case containing the caller-reported IP dependency gap.
    #[arg(long, required_if_eq("cause", "unrecorded-ip"))]
    case_id: Option<String>,
    /// Address origin established by source inspection; unknown requests investigation guidance.
    #[arg(long, default_value = "unknown", value_parser = ["unknown", "http-response", "static", "other"])]
    ip_origin: String,
    /// Exact required non-target change; required for causes that enter system repair.
    #[arg(
        long,
        required_if_eq_any([
            ("cause", "recorder-capability-gap"),
            ("cause", "replay-capability-gap"),
            ("cause", "external-data-blocker")
        ]),
        conflicts_with = "endpoint"
    )]
    required_change: Option<String>,
}

#[derive(Debug, Args)]
struct RepairArgs {
    #[command(subcommand)]
    command: RepairCommand,
}

#[derive(Debug, Subcommand)]
enum RepairCommand {
    /// Verify that the accepted system or source revision changed.
    Verify(RepairVerifyArgs),
    /// Migrate a legacy external-data response blocker to bootstrap replay planning.
    ResumeReplayPlanning(RepairVerifyArgs),
}

#[derive(Debug, Args)]
struct RepairVerifyArgs {
    repair_id: String,
}

#[derive(Debug, Args)]
struct WorkerArgs {
    #[command(subcommand)]
    command: WorkerCommand,
}

#[derive(Debug, Subcommand)]
enum WorkerCommand {
    /// Bind an actual subagent handle to the current implementation dispatch.
    Confirm(WorkerConfirmArgs),
    /// Report a runtime observation, worker handoff, or completed integration.
    Report(WorkerReportArgs),
    /// Transfer worker ownership with user approval or an actual runtime query confirming absence.
    Transfer(WorkerTransferArgs),
}

#[derive(Debug, Args)]
struct WorkerConfirmArgs {
    /// Assigned worker worktree; register again when resuming a dispatch.
    #[arg(long, env = "BACKEND_REWRITE_WORKER_WORKTREE")]
    worktree: Option<PathBuf>,
    /// Exact API assigned to this worker.
    #[arg(
        long,
        value_parser = parse_api_scope
    )]
    api: String,
    /// Runtime-returned subagent handle. Supply through the named environment variable.
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
    agent_handle: String,
    /// Optional human-readable subagent name for diagnostics.
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_NAME", hide_env_values = true)]
    agent_name: Option<String>,
}

fn parse_api_scope(value: &str) -> Result<String> {
    Ok(value
        .parse::<traffic_e2e::RewriteApiSelector>()?
        .to_string())
}

#[derive(Debug, Args)]
struct WorkerReportArgs {
    /// Original review report for handoff_ready, integrated or rework_required.
    #[arg(long, env = "BACKEND_REWRITE_WORKER_REVIEW_REPORT")]
    review_report: Option<PathBuf>,
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
    agent_handle: String,
    #[arg(long, env = "BACKEND_REWRITE_WORKER_ACTIVITY", hide_env_values = true,
        value_parser = ["running", "queued", "idle", "handoff_ready", "integrated", "rework_required"])]
    activity: String,
    /// Stable handoff identity; required for handoff_ready, integrated, and rework_required.
    #[arg(
        long,
        env = "BACKEND_REWRITE_WORKER_HANDOFF_ID",
        hide_env_values = true
    )]
    handoff_id: Option<String>,
}

#[derive(Debug, Args)]
struct OperationArgs {
    #[command(subcommand)]
    command: OperationCommand,
}

#[derive(Debug, Subcommand)]
enum OperationCommand {
    Retry { operation_id: String },
}

#[derive(Debug, Args)]
struct WorkerTransferArgs {
    /// Runtime handle of the existing owner being replaced.
    #[arg(long)]
    previous_agent_handle: String,
    /// Runtime-returned replacement subagent handle.
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
    agent_handle: String,
    /// Optional human-readable replacement subagent name.
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_NAME", hide_env_values = true)]
    agent_name: Option<String>,
    /// Single-line reason the stored worker cannot retain ownership.
    #[arg(long)]
    reason: String,
    /// Attest that the user explicitly approved replacing the worker owner.
    #[arg(
        long,
        required_unless_present = "runtime_query_command",
        conflicts_with_all = ["runtime_query_command", "runtime_query_at"]
    )]
    approve_ownership_transfer: bool,
    /// API/command actually queried to confirm the previous worker no longer exists (e.g. ListAgents).
    #[arg(long, requires = "runtime_query_at")]
    runtime_query_command: Option<String>,
    /// Actual query time (RFC 3339 with timezone); attests runtime_api_confirmed_missing without user approval.
    #[arg(long, requires = "runtime_query_command")]
    runtime_query_at: Option<String>,
}

#[derive(Debug, Args)]
struct VerificationArgs {
    #[command(subcommand)]
    command: VerificationCommand,
}

#[derive(Debug, Subcommand)]
enum VerificationCommand {
    /// Promote stale completed APIs for early Replay after a high-impact change.
    Request(VerificationRequestArgs),
}

#[derive(Debug, Args)]
struct VerificationRequestArgs {
    /// API whose old successful evidence should be checked early; repeat for multiple APIs.
    #[arg(long = "api", required = true, value_name = "PATH_OR_PATTERN")]
    apis: Vec<traffic_e2e::RewriteApiSelector>,
    /// Bounded coordinator rationale identifying the shared or global change.
    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct TargetQualityArgs {
    #[command(subcommand)]
    command: TargetQualityCommand,
}

#[derive(Debug, Subcommand)]
enum TargetQualityCommand {
    /// Validate the published quality receipt; checks run through review check before delivery.
    Run(TargetQualityRunArgs),
}

#[derive(Debug, Args)]
struct TargetQualityRunArgs {
    gate_id: String,
    /// API acceptance whose integrated target revision issued this gate.
    #[arg(long, value_name = "PATH_OR_PATTERN")]
    api: traffic_e2e::RewriteApiSelector,
    /// Confirm one production-source-proven domain occurrence; repeat per target location.
    #[arg(
        long,
        value_name = "TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@REVISION:SOURCE_FILE:LINE:COLUMN"
    )]
    hardcode_ai_verified: Vec<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RouteCauseArg {
    UnrecordedIp,
    MissingRecordedResource,
    RecorderCapabilityGap,
    ReplayCapabilityGap,
    ExternalDataBlocker,
}

async fn run(cli: Cli) -> Result<()> {
    let target_root = cli.target_root;
    let pretty = cli.pretty;
    match cli.command {
        RewriteCommand::Purpose(args) => purpose::run(target_root, args, pretty),
        RewriteCommand::Regression(args) => regression::run(target_root, args, pretty),
        RewriteCommand::Init(args) => project_init::run(target_root, args, pretty).await,
        RewriteCommand::Startup(args) => startup::run(target_root, args, pretty),
        RewriteCommand::Config(args) => config_protocol::run(target_root, args, pretty),
        RewriteCommand::Next(args) => print_json(
            &start_rewrite_next(RewriteNextOptions {
                target_root,
                api: args.api,
                source_route: args.source_route,
            })?,
            pretty,
        ),
        RewriteCommand::Operation(args) => match args.command {
            OperationCommand::Retry { operation_id } => print_json(
                &retry_rewrite_operation(RewriteContext { target_root }, &operation_id)?,
                pretty,
            ),
        },
        RewriteCommand::Status(args) => {
            let context = RewriteContext { target_root };
            let report = if let Some(api) = args.api.as_ref() {
                traffic_e2e::status_rewrite_for_selector(context, api)?
            } else {
                status_rewrite(context)?
            };
            print_json(&report, pretty)
        }
        RewriteCommand::Wait { seconds } => print_json(
            &traffic_e2e::wait_rewrite(traffic_e2e::RewriteWaitOptions {
                target_root,
                seconds,
            })
            .await?,
            pretty,
        ),
        RewriteCommand::Inventory => {
            print_json(&inventory_rewrite(RewriteContext { target_root })?, pretty)
        }
        RewriteCommand::Case(args) => match args.command {
            CaseCommand::Dependencies(args) => print_json(
                &query_rewrite_case_dependencies(RewriteCaseDependenciesOptions {
                    target_root,
                    case_dir: args.case_dir,
                    target_id: args.target_id,
                })?,
                pretty,
            ),
        },
        RewriteCommand::CasePattern(args) => match args.command {
            CasePatternCommand::Apply(args) => {
                let patterns = serde_json::from_str::<Vec<String>>(&args.patterns_json)
                    .map_err(|error| anyhow::anyhow!("invalid case path patterns JSON: {error}"))?;
                print_json(
                    &apply_rewrite_case_patterns(RewriteCasePatternApplyOptions {
                        target_root,
                        batch_id: args.batch_id,
                        patterns,
                    })?,
                    pretty,
                )
            }
        },
        RewriteCommand::RepositoryAnalysis(args) => {
            repository_analysis::run(target_root, args, pretty)
        }
        RewriteCommand::Implementer(args) => implementer::run(target_root, args, pretty),
        RewriteCommand::Evidence(args) => {
            print_json(&args.query(RewriteContext { target_root })?, pretty)
        }
        RewriteCommand::Rule(args) => rule::run(target_root, args, pretty),
        RewriteCommand::RecorderCapture(args) => recorder_capture::run(target_root, args, pretty),
        RewriteCommand::Route(args) => {
            let cause = if matches!(args.cause, RouteCauseArg::UnrecordedIp) {
                RewriteRouteCause::UnrecordedIp {
                    endpoint: args.endpoint.context("unrecorded IP endpoint missing")?,
                    case_id: args.case_id.context("unrecorded IP case missing")?,
                    origin: args.ip_origin,
                }
            } else {
                ensure!(
                    args.case_id.is_none() && args.ip_origin == "unknown",
                    "case-id and ip-origin are only valid with --cause unrecorded-ip"
                );
                args.cause
                    .into_rewrite_cause(args.endpoint, args.required_change)?
            };
            print_json(
                &route_rewrite(RewriteRouteOptions {
                    target_root,
                    cause,
                    evidence_id: args.evidence_id,
                    source_ref: args.source_ref,
                })?,
                pretty,
            )
        }
        RewriteCommand::Repair(args) => match args.command {
            RepairCommand::Verify(args) => print_json(
                &verify_rewrite_repair(RewriteContext { target_root }, &args.repair_id)?,
                pretty,
            ),
            RepairCommand::ResumeReplayPlanning(args) => print_json(
                &resume_rewrite_replay_planning(RewriteContext { target_root }, &args.repair_id)?,
                pretty,
            ),
        },
        RewriteCommand::Review(args) => review::run(target_root, args, pretty),
        RewriteCommand::Expert(args) => expert::run(target_root, args, pretty),
        RewriteCommand::Worker(args) => match args.command {
            WorkerCommand::Confirm(args) => print_json(
                &confirm_rewrite_worker(RewriteWorkerConfirmOptions {
                    target_root,
                    work_scope: traffic_e2e::RewriteWorkScope::Api { api: args.api },
                    agent_handle: args.agent_handle,
                    agent_name: args.agent_name,
                    worktree: args.worktree,
                })?,
                pretty,
            ),
            WorkerCommand::Report(args) => print_json(
                &report_rewrite_worker(RewriteWorkerReportOptions {
                    target_root,
                    agent_handle: args.agent_handle,
                    activity: args.activity.parse()?,
                    handoff_id: args.handoff_id,
                    review_report: args.review_report,
                })?,
                pretty,
            ),
            WorkerCommand::Transfer(args) => print_json(
                &transfer_rewrite_worker(RewriteWorkerTransferOptions {
                    target_root,
                    previous_agent_handle: args.previous_agent_handle,
                    agent_handle: args.agent_handle,
                    agent_name: args.agent_name,
                    reason: args.reason,
                    caller_approved: args.approve_ownership_transfer,
                    runtime_query: args.runtime_query_command.zip(args.runtime_query_at).map(
                        |(api_or_command, queried_at)| traffic_e2e::RewriteWorkerMissingQuery {
                            api_or_command,
                            queried_at,
                        },
                    ),
                })?,
                pretty,
            ),
        },
        RewriteCommand::Verification(args) => match args.command {
            VerificationCommand::Request(args) => print_json(
                &request_rewrite_revalidation(RewriteRevalidationRequestOptions {
                    target_root,
                    apis: args.apis,
                    reason: args.reason,
                })?,
                pretty,
            ),
        },
        RewriteCommand::TargetQuality(args) => match args.command {
            TargetQualityCommand::Run(args) => print_json(
                &start_rewrite_target_quality(RewriteTargetQualityOptions {
                    target_root,
                    gate_id: args.gate_id,
                    api: args.api,
                    hardcode_ai_verified: args.hardcode_ai_verified,
                })?,
                pretty,
            ),
        },
        RewriteCommand::Recover => print_json(
            &recover_rewrite(RewriteContext { target_root }).await?,
            pretty,
        ),
    }
}

impl RouteCauseArg {
    fn into_rewrite_cause(
        self,
        endpoint: Option<String>,
        required_change: Option<String>,
    ) -> Result<RewriteRouteCause> {
        match (self, endpoint, required_change) {
            (Self::MissingRecordedResource, Some(endpoint), None) => {
                Ok(RewriteRouteCause::MissingRecordedResource { endpoint })
            }
            (Self::RecorderCapabilityGap, None, Some(required_change)) => {
                Ok(RewriteRouteCause::RecorderCapabilityGap { required_change })
            }
            (Self::ReplayCapabilityGap, None, Some(required_change)) => {
                Ok(RewriteRouteCause::ReplayCapabilityGap { required_change })
            }
            (Self::ExternalDataBlocker, None, Some(required_change)) => {
                Ok(RewriteRouteCause::ExternalDataBlocker { required_change })
            }
            _ => bail!("route cause arguments are incomplete or mutually exclusive"),
        }
    }
}

fn write_json(mut writer: impl Write, value: &impl serde::Serialize, pretty: bool) -> Result<()> {
    if pretty {
        serde_json::to_writer_pretty(&mut writer, value)?;
    } else {
        serde_json::to_writer(&mut writer, value)?;
    }
    writeln!(writer)?;
    Ok(())
}

fn print_json(value: &impl serde::Serialize, pretty: bool) -> Result<()> {
    write_json(std::io::stdout(), value, pretty)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod worker_transfer_tests;
