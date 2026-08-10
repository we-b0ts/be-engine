use std::io::Write;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use traffic_e2e::{
    DynamicResponseMechanism, RecordingApi, ResponseRuleKind, RewriteCaseDependenciesOptions,
    RewriteContext, RewriteNextOptions, RewriteRecordingKind, RewriteRecordingReason,
    RewriteRecordingRequestOptions, RewriteRevalidationRequestOptions, RewriteRouteOptions,
    RewriteRulePlanOptions, RewriteTargetQualityOptions, RewriteWorkerConfirmOptions,
    RewriteWorkerTransferOptions, apply_rewrite_rule, confirm_rewrite_worker, inventory_rewrite,
    next_rewrite, plan_rewrite_rule, query_rewrite_case_dependencies, query_rewrite_evidence,
    recover_rewrite, request_rewrite_recording, request_rewrite_revalidation,
    resume_rewrite_replay_planning, route_rewrite, run_rewrite_target_quality,
    start_rewrite_recording, status_rewrite, status_rewrite_for_api, transfer_rewrite_worker,
    verify_rewrite_repair,
};

mod dependency_rule;
mod project_init;
mod recorder_capture;
mod startup;

#[derive(Debug, Parser)]
#[command(
    name = "backend-rewrite",
    author,
    version,
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
    /// Inspect or replace the frozen source-compatible target startup inputs.
    Startup(startup::StartupArgs),
    /// Advance deterministic stages and return the only allowed next action.
    Next(NextArgs),
    /// Show bounded coordinator state without advancing it.
    Status(StatusArgs),
    /// Show the full stable API inventory without advancing it.
    Inventory,
    /// Inspect bounded dependency evidence from one published case.
    Case(CaseArgs),
    /// Execute one current, bounded evidence query.
    Evidence(EvidenceArgs),
    /// Plan or apply one evidence-backed response rule.
    Rule(RuleArgs),
    /// Plan or apply one source-proven background dependency rule.
    DependencyRule(dependency_rule::DependencyRuleArgs),
    /// Plan or apply one source-proven Breeze resource capture rule.
    RecorderCapture(recorder_capture::RecorderCaptureArgs),
    /// Submit a source-backed non-target-code attribution for controlled routing.
    Route(RouteArgs),
    /// Verify one coordinator-issued system repair acceptance.
    Repair(RepairArgs),
    /// Confirm the runtime identity of one dispatched or resumed API subagent.
    Worker(WorkerArgs),
    /// Schedule selected stale APIs before the deferred final verification batch.
    Verification(VerificationArgs),
    /// Execute coordinator-issued target repository quality gates.
    TargetQuality(TargetQualityArgs),
    /// Request a fresh coordinator-owned recording with explicit bounded parameters.
    Recording(RecordingArgs),
    /// Remove only a stale coordinator lock after its process has exited.
    Recover,
}

#[derive(Debug, Args)]
struct NextArgs {
    /// Optional canonical API selector; omit at startup to process every API observed through recorder configuration.
    #[arg(long, value_name = "METHOD PATH_OR_PATTERN")]
    api: Option<RecordingApi>,
    /// Source registration route for the active dynamic API when requested by the coordinator.
    #[arg(long)]
    source_route: Option<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// API work item whose action should be reconstructed while other AI work proceeds.
    #[arg(long, value_name = "METHOD PATH_OR_PATTERN")]
    api: Option<RecordingApi>,
}

#[derive(Debug, Args)]
struct EvidenceArgs {
    /// Opaque current query id returned by rewrite next.
    query_id: String,
}

#[derive(Debug, Args)]
struct CaseArgs {
    #[command(subcommand)]
    command: CaseCommand,
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
    /// Validate current evidence and preview one response-rule change.
    Plan(RulePlanArgs),
    /// Atomically apply the persisted, evidence-validated pending plan.
    Apply(RuleApplyArgs),
}

#[derive(Debug, Args)]
struct RulePlanArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long, value_enum)]
    kind: RuleKindArg,
    #[arg(long)]
    json_pointer: Option<String>,
    #[arg(long = "dynamic-mechanism", value_enum)]
    dynamic_mechanisms: Vec<DynamicMechanismArg>,
    #[arg(long)]
    source_evidence: Option<String>,
    #[arg(long)]
    source_example: Option<String>,
    #[arg(long)]
    target_example: Option<String>,
}

#[derive(Debug, Args)]
struct RuleApplyArgs {
    plan_id: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RuleKindArg {
    Dynamic,
    Unordered,
    Counter,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DynamicMechanismArg {
    Timestamp,
    Duration,
    Uuid,
    Random,
    Nonce,
    RandomSalt,
    DynamicDerived,
}

#[derive(Debug, Args)]
struct RouteArgs {
    #[arg(long, value_enum)]
    kind: RouteKindArg,
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    source_ref: String,
    #[arg(long)]
    required_change: String,
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
    /// Transfer one API to a replacement subagent after explicit caller approval.
    Transfer(WorkerTransferArgs),
}

#[derive(Debug, Args)]
struct WorkerConfirmArgs {
    /// Opaque dispatch id returned by the current implementation_required action.
    dispatch_id: String,
    /// Runtime-returned subagent handle. Supply through the named environment variable.
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
    agent_handle: String,
    /// Optional human-readable subagent name for diagnostics.
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_NAME", hide_env_values = true)]
    agent_name: Option<String>,
}

#[derive(Debug, Args)]
struct WorkerTransferArgs {
    /// Opaque current binding id returned by implementation_required status.
    binding_id: String,
    /// Runtime-returned replacement subagent handle.
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
    agent_handle: String,
    /// Optional human-readable replacement subagent name.
    #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_NAME", hide_env_values = true)]
    agent_name: Option<String>,
    /// Single-line reason the stored worker cannot retain ownership.
    #[arg(long)]
    reason: String,
    /// Attest that the caller explicitly approved replacing the API owner.
    #[arg(long, required = true)]
    approve_ownership_transfer: bool,
}

#[derive(Debug, Args)]
struct VerificationArgs {
    #[command(subcommand)]
    command: VerificationCommand,
}

#[derive(Debug, Subcommand)]
enum VerificationCommand {
    /// Promote stale completed APIs for early Replay and Compare after a high-impact change.
    Request(VerificationRequestArgs),
}

#[derive(Debug, Args)]
struct VerificationRequestArgs {
    /// API whose old successful evidence should be checked early; repeat for multiple APIs.
    #[arg(long = "api", required = true, value_name = "METHOD PATH_OR_PATTERN")]
    apis: Vec<RecordingApi>,
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
    /// Run the exact quality gates bound to the integrated target revision.
    Run(TargetQualityRunArgs),
}

#[derive(Debug, Args)]
struct TargetQualityRunArgs {
    gate_id: String,
    /// API acceptance whose integrated target revision issued this gate.
    #[arg(long, value_name = "METHOD PATH_OR_PATTERN")]
    api: RecordingApi,
}

#[derive(Debug, Args)]
struct RecordingArgs {
    #[command(subcommand)]
    command: RecordingCommand,
}

#[derive(Debug, Subcommand)]
enum RecordingCommand {
    /// Request or recover one idempotent standard recording action.
    Request(RecordingRequestArgs),
    /// Start one detached coordinator-owned recording action and return immediately.
    Execute(RecordingExecuteArgs),
}

#[derive(Debug, Args)]
struct RecordingExecuteArgs {
    action_id: String,
}

#[derive(Debug, Args)]
struct RecordingRequestArgs {
    #[arg(long, value_enum)]
    kind: RecordingKindArg,
    #[arg(long, value_enum)]
    reason: RecordingReasonArg,
    #[arg(long, default_value = "60")]
    duration_seconds: NonZeroU64,
    #[arg(long = "per-api-case-limit", default_value = "100")]
    per_api_case_limit: NonZeroUsize,
    /// Optional API selector; omit to record every API admitted by recorder configuration.
    #[arg(long, value_name = "METHOD PATH_OR_PATTERN")]
    api: Option<RecordingApi>,
    /// Replace a different pending recording request instead of returning a conflict.
    #[arg(long)]
    replace_pending: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RecordingKindArg {
    Standard,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RecordingReasonArg {
    UserRequested,
    RecorderContractChanged,
    SourceBaselineChanged,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RouteKindArg {
    RecorderCapabilityGap,
    ReplayCapabilityGap,
    ExternalDataBlocker,
    SourceChange,
}

async fn run(cli: Cli) -> Result<()> {
    let target_root = cli.target_root;
    let pretty = cli.pretty;
    match cli.command {
        RewriteCommand::Init(args) => project_init::run(target_root, args, pretty).await,
        RewriteCommand::Startup(args) => startup::run(target_root, args, pretty),
        RewriteCommand::Next(args) => {
            let recovery_root = target_root.clone();
            let mut operation = Box::pin(next_rewrite(RewriteNextOptions {
                target_root,
                api: args.api,
                source_route: args.source_route,
            }));
            tokio::select! {
                biased;
                result = &mut operation => print_json(&result?, pretty),
                signal = shutdown_signal() => {
                    signal?;
                    drop(operation);
                    let recovery = recover_rewrite(RewriteContext {
                        target_root: recovery_root,
                    }).await?;
                    print_json(&recovery, pretty)?;
                    bail!("rewrite next was interrupted; runtime cleanup completed")
                }
            }
        }
        RewriteCommand::Status(args) => {
            let context = RewriteContext { target_root };
            let report = if let Some(api) = args.api.as_ref() {
                status_rewrite_for_api(context, Some(api))?
            } else {
                status_rewrite(context)?
            };
            print_json(&report, pretty)
        }
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
        RewriteCommand::Evidence(args) => print_json(
            &query_rewrite_evidence(RewriteContext { target_root }, &args.query_id)?,
            pretty,
        ),
        RewriteCommand::Rule(args) => match args.command {
            RuleCommand::Plan(args) => print_json(
                &plan_rewrite_rule(
                    RewriteContext { target_root },
                    RewriteRulePlanOptions {
                        evidence_id: args.evidence_id,
                        kind: args.kind.into(),
                        json_pointer: args.json_pointer,
                        dynamic_mechanisms: args
                            .dynamic_mechanisms
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        source_evidence: args.source_evidence,
                        source_example: args.source_example,
                        target_example: args.target_example,
                    },
                )?,
                pretty,
            ),
            RuleCommand::Apply(args) => print_json(
                &apply_rewrite_rule(RewriteContext { target_root }, &args.plan_id)?,
                pretty,
            ),
        },
        RewriteCommand::DependencyRule(args) => dependency_rule::run(target_root, args, pretty),
        RewriteCommand::RecorderCapture(args) => recorder_capture::run(target_root, args, pretty),
        RewriteCommand::Route(args) => print_json(
            &route_rewrite(RewriteRouteOptions {
                target_root,
                kind: args.kind.as_str().to_string(),
                evidence_id: args.evidence_id,
                source_ref: args.source_ref,
                required_change: args.required_change,
            })?,
            pretty,
        ),
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
        RewriteCommand::Worker(args) => match args.command {
            WorkerCommand::Confirm(args) => print_json(
                &confirm_rewrite_worker(RewriteWorkerConfirmOptions {
                    target_root,
                    dispatch_id: args.dispatch_id,
                    agent_handle: args.agent_handle,
                    agent_name: args.agent_name,
                })?,
                pretty,
            ),
            WorkerCommand::Transfer(args) => print_json(
                &transfer_rewrite_worker(RewriteWorkerTransferOptions {
                    target_root,
                    binding_id: args.binding_id,
                    agent_handle: args.agent_handle,
                    agent_name: args.agent_name,
                    reason: args.reason,
                    caller_approved: args.approve_ownership_transfer,
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
                &run_rewrite_target_quality(RewriteTargetQualityOptions {
                    target_root,
                    gate_id: args.gate_id,
                    api: args.api,
                })?,
                pretty,
            ),
        },
        RewriteCommand::Recording(args) => match args.command {
            RecordingCommand::Request(args) => print_json(
                &request_rewrite_recording(RewriteRecordingRequestOptions {
                    target_root,
                    kind: args.kind.into(),
                    reason: args.reason.into(),
                    duration_seconds: args.duration_seconds,
                    per_api_case_limit: args.per_api_case_limit,
                    api: args.api,
                    replace_pending: args.replace_pending,
                })?,
                pretty,
            ),
            RecordingCommand::Execute(args) => print_json(
                &start_rewrite_recording(target_root, &args.action_id)?,
                pretty,
            ),
        },
        RewriteCommand::Recover => print_json(
            &recover_rewrite(RewriteContext { target_root }).await?,
            pretty,
        ),
    }
}

impl From<RuleKindArg> for ResponseRuleKind {
    fn from(value: RuleKindArg) -> Self {
        match value {
            RuleKindArg::Dynamic => Self::Dynamic,
            RuleKindArg::Unordered => Self::Unordered,
            RuleKindArg::Counter => Self::Counter,
        }
    }
}

impl From<DynamicMechanismArg> for DynamicResponseMechanism {
    fn from(value: DynamicMechanismArg) -> Self {
        match value {
            DynamicMechanismArg::Timestamp => Self::Timestamp,
            DynamicMechanismArg::Duration => Self::Duration,
            DynamicMechanismArg::Uuid => Self::Uuid,
            DynamicMechanismArg::Random => Self::Random,
            DynamicMechanismArg::Nonce => Self::Nonce,
            DynamicMechanismArg::RandomSalt => Self::RandomSalt,
            DynamicMechanismArg::DynamicDerived => Self::DynamicDerived,
        }
    }
}

impl RouteKindArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::RecorderCapabilityGap => "recorder_capability_gap",
            Self::ReplayCapabilityGap => "replay_capability_gap",
            Self::ExternalDataBlocker => "external_data_blocker",
            Self::SourceChange => "source_change",
        }
    }
}

impl From<RecordingKindArg> for RewriteRecordingKind {
    fn from(value: RecordingKindArg) -> Self {
        match value {
            RecordingKindArg::Standard => Self::Standard,
        }
    }
}

impl From<RecordingReasonArg> for RewriteRecordingReason {
    fn from(value: RecordingReasonArg) -> Self {
        match value {
            RecordingReasonArg::UserRequested => Self::UserRequested,
            RecordingReasonArg::RecorderContractChanged => Self::RecorderContractChanged,
            RecordingReasonArg::SourceBaselineChanged => Self::SourceBaselineChanged,
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

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
