use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    DynamicResponseMechanism, RecordingApi, ResponseRuleKind, RewriteContext, RewriteNextOptions,
    RewriteRecordingKind, RewriteRecordingReason, RewriteRecordingRequestOptions,
    RewriteRouteOptions, RewriteRulePlanOptions, apply_rewrite_rule, execute_rewrite_recording,
    next_rewrite, plan_rewrite_rule, query_rewrite_evidence, recover_rewrite,
    request_rewrite_recording, route_rewrite, status_rewrite, verify_rewrite_repair,
};

mod dependency_rule;

#[derive(Debug, Args)]
pub(super) struct RewriteArgs {
    /// Initialized target repository root.
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    #[command(subcommand)]
    command: RewriteCommand,
}

#[derive(Debug, Subcommand)]
enum RewriteCommand {
    /// Advance deterministic stages and return the only allowed next action.
    Next(NextArgs),
    /// Show bounded coordinator state without advancing it.
    Status,
    /// Execute one current, bounded evidence query.
    Evidence(EvidenceArgs),
    /// Plan or apply one evidence-backed response rule.
    Rule(RuleArgs),
    /// Plan or apply one source-proven background dependency rule.
    DependencyRule(dependency_rule::DependencyRuleArgs),
    /// Submit a source-backed non-target-code attribution for controlled routing.
    Route(RouteArgs),
    /// Verify one coordinator-issued system repair acceptance.
    Repair(RepairArgs),
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
struct EvidenceArgs {
    /// Opaque current query id returned by rewrite next.
    query_id: String,
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
    /// Revalidate and atomically apply an unchanged pending plan.
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
}

#[derive(Debug, Args)]
struct RepairVerifyArgs {
    repair_id: String,
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
    /// Execute one unchanged coordinator-owned recording action.
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

pub(super) async fn run(args: RewriteArgs) -> Result<()> {
    let target_root = args.target_root;
    match args.command {
        RewriteCommand::Next(args) => {
            let recovery_root = target_root.clone();
            let mut operation = Box::pin(next_rewrite(RewriteNextOptions {
                target_root,
                api: args.api,
                source_route: args.source_route,
            }));
            tokio::select! {
                biased;
                result = &mut operation => print_json(&result?),
                signal = super::signal::shutdown_signal() => {
                    signal?;
                    drop(operation);
                    let recovery = recover_rewrite(RewriteContext {
                        target_root: recovery_root,
                    }).await?;
                    print_json(&recovery)?;
                    bail!("rewrite next was interrupted; runtime cleanup completed")
                }
            }
        }
        RewriteCommand::Status => print_json(&status_rewrite(RewriteContext { target_root })?),
        RewriteCommand::Evidence(args) => print_json(&query_rewrite_evidence(
            RewriteContext { target_root },
            &args.query_id,
        )?),
        RewriteCommand::Rule(args) => match args.command {
            RuleCommand::Plan(args) => print_json(&plan_rewrite_rule(
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
            )?),
            RuleCommand::Apply(args) => print_json(&apply_rewrite_rule(
                RewriteContext { target_root },
                &args.plan_id,
            )?),
        },
        RewriteCommand::DependencyRule(args) => dependency_rule::run(target_root, args),
        RewriteCommand::Route(args) => print_json(&route_rewrite(RewriteRouteOptions {
            target_root,
            kind: args.kind.as_str().to_string(),
            evidence_id: args.evidence_id,
            source_ref: args.source_ref,
            required_change: args.required_change,
        })?),
        RewriteCommand::Repair(args) => match args.command {
            RepairCommand::Verify(args) => print_json(&verify_rewrite_repair(
                RewriteContext { target_root },
                &args.repair_id,
            )?),
        },
        RewriteCommand::Recording(args) => match args.command {
            RecordingCommand::Request(args) => print_json(&request_rewrite_recording(
                RewriteRecordingRequestOptions {
                    target_root,
                    kind: args.kind.into(),
                    reason: args.reason.into(),
                    duration_seconds: args.duration_seconds,
                    per_api_case_limit: args.per_api_case_limit,
                    replace_pending: args.replace_pending,
                },
            )?),
            RecordingCommand::Execute(args) => {
                print_json(&execute_rewrite_recording(target_root, &args.action_id).await?)
            }
        },
        RewriteCommand::Recover => {
            print_json(&recover_rewrite(RewriteContext { target_root }).await?)
        }
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

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout(), value)?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        rewrite: RewriteArgs,
    }

    #[test]
    fn parses_the_bounded_rewrite_surface() {
        assert!(
            TestCli::try_parse_from([
                "test",
                "next",
                "--api",
                "GET /api/users/*",
                "--source-route",
                "/api/users/:id",
            ])
            .is_ok()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "recording",
                "request",
                "--kind",
                "standard",
                "--reason",
                "user-requested",
                "--replace-pending",
            ])
            .is_ok()
        );
        assert!(
            TestCli::try_parse_from(
                ["test", "recording", "execute", "recording-0123456789abcdef",]
            )
            .is_ok()
        );
        assert!(
            TestCli::try_parse_from(["test", "evidence", "evq-r1-issue-representatives"]).is_ok()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "route",
                "--kind",
                "replay-capability-gap",
                "--evidence-id",
                "evidence-1",
                "--source-ref",
                "src/client.rs:42",
                "--required-change",
                "support source-equivalent request matching",
            ])
            .is_ok()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "route",
                "--kind",
                "replay-capability-gap",
                "--evidence-id",
                "evidence-1",
                "--source-ref",
                "src/client.rs:42",
                "--required-change",
                "support source-equivalent request matching",
                "--acceptance-command",
                "traffic-e2e rewrite next",
            ])
            .is_err()
        );
        assert!(TestCli::try_parse_from(["test", "repair", "verify", "repair-1"]).is_ok());
        assert!(
            TestCli::try_parse_from([
                "test",
                "recording",
                "request",
                "--kind",
                "standard",
                "--reason",
                "user-requested",
                "--duration-seconds",
                "90",
                "--per-api-case-limit",
                "250",
            ])
            .is_ok()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "recording",
                "request",
                "--kind",
                "standard",
                "--reason",
                "user-requested",
                "--per-api-case-limit",
                "0",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "dependency-rule",
                "plan",
                "memcached",
                "--evidence-id",
                "evidence-1",
                "--name",
                "planet-video-cache-warm",
                "--source-evidence",
                "TopUserServiceImpl.java:691 scheduled cache warm",
                "--breeze-resource",
                "user-video",
                "--key-start",
                "0",
                "--key-end",
                "4095",
                "--key-suffix",
                "pl_video",
            ])
            .is_ok()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "dependency-rule",
                "plan",
                "memcached",
                "--evidence-id",
                "evidence-1",
                "--name",
                "cache-warm",
                "--source-evidence",
                "src/cache.rs:init",
                "--breeze-resource",
                "user-video",
                "--key-start",
                "0",
                "--key-end",
                "1",
                "--key-suffix",
                "warm",
                "--authority",
                "config.internal",
            ])
            .is_err()
        );
    }

    #[test]
    fn dependency_rule_help_is_protocol_specific_and_has_no_api_context() {
        let memcached =
            TestCli::try_parse_from(["test", "dependency-rule", "plan", "memcached", "--help"])
                .unwrap_err()
                .to_string();
        assert!(memcached.contains("--breeze-resource"));
        assert!(memcached.contains("--key-start"));
        assert!(!memcached.contains("--authority"));
        assert!(!memcached.contains("--api"));
        assert!(!memcached.contains("--case-source"));
        assert!(!memcached.contains("--source-revision"));

        let http = TestCli::try_parse_from(["test", "dependency-rule", "plan", "http", "--help"])
            .unwrap_err()
            .to_string();
        assert!(http.contains("--authority"));
        assert!(http.contains("--path-prefix"));
        assert!(!http.contains("--breeze-resource"));
        assert!(!http.contains("--key-start"));

        let zcount = TestCli::try_parse_from([
            "test",
            "dependency-rule",
            "plan",
            "redis",
            "zcount",
            "--help",
        ])
        .unwrap_err()
        .to_string();
        assert!(zcount.contains("--key-prefix"));
        assert!(!zcount.contains("--key <"));
        assert!(!zcount.contains("--initial-load-timeout-ms"));

        let get =
            TestCli::try_parse_from(["test", "dependency-rule", "plan", "redis", "get", "--help"])
                .unwrap_err()
                .to_string();
        assert!(get.contains("--key <"));
        assert!(get.contains("--initial-load-timeout-ms"));
        assert!(!get.contains("--key-prefix"));
    }
}
