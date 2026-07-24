use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    AllowedUnusedHttpHostFeedback, BackgroundDependencyFeedback, CasePathPatternAuthority,
    CasePathPatternFeedback, RecorderConfigInitOptions, VerifiedApiExcludeFeedback,
    VerifiedApiVerification, initialize_recorder_config, plan_allowed_unused_http_hosts,
    plan_background_dependency, plan_case_path_pattern_feedback, plan_verified_api_exclude,
};

#[derive(Debug, Args)]
pub(super) struct RecorderArgs {
    #[command(subcommand)]
    command: RecorderCommand,
}

#[derive(Debug, Subcommand)]
enum RecorderCommand {
    /// Create a complete recorder template from four runtime facts.
    Init(InitArgs),
    /// Validate evidence and preview one recorder strategy.
    Plan(PlanArgs),
    /// Validate evidence and atomically apply one recorder strategy.
    Apply(ApplyArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Genuine source HTTP port inside the shared recording network namespace.
    #[arg(long)]
    source_http_port: u16,
    /// Genuine application readiness path.
    #[arg(long)]
    readiness_path: String,
    /// Exact final HTTP status proving application readiness.
    #[arg(long)]
    readiness_status: u16,
    /// Reachable upstream resolver used after Recorder intercepts target DNS.
    #[arg(long)]
    upstream_dns: SocketAddr,
}

#[derive(Debug, Args)]
struct PlanArgs {
    #[command(subcommand)]
    strategy: PlanStrategy,
}

#[derive(Debug, Subcommand)]
enum PlanStrategy {
    AllowedUnusedHttpHosts(AllowedUnusedHttpHostArgs),
    BackgroundDependencies(BackgroundDependencyArgs),
    CasePathPatterns(PatternFeedbackArgs),
    VerifiedExcludes(VerifiedExcludeArgs),
}

#[derive(Debug, Args)]
struct ApplyArgs {
    #[command(subcommand)]
    strategy: ApplyStrategy,
}

#[derive(Debug, Subcommand)]
enum ApplyStrategy {
    AllowedUnusedHttpHosts(AllowedUnusedHttpHostArgs),
    BackgroundDependencies(BackgroundDependencyArgs),
    CasePathPatterns(ApplyPatternFeedbackArgs),
    VerifiedExcludes(VerifiedExcludeArgs),
}

#[derive(Debug, Args)]
struct AllowedUnusedHttpHostArgs {
    #[arg(long, default_value = traffic_e2e::DEFAULT_RECORDING_RULE)]
    rule: String,
    #[arg(long = "host", required = true)]
    hosts: Vec<String>,
}

#[derive(Debug, Args)]
struct BackgroundDependencyArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    authority: String,
    #[arg(long)]
    method: String,
    #[arg(long)]
    path_prefix: String,
    #[arg(long)]
    replay_report: PathBuf,
    #[arg(long)]
    source_revision: String,
    #[arg(
        long,
        help = "Single-line source evidence proving process-level ownership and API independence"
    )]
    evidence: String,
}

#[derive(Debug, Args)]
struct PatternFeedbackArgs {
    #[arg(long, default_value = traffic_e2e::DEFAULT_RECORDING_RULE)]
    rule: String,
    #[arg(long)]
    source_revision: String,
    #[arg(long)]
    case_source: String,
    #[arg(long, value_enum, default_value_t = AuthorityArg::Focused)]
    authority: AuthorityArg,
    #[arg(
        long = "pattern",
        help = "Recorder path pattern: '*' matches one segment; trailing '**' matches one or more remaining segments"
    )]
    patterns: Vec<String>,
    #[arg(
        long = "remove-incorrect-pattern",
        help = "Exact existing AI-managed pattern proven incorrect from source routes"
    )]
    incorrect_patterns: Vec<String>,
    #[arg(
        long,
        help = "Single-line source-route evidence for explicitly removed incorrect patterns"
    )]
    correction_evidence: Option<String>,
}

#[derive(Debug, Args)]
struct ApplyPatternFeedbackArgs {
    #[command(flatten)]
    feedback: PatternFeedbackArgs,
    #[arg(long)]
    allow_delete: bool,
}

#[derive(Debug, Args)]
struct VerifiedExcludeArgs {
    #[arg(long, default_value = traffic_e2e::DEFAULT_RECORDING_RULE)]
    rule: String,
    #[arg(long)]
    method: String,
    #[arg(
        long,
        help = "Exact path or recorder path pattern: '*' matches one segment; trailing '**' matches one or more remaining segments"
    )]
    pattern: String,
    #[arg(long)]
    aggregate_report: PathBuf,
    #[arg(long)]
    assertion_report: PathBuf,
    #[arg(long)]
    consecutive_successful_runs: u64,
    #[arg(long)]
    consecutive_successful_cases: u64,
    #[arg(long)]
    required_consecutive_successful_runs: u64,
    #[arg(long)]
    required_successful_cases: u64,
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

pub(super) fn run(target_root: PathBuf, args: RecorderArgs) -> Result<()> {
    match args.command {
        RecorderCommand::Init(args) => {
            super::print_json(&initialize_recorder_config(RecorderConfigInitOptions {
                target_root,
                source_http_port: args.source_http_port,
                readiness_path: args.readiness_path,
                readiness_status: args.readiness_status,
                upstream_dns: args.upstream_dns,
            })?)
        }
        RecorderCommand::Plan(args) => plan(target_root, args.strategy),
        RecorderCommand::Apply(args) => apply(target_root, args.strategy),
    }
}

fn plan(target_root: PathBuf, strategy: PlanStrategy) -> Result<()> {
    let config = recorder_path(&target_root);
    match strategy {
        PlanStrategy::AllowedUnusedHttpHosts(args) => {
            let plan = plan_allowed_unused_http_hosts(allowed_unused_feedback(config, args))?;
            super::print_json(plan.report())
        }
        PlanStrategy::BackgroundDependencies(args) => {
            let plan = plan_background_dependency(background_feedback(config, args))?;
            super::print_json(plan.report())
        }
        PlanStrategy::CasePathPatterns(args) => {
            let plan = plan_case_path_pattern_feedback(pattern_feedback(config, args))?;
            super::print_json(plan.report())
        }
        PlanStrategy::VerifiedExcludes(args) => {
            let plan = plan_verified_api_exclude(verified_feedback(config, args))?;
            super::print_json(plan.report())
        }
    }
}

fn apply(target_root: PathBuf, strategy: ApplyStrategy) -> Result<()> {
    let config = recorder_path(&target_root);
    match strategy {
        ApplyStrategy::AllowedUnusedHttpHosts(args) => {
            let report =
                plan_allowed_unused_http_hosts(allowed_unused_feedback(config, args))?.apply()?;
            super::print_json(&report)
        }
        ApplyStrategy::BackgroundDependencies(args) => {
            let report = plan_background_dependency(background_feedback(config, args))?.apply()?;
            super::print_json(&report)
        }
        ApplyStrategy::CasePathPatterns(args) => {
            let report = plan_case_path_pattern_feedback(pattern_feedback(config, args.feedback))?
                .apply(args.allow_delete)?;
            super::print_json(&report)
        }
        ApplyStrategy::VerifiedExcludes(args) => {
            let report = plan_verified_api_exclude(verified_feedback(config, args))?.apply()?;
            super::print_json(&report)
        }
    }
}

fn recorder_path(target_root: &std::path::Path) -> PathBuf {
    target_root.join(".traffic-e2e/recorder.toml")
}

fn allowed_unused_feedback(
    config_path: PathBuf,
    args: AllowedUnusedHttpHostArgs,
) -> AllowedUnusedHttpHostFeedback {
    AllowedUnusedHttpHostFeedback {
        config_path,
        rule_name: args.rule,
        hosts: args.hosts,
    }
}

fn background_feedback(
    config_path: PathBuf,
    args: BackgroundDependencyArgs,
) -> BackgroundDependencyFeedback {
    BackgroundDependencyFeedback {
        config_path,
        replay_report_path: args.replay_report,
        name: args.name,
        authority: args.authority,
        method: args.method,
        path_prefix: args.path_prefix,
        source_revision: args.source_revision,
        source_evidence: args.evidence,
    }
}

fn pattern_feedback(config_path: PathBuf, args: PatternFeedbackArgs) -> CasePathPatternFeedback {
    CasePathPatternFeedback {
        config_path,
        rule_name: args.rule,
        source_revision: args.source_revision,
        case_source: args.case_source,
        authority: args.authority.into(),
        patterns: args.patterns,
        incorrect_patterns: args.incorrect_patterns,
        correction_evidence: args.correction_evidence,
    }
}

fn verified_feedback(
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
        verification: VerifiedApiVerification {
            consecutive_successful_runs: args.consecutive_successful_runs,
            consecutive_successful_cases: args.consecutive_successful_cases,
            required_consecutive_successful_runs: args.required_consecutive_successful_runs,
            required_successful_cases: args.required_successful_cases,
        },
    }
}
