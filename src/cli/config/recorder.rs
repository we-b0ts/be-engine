use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    AllowedUnusedHttpHostFeedback, BreezeResourceCaptureFeedback, CasePathPatternAuthority,
    CasePathPatternFeedback, plan_allowed_unused_http_hosts, plan_breeze_resource_capture,
    plan_case_path_pattern_feedback,
};

mod background_dependency;

#[derive(Debug, Args)]
pub(super) struct RecorderArgs {
    #[command(subcommand)]
    command: RecorderCommand,
}

#[derive(Debug, Subcommand)]
enum RecorderCommand {
    /// Validate evidence and preview one recorder strategy.
    Plan(PlanArgs),
    /// Validate evidence and atomically apply one recorder strategy.
    Apply(ApplyArgs),
}

#[derive(Debug, Args)]
struct PlanArgs {
    #[command(subcommand)]
    strategy: PlanStrategy,
}

#[derive(Debug, Subcommand)]
enum PlanStrategy {
    AllowedUnusedHttpHosts(AllowedUnusedHttpHostArgs),
    ProcessOwnedDependencies(Box<background_dependency::BackgroundDependencyArgs>),
    BreezeResourceCapture(BreezeResourceCaptureArgs),
    CasePathPatterns(PatternFeedbackArgs),
}

#[derive(Debug, Args)]
struct ApplyArgs {
    #[command(subcommand)]
    strategy: ApplyStrategy,
}

#[derive(Debug, Subcommand)]
enum ApplyStrategy {
    AllowedUnusedHttpHosts(AllowedUnusedHttpHostArgs),
    ProcessOwnedDependencies(Box<background_dependency::BackgroundDependencyArgs>),
    BreezeResourceCapture(BreezeResourceCaptureArgs),
    CasePathPatterns(ApplyPatternFeedbackArgs),
}

#[derive(Debug, Args)]
struct AllowedUnusedHttpHostArgs {
    #[arg(long = "host", required = true)]
    hosts: Vec<String>,
}

#[derive(Debug, Args)]
struct BreezeResourceCaptureArgs {
    /// Unique Breeze snapshot resource name or exact descriptor identity.
    #[arg(long)]
    resource: String,
    /// Immutable source revision used for the response-driving diagnosis.
    #[arg(long)]
    source_revision: String,
    /// Single-line source file/symbol evidence connecting the response to this resource.
    #[arg(long)]
    evidence: String,
}

#[derive(Debug, Args)]
struct PatternFeedbackArgs {
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
        RecorderCommand::Plan(args) => plan(target_root, args.strategy),
        RecorderCommand::Apply(args) => apply(target_root, args.strategy),
    }
}

fn plan(target_root: PathBuf, strategy: PlanStrategy) -> Result<()> {
    let project = project_path(&target_root);
    let rules = source_traffic_policy_path(&target_root);
    match strategy {
        PlanStrategy::AllowedUnusedHttpHosts(args) => {
            let plan =
                plan_allowed_unused_http_hosts(allowed_unused_feedback(project, rules, args))?;
            super::print_json(plan.report())
        }
        PlanStrategy::ProcessOwnedDependencies(args) => {
            background_dependency::run(target_root, rules, *args, false)
        }
        PlanStrategy::BreezeResourceCapture(args) => {
            let plan = plan_breeze_resource_capture(breeze_capture_feedback(project, rules, args))?;
            super::print_json(plan.report())
        }
        PlanStrategy::CasePathPatterns(args) => {
            let plan = plan_case_path_pattern_feedback(pattern_feedback(project, rules, args))?;
            super::print_json(plan.report())
        }
    }
}

fn apply(target_root: PathBuf, strategy: ApplyStrategy) -> Result<()> {
    let project = project_path(&target_root);
    let rules = source_traffic_policy_path(&target_root);
    match strategy {
        ApplyStrategy::AllowedUnusedHttpHosts(args) => {
            let report =
                plan_allowed_unused_http_hosts(allowed_unused_feedback(project, rules, args))?
                    .apply()?;
            super::print_json(&report)
        }
        ApplyStrategy::ProcessOwnedDependencies(args) => {
            background_dependency::run(target_root, rules, *args, true)
        }
        ApplyStrategy::BreezeResourceCapture(args) => {
            let report =
                plan_breeze_resource_capture(breeze_capture_feedback(project, rules, args))?
                    .apply()?;
            super::print_json(&report)
        }
        ApplyStrategy::CasePathPatterns(args) => {
            let report =
                plan_case_path_pattern_feedback(pattern_feedback(project, rules, args.feedback))?
                    .apply(args.allow_delete)?;
            super::print_json(&report)
        }
    }
}

fn breeze_capture_feedback(
    project_config_path: PathBuf,
    rules_path: PathBuf,
    args: BreezeResourceCaptureArgs,
) -> BreezeResourceCaptureFeedback {
    BreezeResourceCaptureFeedback {
        project_config_path,
        rules_path,
        resource: args.resource,
        source_revision: args.source_revision,
        source_evidence: args.evidence,
    }
}

fn project_path(target_root: &std::path::Path) -> PathBuf {
    target_root.join(".traffic-e2e/project.yaml")
}

fn source_traffic_policy_path(target_root: &std::path::Path) -> PathBuf {
    target_root
        .join(".traffic-e2e")
        .join("source-traffic-policy.yaml")
}

fn allowed_unused_feedback(
    project_config_path: PathBuf,
    rules_path: PathBuf,
    args: AllowedUnusedHttpHostArgs,
) -> AllowedUnusedHttpHostFeedback {
    AllowedUnusedHttpHostFeedback {
        project_config_path,
        rules_path,
        hosts: args.hosts,
    }
}

fn pattern_feedback(
    project_config_path: PathBuf,
    rules_path: PathBuf,
    args: PatternFeedbackArgs,
) -> CasePathPatternFeedback {
    CasePathPatternFeedback {
        project_config_path,
        rules_path,
        source_revision: args.source_revision,
        case_source: args.case_source,
        authority: args.authority.into(),
        patterns: args.patterns,
        incorrect_patterns: args.incorrect_patterns,
        correction_evidence: args.correction_evidence,
    }
}
