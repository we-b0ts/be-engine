use std::path::PathBuf;

use anyhow::Result;
use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use traffic_e2e::{
    ComparisonResponseRuleFeedback, ReplayPolicyInitOptions, ResponseRuleFeedback,
    ResponseRuleKind, initialize_replay_policy, plan_comparison_response_rule, plan_response_rule,
};

#[derive(Debug, Args)]
pub(super) struct ReplayArgs {
    #[command(subcommand)]
    command: ReplayCommand,
}

#[derive(Debug, Subcommand)]
enum ReplayCommand {
    /// Create an empty dependency replay and response verification policy.
    Init,
    /// Validate evidence and preview one policy strategy.
    Plan(PlanArgs),
    /// Validate evidence and atomically apply one policy strategy.
    Apply(ApplyArgs),
}

#[derive(Debug, Args)]
struct PlanArgs {
    #[command(subcommand)]
    strategy: ReplayStrategy,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    #[command(subcommand)]
    strategy: ReplayStrategy,
}

#[derive(Debug, Subcommand)]
enum ReplayStrategy {
    /// Add evidence-backed dynamic or unordered response fields.
    ResponseRule(ResponseRuleArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("evidence")
        .required(true)
        .args(["assertion_report", "comparison_report"])
))]
struct ResponseRuleArgs {
    #[arg(long, value_enum)]
    kind: ResponseRuleKindArg,
    #[arg(long)]
    api: String,
    #[arg(long = "json-pointer", required = true)]
    json_pointers: Vec<String>,
    #[arg(
        long,
        requires = "aggregate_report",
        conflicts_with = "comparison_report"
    )]
    assertion_report: Option<PathBuf>,
    #[arg(
        long,
        requires = "assertion_report",
        conflicts_with = "comparison_report"
    )]
    aggregate_report: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["assertion_report", "aggregate_report"])]
    comparison_report: Option<PathBuf>,
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

pub(super) fn run(target_root: PathBuf, args: ReplayArgs) -> Result<()> {
    match args.command {
        ReplayCommand::Init => {
            super::print_json(&initialize_replay_policy(ReplayPolicyInitOptions {
                target_root,
            })?)
        }
        ReplayCommand::Plan(args) => plan(target_root, args.strategy),
        ReplayCommand::Apply(args) => apply(target_root, args.strategy),
    }
}

fn plan(target_root: PathBuf, strategy: ReplayStrategy) -> Result<()> {
    match strategy {
        ReplayStrategy::ResponseRule(args) => {
            let plan = response_rule_plan(target_root, args)?;
            super::print_json(plan.report())
        }
    }
}

fn apply(target_root: PathBuf, strategy: ReplayStrategy) -> Result<()> {
    match strategy {
        ReplayStrategy::ResponseRule(args) => {
            let report = response_rule_plan(target_root, args)?.apply()?;
            super::print_json(&report)
        }
    }
}

fn response_rule_plan(
    target_root: PathBuf,
    args: ResponseRuleArgs,
) -> Result<traffic_e2e::ResponseRulePlan> {
    let policy_path = target_root.join(".traffic-e2e/verification.yaml");
    let kind = args.kind.into();
    if let Some(comparison_report) = args.comparison_report {
        plan_comparison_response_rule(ComparisonResponseRuleFeedback {
            policy_path,
            kind,
            api: args.api,
            json_pointers: args.json_pointers,
            comparison_report,
        })
    } else {
        plan_response_rule(ResponseRuleFeedback {
            policy_path,
            kind,
            api: args.api,
            json_pointers: args.json_pointers,
            assertion_report: args
                .assertion_report
                .expect("clap requires replay assertion evidence"),
            aggregate_report: args
                .aggregate_report
                .expect("clap requires replay aggregate evidence"),
        })
    }
}
