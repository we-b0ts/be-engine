use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    ReplayPolicyInitOptions, ResponseRuleFeedback, ResponseRuleKind, initialize_replay_policy,
    plan_response_rule,
};

#[derive(Debug, Args)]
pub(super) struct ReplayArgs {
    #[command(subcommand)]
    command: ReplayCommand,
}

#[derive(Debug, Subcommand)]
enum ReplayCommand {
    /// Create an empty assertion-only replay policy.
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
struct ResponseRuleArgs {
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
    plan_response_rule(ResponseRuleFeedback {
        policy_path: target_root.join(".traffic-e2e/replay.yaml"),
        kind: args.kind.into(),
        api: args.api,
        json_pointers: args.json_pointers,
        assertion_report: args.assertion_report,
        aggregate_report: args.aggregate_report,
    })
}
