use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    ComparisonResponseRuleFeedback, ResponseRuleKind, plan_comparison_response_rule,
};

#[derive(Debug, Args)]
pub(super) struct ComparisonArgs {
    #[command(subcommand)]
    command: ComparisonCommand,
}

#[derive(Debug, Subcommand)]
enum ComparisonCommand {
    /// Validate comparison evidence and preview one comparison-only strategy.
    Plan(PlanArgs),
    /// Validate comparison evidence and atomically apply one comparison-only strategy.
    Apply(ApplyArgs),
}

#[derive(Debug, Args)]
struct PlanArgs {
    #[command(subcommand)]
    strategy: ComparisonStrategy,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    #[command(subcommand)]
    strategy: ComparisonStrategy,
}

#[derive(Debug, Subcommand)]
enum ComparisonStrategy {
    /// Add an evidence-backed comparison-only response rule.
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
    source_evidence: String,
    #[arg(long)]
    source_example: String,
    #[arg(long)]
    target_example: String,
    /// Exact finalized comparison recording directory.
    #[arg(long)]
    comparison_run: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ResponseRuleKindArg {
    /// A source-proven live count whose representation class remains exact.
    Counter,
}

pub(super) fn run(target_root: PathBuf, args: ComparisonArgs) -> Result<()> {
    match args.command {
        ComparisonCommand::Plan(args) => plan(target_root, args.strategy),
        ComparisonCommand::Apply(args) => apply(target_root, args.strategy),
    }
}

fn plan(target_root: PathBuf, strategy: ComparisonStrategy) -> Result<()> {
    match strategy {
        ComparisonStrategy::ResponseRule(args) => {
            let plan = response_rule_plan(target_root, args)?;
            super::print_json(plan.report())
        }
    }
}

fn apply(target_root: PathBuf, strategy: ComparisonStrategy) -> Result<()> {
    match strategy {
        ComparisonStrategy::ResponseRule(args) => {
            let report = response_rule_plan(target_root, args)?.apply()?;
            super::print_json(&report)
        }
    }
}

fn response_rule_plan(
    target_root: PathBuf,
    args: ResponseRuleArgs,
) -> Result<traffic_e2e::ResponseRulePlan> {
    let kind = match args.kind {
        ResponseRuleKindArg::Counter => ResponseRuleKind::Counter,
    };
    plan_comparison_response_rule(ComparisonResponseRuleFeedback {
        policy_path: target_root.join(".traffic-e2e/verification.yaml"),
        kind,
        api: args.api,
        json_pointers: args.json_pointers,
        source_evidence: Some(args.source_evidence),
        source_example: Some(args.source_example),
        target_example: Some(args.target_example),
        comparison_report: args.comparison_run.join("comparison-report.json"),
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        comparison: ComparisonArgs,
    }

    #[test]
    fn counter_rule_accepts_a_comparison_run() {
        assert!(
            TestCli::try_parse_from([
                "test",
                "plan",
                "response-rule",
                "--kind",
                "counter",
                "--api",
                "GET /api",
                "--json-pointer",
                "/count",
                "--source-evidence",
                "src/api.rs:count",
                "--source-example",
                "1",
                "--target-example",
                "2",
                "--comparison-run",
                "/comparison/run",
            ])
            .is_ok()
        );
    }
}
