use std::path::PathBuf;

use anyhow::Result;
use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use traffic_e2e::{
    ComparisonResponseRuleFeedback, E2eRunContext, ResponseRuleFeedback, ResponseRuleKind,
    plan_comparison_response_rule, plan_response_rule, resolve_e2e_response_rule_evidence,
};

#[derive(Debug, Args)]
pub(super) struct ReplayArgs {
    #[command(subcommand)]
    command: ReplayCommand,
}

#[derive(Debug, Subcommand)]
enum ReplayCommand {
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
    /// Add evidence-backed generated-scalar or unordered response fields.
    ResponseRule(ResponseRuleArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("evidence")
        .required(true)
        .args(["case_source", "comparison_run"])
))]
struct ResponseRuleArgs {
    #[arg(long, value_enum)]
    kind: ResponseRuleKindArg,
    #[arg(long)]
    api: String,
    #[arg(long = "json-pointer", required = true)]
    json_pointers: Vec<String>,
    #[arg(long)]
    source_evidence: String,
    #[arg(
        long,
        required_if_eq("kind", "timestamp"),
        required_if_eq("kind", "duration"),
        required_if_eq("kind", "uuid"),
        required_if_eq("kind", "random")
    )]
    source_example: Option<String>,
    #[arg(
        long,
        required_if_eq("kind", "timestamp"),
        required_if_eq("kind", "duration"),
        required_if_eq("kind", "uuid"),
        required_if_eq("kind", "random")
    )]
    target_example: Option<String>,
    /// Exact finalized replay case source; runner-owned evidence is resolved internally.
    #[arg(long, conflicts_with = "comparison_run")]
    case_source: Option<PathBuf>,
    /// Exact finalized comparison recording directory; its report is resolved internally.
    #[arg(long, conflicts_with = "case_source")]
    comparison_run: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ResponseRuleKindArg {
    Timestamp,
    Duration,
    Uuid,
    Random,
    Unordered,
}

impl From<ResponseRuleKindArg> for ResponseRuleKind {
    fn from(value: ResponseRuleKindArg) -> Self {
        match value {
            ResponseRuleKindArg::Timestamp => Self::Timestamp,
            ResponseRuleKindArg::Duration => Self::Duration,
            ResponseRuleKindArg::Uuid => Self::Uuid,
            ResponseRuleKindArg::Random => Self::Random,
            ResponseRuleKindArg::Unordered => Self::Unordered,
        }
    }
}

pub(super) fn run(target_root: PathBuf, args: ReplayArgs) -> Result<()> {
    match args.command {
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
    if let Some(comparison_run) = args.comparison_run {
        plan_comparison_response_rule(ComparisonResponseRuleFeedback {
            policy_path,
            kind,
            api: args.api,
            json_pointers: args.json_pointers,
            source_evidence: Some(args.source_evidence),
            source_example: args.source_example,
            target_example: args.target_example,
            comparison_report: comparison_run.join("comparison-report.json"),
        })
    } else {
        let evidence = resolve_e2e_response_rule_evidence(
            E2eRunContext {
                target_root: target_root.clone(),
                case_source: args
                    .case_source
                    .expect("clap requires replay or comparison evidence"),
                run_key: None,
            },
            &args.api,
        )?;
        plan_response_rule(ResponseRuleFeedback {
            policy_path,
            kind,
            api: args.api,
            json_pointers: args.json_pointers,
            source_evidence: Some(args.source_evidence),
            source_example: args.source_example,
            target_example: args.target_example,
            assertion_report: evidence.assertions,
            aggregate_report: evidence.aggregate,
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        replay: ReplayArgs,
    }

    #[test]
    fn response_rule_uses_case_source_or_comparison_run_instead_of_report_paths() {
        assert!(
            TestCli::try_parse_from([
                "test",
                "plan",
                "response-rule",
                "--kind",
                "unordered",
                "--api",
                "GET /api",
                "--json-pointer",
                "/items",
                "--source-evidence",
                "src/api.rs:items is a Set",
                "--case-source",
                "/cases/run",
            ])
            .is_ok()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "plan",
                "response-rule",
                "--kind",
                "unordered",
                "--api",
                "GET /api",
                "--json-pointer",
                "/items",
                "--source-evidence",
                "src/api.rs:items is a Set",
                "--comparison-run",
                "/comparison/run",
            ])
            .is_ok()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "plan",
                "response-rule",
                "--kind",
                "unordered",
                "--api",
                "GET /api",
                "--json-pointer",
                "/items",
                "--source-evidence",
                "src/api.rs:items is a Set",
            ])
            .is_err()
        );
    }
}
