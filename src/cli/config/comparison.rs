use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    ComparisonResponseRuleFeedback, ProfileTargetMissingFeedback, ResponseRuleKind,
    plan_comparison_response_rule, plan_profile_target_missing,
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
    /// Allow one source-only profile metric proven to come from an indirect dependency.
    AllowTargetMissing(ProfileTargetMissingArgs),
}

#[derive(Debug, Args)]
struct ProfileTargetMissingArgs {
    #[arg(long)]
    process_output: String,
    /// Exact profile metric in <type>.<name> format.
    #[arg(long)]
    metric: String,
    #[arg(long)]
    source_revision: String,
    /// Dependency coordinates ordered from the direct dependency to the indirect emitter.
    #[arg(long, required = true)]
    dependency_path: Vec<String>,
    /// JSON evidence with inspected_paths and description from source analysis.
    #[arg(long, value_parser = parse_profile_emitter_evidence)]
    emitter_evidence: traffic_e2e::ProfileTargetMissingEmitterEvidence,
    /// Exact finalized comparison recording directory.
    #[arg(long)]
    comparison_run: PathBuf,
}

#[derive(Debug, Args)]
struct ResponseRuleArgs {
    #[arg(long, value_enum)]
    kind: ResponseRuleKindArg,
    #[arg(long)]
    api: String,
    /// JSON Pointer; a whole * segment selects every array element (quote in the shell).
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
        ComparisonStrategy::AllowTargetMissing(args) => {
            let plan = profile_target_missing_plan(target_root, args)?;
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
        ComparisonStrategy::AllowTargetMissing(args) => {
            let report = profile_target_missing_plan(target_root, args)?.apply()?;
            super::print_json(&report)
        }
    }
}

fn profile_target_missing_plan(
    target_root: PathBuf,
    args: ProfileTargetMissingArgs,
) -> Result<traffic_e2e::ProfileTargetMissingPlan> {
    plan_profile_target_missing(ProfileTargetMissingFeedback {
        project_config_path: target_root.join(".traffic-e2e/project.yaml"),
        policy_path: target_root.join(".traffic-e2e/verification.yaml"),
        process_output_id: args.process_output,
        metric: args.metric,
        source_revision: args.source_revision,
        dependency_path: args.dependency_path,
        emitter_evidence: args.emitter_evidence,
        comparison_run: args.comparison_run,
    })
}

fn parse_profile_emitter_evidence(
    value: &str,
) -> std::result::Result<traffic_e2e::ProfileTargetMissingEmitterEvidence, String> {
    serde_json::from_str(value).map_err(|error| {
        format!("--emitter-evidence must be JSON with inspected_paths and description: {error}")
    })
}

fn response_rule_plan(
    target_root: PathBuf,
    args: ResponseRuleArgs,
) -> Result<traffic_e2e::ResponseRulePlan> {
    let kind = match args.kind {
        ResponseRuleKindArg::Counter => ResponseRuleKind::Counter,
    };
    plan_comparison_response_rule(ComparisonResponseRuleFeedback {
        time: None,
        policy_path: target_root.join(".traffic-e2e/verification.yaml"),
        kind,
        api: args.api,
        json_pointers: args.json_pointers,
        source_evidence: Some(args.source_evidence),
        source_example: Some(args.source_example),
        target_example: Some(args.target_example),
        separator: None,
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

    #[test]
    fn target_missing_rule_requires_structured_indirect_dependency_evidence() {
        assert!(
            TestCli::try_parse_from([
                "test",
                "plan",
                "allow-target-missing",
                "--process-output",
                "metrics-profile",
                "--metric",
                "HTTP.http://telemetry.example/ping",
                "--source-revision",
                "0123456789abcdef",
                "--dependency-path",
                "com.example:client:1.0.0",
                "--dependency-path",
                "com.vendor:telemetry:2.0.0",
                "--emitter-evidence",
                r#"{"inspected_paths":["pom.xml","vendor/src/com/vendor/TelemetryInitializer.java"],"description":"TelemetryInitializer independently emits /ping without affecting source behavior"}"#,
                "--comparison-run",
                "/comparison/run",
            ])
            .is_ok()
        );
    }
}
