use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    DynamicResponseMechanism, RecordingApi, ResponseRuleKind, RewriteContext, RewriteNextOptions,
    RewriteRouteOptions, RewriteRulePlanOptions, apply_rewrite_rule, next_rewrite,
    plan_rewrite_rule, query_rewrite_evidence, recover_rewrite, route_rewrite, status_rewrite,
};

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
    /// Submit a source-backed non-target-code attribution for controlled routing.
    Route(RouteArgs),
    /// Remove only a stale coordinator lock after its process has exited.
    Recover,
}

#[derive(Debug, Args)]
struct NextArgs {
    /// Canonical active API. Required only when starting a new workflow.
    #[arg(long, value_name = "METHOD PATH_OR_PATTERN")]
    api: Option<RecordingApi>,
    /// Source registration route; required for a dynamic API pattern.
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
    #[arg(long)]
    acceptance_command: String,
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
        RewriteCommand::Route(args) => print_json(&route_rewrite(RewriteRouteOptions {
            target_root,
            kind: args.kind.as_str().to_string(),
            evidence_id: args.evidence_id,
            source_ref: args.source_ref,
            required_change: args.required_change,
            acceptance_command: args.acceptance_command,
        })?),
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
                "--acceptance-command",
                "traffic-e2e rewrite next",
            ])
            .is_ok()
        );
    }
}
