use std::{io, path::PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    AllowedUnusedHttpHostFeedback, AllowedUnusedHttpHostReport, BackgroundDependencyFeedback,
    BackgroundDependencyReport, CasePathPatternAuthority, CasePathPatternFeedback,
    CasePathPatternReport, VerifiedApiExcludeEnsureReport, VerifiedApiExcludeFeedback,
    VerifiedApiExcludeReport, VerifiedApiVerification, ensure_verified_api_exclude,
    plan_allowed_unused_http_hosts, plan_background_dependency, plan_case_path_pattern_feedback,
    plan_verified_api_exclude,
};

#[derive(Debug, Args)]
pub(super) struct RecorderConfigArgs {
    /// Recorder configuration to inspect or update.
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: RecorderConfigCommand,
}

#[derive(Debug, Subcommand)]
enum RecorderConfigCommand {
    AllowedUnusedHttpHosts(AllowedUnusedHttpHostsArgs),
    BackgroundDependencies(BackgroundDependenciesArgs),
    CasePathPatterns(CasePathPatternsArgs),
    VerifiedExcludes(VerifiedExcludesArgs),
}

#[derive(Debug, Args)]
struct BackgroundDependenciesArgs {
    #[command(subcommand)]
    command: BackgroundDependenciesCommand,
}

#[derive(Debug, Subcommand)]
enum BackgroundDependenciesCommand {
    Plan(BackgroundDependencyArgs),
    Apply(BackgroundDependencyArgs),
}

#[derive(Debug, Args)]
struct BackgroundDependencyArgs {
    #[arg(long)]
    name: String,
    #[arg(long, value_enum)]
    protocol: BackgroundProtocolArg,
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
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct AllowedUnusedHttpHostsArgs {
    #[command(subcommand)]
    command: AllowedUnusedHttpHostsCommand,
}

#[derive(Debug, Subcommand)]
enum AllowedUnusedHttpHostsCommand {
    Plan(AllowedUnusedHttpHostArgs),
    Apply(AllowedUnusedHttpHostArgs),
}

#[derive(Debug, Args)]
struct AllowedUnusedHttpHostArgs {
    #[arg(long)]
    rule: String,
    #[arg(long = "host", required = true)]
    hosts: Vec<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct CasePathPatternsArgs {
    #[command(subcommand)]
    command: CasePathPatternsCommand,
}

#[derive(Debug, Subcommand)]
enum CasePathPatternsCommand {
    Plan(PatternFeedbackArgs),
    Apply(ApplyPatternFeedbackArgs),
}

#[derive(Debug, Args)]
struct VerifiedExcludesArgs {
    #[command(subcommand)]
    command: VerifiedExcludesCommand,
}

#[derive(Debug, Subcommand)]
enum VerifiedExcludesCommand {
    Plan(VerifiedExcludeArgs),
    Apply(VerifiedExcludeArgs),
    Ensure(VerifiedExcludeArgs),
}

#[derive(Debug, Args)]
struct VerifiedExcludeArgs {
    #[arg(long)]
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
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct PatternFeedbackArgs {
    #[arg(long)]
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
        help = "Exact existing AI-managed pattern proven incorrect from source routes; omission from cases is never evidence"
    )]
    incorrect_patterns: Vec<String>,
    #[arg(
        long,
        help = "Single-line source-route evidence for every explicitly removed incorrect pattern"
    )]
    correction_evidence: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackgroundProtocolArg {
    Http,
}

impl From<AuthorityArg> for CasePathPatternAuthority {
    fn from(authority: AuthorityArg) -> Self {
        match authority {
            AuthorityArg::Focused => Self::Focused,
            AuthorityArg::Authoritative => Self::Authoritative,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

pub(super) fn run(args: RecorderConfigArgs) -> Result<()> {
    let RecorderConfigArgs { config, command } = args;
    match command {
        RecorderConfigCommand::AllowedUnusedHttpHosts(args) => match args.command {
            AllowedUnusedHttpHostsCommand::Plan(args) => {
                let format = args.format;
                let plan =
                    plan_allowed_unused_http_hosts(allowed_unused_http_feedback(config, args))?;
                print_allowed_unused_http_report(plan.report(), format)
            }
            AllowedUnusedHttpHostsCommand::Apply(args) => {
                let format = args.format;
                let plan =
                    plan_allowed_unused_http_hosts(allowed_unused_http_feedback(config, args))?;
                let report = plan.apply()?;
                print_allowed_unused_http_report(&report, format)
            }
        },
        RecorderConfigCommand::BackgroundDependencies(args) => match args.command {
            BackgroundDependenciesCommand::Plan(args) => {
                let format = args.format;
                let plan =
                    plan_background_dependency(background_dependency_feedback(config, args))?;
                print_background_dependency_report(plan.report(), format)
            }
            BackgroundDependenciesCommand::Apply(args) => {
                let format = args.format;
                let plan =
                    plan_background_dependency(background_dependency_feedback(config, args))?;
                let report = plan.apply()?;
                print_background_dependency_report(&report, format)
            }
        },
        RecorderConfigCommand::CasePathPatterns(args) => match args.command {
            CasePathPatternsCommand::Plan(args) => {
                let format = args.format;
                let plan = plan_case_path_pattern_feedback(feedback(config, args))?;
                print_pattern_report(plan.report(), format)
            }
            CasePathPatternsCommand::Apply(args) => {
                let format = args.feedback.format;
                let plan = plan_case_path_pattern_feedback(feedback(config, args.feedback))?;
                let report = plan.apply(args.allow_delete)?;
                print_pattern_report(&report, format)
            }
        },
        RecorderConfigCommand::VerifiedExcludes(args) => match args.command {
            VerifiedExcludesCommand::Plan(args) => {
                let format = args.format;
                let plan = plan_verified_api_exclude(verified_exclude_feedback(config, args))?;
                print_verified_exclude_report(plan.report(), format)
            }
            VerifiedExcludesCommand::Apply(args) => {
                let format = args.format;
                let plan = plan_verified_api_exclude(verified_exclude_feedback(config, args))?;
                let report = plan.apply()?;
                print_verified_exclude_report(&report, format)
            }
            VerifiedExcludesCommand::Ensure(args) => {
                let format = args.format;
                let report = ensure_verified_api_exclude(verified_exclude_feedback(config, args))?;
                print_verified_exclude_ensure_report(&report, format)
            }
        },
    }
}

fn background_dependency_feedback(
    config_path: PathBuf,
    args: BackgroundDependencyArgs,
) -> BackgroundDependencyFeedback {
    match args.protocol {
        BackgroundProtocolArg::Http => BackgroundDependencyFeedback {
            config_path,
            replay_report_path: args.replay_report,
            name: args.name,
            authority: args.authority,
            method: args.method,
            path_prefix: args.path_prefix,
            source_revision: args.source_revision,
            source_evidence: args.evidence,
        },
    }
}

fn allowed_unused_http_feedback(
    config_path: PathBuf,
    args: AllowedUnusedHttpHostArgs,
) -> AllowedUnusedHttpHostFeedback {
    AllowedUnusedHttpHostFeedback {
        config_path,
        rule_name: args.rule,
        hosts: args.hosts,
    }
}

fn verified_exclude_feedback(
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

fn feedback(config_path: PathBuf, args: PatternFeedbackArgs) -> CasePathPatternFeedback {
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

fn print_pattern_report(report: &CasePathPatternReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout(), report)?;
            println!();
        }
        OutputFormat::Human => {
            println!("config: {}", report.config.display());
            println!("rule: {}", report.rule);
            println!("authority: {}", report.authority);
            println!("no_candidates: {}", report.no_candidates);
            println!("changed: {}", report.changed);
            println!("applied: {}", report.applied);
            println!("added: {}", report.added.len());
            println!("removed: {}", report.removed.len());
            println!(
                "corrections_already_absent: {}",
                report.corrections_already_absent.len()
            );
            if let Some(evidence) = &report.correction_evidence {
                println!("correction_evidence: {evidence}");
            }
            if !report.diff.is_empty() {
                print!("{}", report.diff);
            }
        }
    }
    Ok(())
}

fn print_allowed_unused_http_report(
    report: &AllowedUnusedHttpHostReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout(), report)?;
            println!();
        }
        OutputFormat::Human => {
            println!("config: {}", report.config.display());
            println!("rule: {}", report.rule);
            println!("changed: {}", report.changed);
            println!("applied: {}", report.applied);
            println!("added: {}", report.added.len());
            if !report.diff.is_empty() {
                print!("{}", report.diff);
            }
        }
    }
    Ok(())
}

fn print_background_dependency_report(
    report: &BackgroundDependencyReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout(), report)?;
            println!();
        }
        OutputFormat::Human => {
            println!("config: {}", report.config.display());
            println!("replay_report: {}", report.replay_report.display());
            println!("rule: {}", report.name);
            println!("protocol: {}", report.protocol);
            println!(
                "selector: {} {}{}",
                report.method, report.authority, report.path_prefix
            );
            println!("source_revision: {}", report.source_revision);
            println!("source_evidence: {}", report.source_evidence);
            println!(
                "matched_unused_exchanges: {}",
                report.matched_unused_exchanges
            );
            if !report.matched_case_ids.is_empty() {
                println!("matched_case_ids: {}", report.matched_case_ids.join(","));
            }
            println!("changed: {}", report.changed);
            println!("applied: {}", report.applied);
            if !report.diff.is_empty() {
                print!("{}", report.diff);
            }
        }
    }
    Ok(())
}

fn print_verified_exclude_report(
    report: &VerifiedApiExcludeReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout(), report)?;
            println!();
        }
        OutputFormat::Human => {
            println!("config: {}", report.config.display());
            println!("api: {} {}", report.method, report.path_pattern);
            println!("rule: {}", report.rule);
            println!(
                "consecutive_successful_runs: {}/{}",
                report.verification.consecutive_successful_runs,
                report.verification.required_consecutive_successful_runs
            );
            println!(
                "consecutive_successful_cases: {}/{}",
                report.verification.consecutive_successful_cases,
                report.verification.required_successful_cases
            );
            println!("eligible: {}", report.eligible);
            println!("changed: {}", report.changed);
            println!("applied: {}", report.applied);
            if !report.blockers.is_empty() {
                println!("blockers: {}", report.blockers.join(", "));
            }
            if !report.diff.is_empty() {
                print!("{}", report.diff);
            }
        }
    }
    Ok(())
}

fn print_verified_exclude_ensure_report(
    report: &VerifiedApiExcludeEnsureReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout(), report)?;
            println!();
        }
        OutputFormat::Human => {
            println!("status: {}", report.status);
            println!("config: {}", report.plan.config.display());
            println!("api: {} {}", report.plan.method, report.plan.path_pattern);
            println!("rule: {}", report.plan.rule);
            println!(
                "consecutive_successful_runs: {}/{}",
                report.plan.verification.consecutive_successful_runs,
                report
                    .plan
                    .verification
                    .required_consecutive_successful_runs
            );
            println!(
                "consecutive_successful_cases: {}/{}",
                report.plan.verification.consecutive_successful_cases,
                report.plan.verification.required_successful_cases
            );
            println!("initial_changed: {}", report.plan.changed);
            println!("apply_performed: {}", report.apply.is_some());
            if let Some(verification) = &report.verification {
                println!("verification_changed: {}", verification.changed);
            }
            if !report.plan.diff.is_empty() {
                print!("{}", report.plan.diff);
            }
        }
    }
    Ok(())
}
