use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    AllowedUnusedHttpHostFeedback, BackgroundDependencyFeedback,
    BreezeMemcachedBackgroundDependencyFeedback, BreezeResourceCaptureFeedback,
    CasePathPatternAuthority, CasePathPatternFeedback, MotanBackgroundDependencyFeedback,
    RecorderConfigInitOptions, initialize_recorder_config, plan_allowed_unused_http_hosts,
    plan_background_dependency, plan_breeze_memcached_background_dependency,
    plan_breeze_resource_capture, plan_case_path_pattern_feedback,
    plan_motan_background_dependency,
};

#[derive(Debug, Args)]
pub(super) struct RecorderArgs {
    #[command(subcommand)]
    command: RecorderCommand,
}

#[derive(Debug, Subcommand)]
enum RecorderCommand {
    /// Create a complete recorder template from source runtime facts.
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
    /// Candidate HTTP port initially served by the generated fixed-response project CLI.
    #[arg(long, default_value_t = 8081)]
    candidate_http_port: u16,
    /// Genuine application readiness path.
    #[arg(long = "readiness", default_value = "/healthz")]
    readiness_path: String,
    /// Exact final HTTP status proving application readiness.
    #[arg(long, default_value_t = 404)]
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
    BackgroundDependencies(Box<BackgroundDependencyArgs>),
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
    BackgroundDependencies(Box<BackgroundDependencyArgs>),
    BreezeResourceCapture(BreezeResourceCaptureArgs),
    CasePathPatterns(ApplyPatternFeedbackArgs),
}

#[derive(Debug, Args)]
struct AllowedUnusedHttpHostArgs {
    #[arg(long, default_value = traffic_e2e::DEFAULT_RECORDING_RULE)]
    rule: String,
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
struct BackgroundDependencyArgs {
    #[arg(long, value_enum, default_value_t = BackgroundProtocolArg::Http)]
    protocol: BackgroundProtocolArg,
    #[arg(long)]
    name: String,
    #[arg(long)]
    authority: Option<String>,
    #[arg(long)]
    method: Option<String>,
    #[arg(long)]
    path_prefix: Option<String>,
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    interface_name: Option<String>,
    #[arg(long)]
    method_name: Option<String>,
    #[arg(long)]
    breeze_resource: Option<String>,
    #[arg(long, default_value = "get")]
    command: String,
    #[arg(long)]
    key_start: Option<u32>,
    #[arg(long)]
    key_end: Option<u32>,
    #[arg(long, default_value = ".")]
    key_separator: String,
    #[arg(long)]
    key_suffix: Option<String>,
    #[arg(long, default_value_t = 60_000)]
    initial_load_timeout_ms: u64,
    #[arg(long)]
    replay_report: PathBuf,
    #[arg(long)]
    source_revision: String,
    #[arg(
        long,
        help = "Single-line source evidence proving process-level ownership and the protocol's required response relationship"
    )]
    evidence: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackgroundProtocolArg {
    Http,
    Memcached,
    Motan,
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
                candidate_http_port: args.candidate_http_port,
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
            plan_background_dependency_args(config, *args, false)
        }
        PlanStrategy::BreezeResourceCapture(args) => {
            let plan = plan_breeze_resource_capture(breeze_capture_feedback(config, args))?;
            super::print_json(plan.report())
        }
        PlanStrategy::CasePathPatterns(args) => {
            let plan = plan_case_path_pattern_feedback(pattern_feedback(config, args))?;
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
            plan_background_dependency_args(config, *args, true)
        }
        ApplyStrategy::BreezeResourceCapture(args) => {
            let report =
                plan_breeze_resource_capture(breeze_capture_feedback(config, args))?.apply()?;
            super::print_json(&report)
        }
        ApplyStrategy::CasePathPatterns(args) => {
            let report = plan_case_path_pattern_feedback(pattern_feedback(config, args.feedback))?
                .apply(args.allow_delete)?;
            super::print_json(&report)
        }
    }
}

fn breeze_capture_feedback(
    config_path: PathBuf,
    args: BreezeResourceCaptureArgs,
) -> BreezeResourceCaptureFeedback {
    BreezeResourceCaptureFeedback {
        config_path,
        resource: args.resource,
        source_revision: args.source_revision,
        source_evidence: args.evidence,
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

fn plan_background_dependency_args(
    config_path: PathBuf,
    args: BackgroundDependencyArgs,
    apply: bool,
) -> Result<()> {
    match args.protocol {
        BackgroundProtocolArg::Http => {
            let feedback = BackgroundDependencyFeedback {
                config_path,
                replay_report_path: args.replay_report,
                name: args.name,
                authority: required(args.authority, "--authority", "http")?,
                method: required(args.method, "--method", "http")?,
                path_prefix: required(args.path_prefix, "--path-prefix", "http")?,
                source_revision: args.source_revision,
                source_evidence: args.evidence,
            };
            let plan = plan_background_dependency(feedback)?;
            if apply {
                super::print_json(&plan.apply()?)
            } else {
                super::print_json(plan.report())
            }
        }
        BackgroundProtocolArg::Memcached => {
            let feedback = BreezeMemcachedBackgroundDependencyFeedback {
                config_path,
                replay_report_path: args.replay_report,
                name: args.name,
                breeze_resource: required(args.breeze_resource, "--breeze-resource", "memcached")?,
                command: args.command,
                key_start: required(args.key_start, "--key-start", "memcached")?,
                key_end: required(args.key_end, "--key-end", "memcached")?,
                key_separator: args.key_separator,
                key_suffix: required(args.key_suffix, "--key-suffix", "memcached")?,
                initial_load_timeout_ms: args.initial_load_timeout_ms,
                source_revision: args.source_revision,
                source_evidence: args.evidence,
            };
            let plan = plan_breeze_memcached_background_dependency(feedback)?;
            if apply {
                super::print_json(&plan.apply()?)
            } else {
                super::print_json(plan.report())
            }
        }
        BackgroundProtocolArg::Motan => {
            let feedback = MotanBackgroundDependencyFeedback {
                config_path,
                replay_report_path: args.replay_report,
                name: args.name,
                group: required(args.group, "--group", "motan")?,
                interface_name: required(args.interface_name, "--interface-name", "motan")?,
                method_name: required(args.method_name, "--method-name", "motan")?,
                source_revision: args.source_revision,
                source_evidence: args.evidence,
            };
            let plan = plan_motan_background_dependency(feedback)?;
            if apply {
                super::print_json(&plan.apply()?)
            } else {
                super::print_json(plan.report())
            }
        }
    }
}

fn required<T>(value: Option<T>, flag: &str, protocol: &str) -> Result<T> {
    value.ok_or_else(|| anyhow!("{flag} is required for --protocol {protocol}"))
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        init: InitArgs,
    }

    #[derive(Parser)]
    struct BackgroundTestCli {
        #[command(flatten)]
        background: BackgroundDependencyArgs,
    }

    #[test]
    fn defaults_readiness_and_accepts_explicit_overrides() {
        let defaults = TestCli::try_parse_from([
            "test",
            "--source-http-port",
            "8080",
            "--upstream-dns",
            "10.10.10.10:53",
        ])
        .unwrap();
        assert_eq!(defaults.init.readiness_path, "/healthz");
        assert_eq!(defaults.init.readiness_status, 404);
        assert_eq!(defaults.init.candidate_http_port, 8081);

        let explicit = TestCli::try_parse_from([
            "test",
            "--source-http-port",
            "8080",
            "--candidate-http-port",
            "8181",
            "--readiness",
            "/ready",
            "--readiness-status",
            "200",
            "--upstream-dns",
            "10.10.10.10:53",
        ])
        .unwrap();
        assert_eq!(explicit.init.readiness_path, "/ready");
        assert_eq!(explicit.init.readiness_status, 200);
        assert_eq!(explicit.init.candidate_http_port, 8181);
    }

    #[test]
    fn accepts_exact_motan_background_selector() {
        let parsed = BackgroundTestCli::try_parse_from([
            "test",
            "--protocol",
            "motan",
            "--name",
            "kunpeng-refresh",
            "--group",
            "kunpeng-config-rpc",
            "--interface-name",
            "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc",
            "--method-name",
            "getConfigByName",
            "--replay-report",
            "replay-report.json",
            "--source-revision",
            "0123456789abcdef",
            "--evidence",
            "MapiConfigLoader.java:init scheduled refresh",
        ])
        .unwrap();

        assert!(matches!(
            parsed.background.protocol,
            BackgroundProtocolArg::Motan
        ));
        assert_eq!(
            parsed.background.group.as_deref(),
            Some("kunpeng-config-rpc")
        );
        assert_eq!(
            parsed.background.interface_name.as_deref(),
            Some("com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc")
        );
        assert_eq!(
            parsed.background.method_name.as_deref(),
            Some("getConfigByName")
        );
    }
}
