use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    AllowedUnusedHttpHostFeedback, BackgroundDependencyFeedback, BackgroundDependencyResponseRole,
    BreezeMemcachedBackgroundDependencyFeedback, BreezeResourceCaptureFeedback,
    CasePathPatternAuthority, CasePathPatternFeedback, E2eRunContext,
    MotanBackgroundDependencyFeedback, RedisBackgroundDependencyFeedback,
    plan_allowed_unused_http_hosts, plan_background_dependency,
    plan_breeze_memcached_background_dependency, plan_breeze_resource_capture,
    plan_case_path_pattern_feedback, plan_motan_background_dependency,
    plan_redis_background_dependency, resolve_e2e_response_rule_evidence,
};

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
    #[arg(long = "port")]
    ports: Vec<u16>,
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
    key_start: Option<u64>,
    #[arg(long)]
    key_end: Option<u64>,
    #[arg(long = "key")]
    keys: Vec<String>,
    #[arg(long, default_value = ".")]
    key_separator: String,
    #[arg(long)]
    key_suffix: Option<String>,
    #[arg(long)]
    key_prefix: Option<String>,
    #[arg(long, default_value_t = 60_000)]
    initial_load_timeout_ms: u64,
    #[arg(long, value_enum, default_value_t = BackgroundResponseRoleArg::Independent)]
    response_role: BackgroundResponseRoleArg,
    /// Exact finalized replay case source; replay evidence is resolved internally.
    #[arg(long)]
    case_source: PathBuf,
    /// Exact canonical API group whose focused replay evidence authorizes the rule.
    #[arg(long)]
    api: String,
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
    Redis,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackgroundResponseRoleArg {
    Independent,
    RuntimeState,
}

impl From<BackgroundResponseRoleArg> for BackgroundDependencyResponseRole {
    fn from(value: BackgroundResponseRoleArg) -> Self {
        match value {
            BackgroundResponseRoleArg::Independent => Self::Independent,
            BackgroundResponseRoleArg::RuntimeState => Self::RuntimeState,
        }
    }
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
            plan_background_dependency_args(target_root, config, *args, false)
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
            plan_background_dependency_args(target_root, config, *args, true)
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
    target_root: PathBuf,
    config_path: PathBuf,
    args: BackgroundDependencyArgs,
    apply: bool,
) -> Result<()> {
    let replay_report = resolve_e2e_response_rule_evidence(
        E2eRunContext {
            target_root,
            case_source: args.case_source,
            run_key: None,
        },
        &args.api,
    )?
    .replay;
    match args.protocol {
        BackgroundProtocolArg::Http => {
            let feedback = BackgroundDependencyFeedback {
                config_path,
                replay_report_path: replay_report,
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
                replay_report_path: replay_report,
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
                replay_report_path: replay_report,
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
        BackgroundProtocolArg::Redis => {
            let response_role = args.response_role.into();
            let (key_prefix, key_suffix, initial_load_timeout_ms) = match response_role {
                BackgroundDependencyResponseRole::Independent => (
                    required(args.key_prefix, "--key-prefix", "redis")?,
                    required(args.key_suffix, "--key-suffix", "redis")?,
                    None,
                ),
                BackgroundDependencyResponseRole::RuntimeState => (
                    args.key_prefix.unwrap_or_default(),
                    args.key_suffix.unwrap_or_default(),
                    Some(args.initial_load_timeout_ms),
                ),
            };
            let feedback = RedisBackgroundDependencyFeedback {
                config_path,
                replay_report_path: replay_report,
                name: args.name,
                ports: required_nonempty(args.ports, "--port", "redis")?,
                command: args.command,
                keys: args.keys,
                key_prefix,
                key_suffix,
                initial_load_timeout_ms,
                response_role,
                source_revision: args.source_revision,
                source_evidence: args.evidence,
            };
            let plan = plan_redis_background_dependency(feedback)?;
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

fn required_nonempty<T>(values: Vec<T>, flag: &str, protocol: &str) -> Result<Vec<T>> {
    if values.is_empty() {
        return Err(anyhow!(
            "at least one {flag} is required for --protocol {protocol}"
        ));
    }
    Ok(values)
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
    struct BackgroundTestCli {
        #[command(flatten)]
        background: BackgroundDependencyArgs,
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
            "--case-source",
            "/cases/run",
            "--api",
            "GET /api",
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

    #[test]
    fn accepts_port_scoped_redis_background_selector() {
        let parsed = BackgroundTestCli::try_parse_from([
            "test",
            "--protocol",
            "redis",
            "--name",
            "interest-tag-mining-cache-refresh",
            "--port",
            "20917",
            "--port",
            "20918",
            "--command",
            "ZCOUNT",
            "--key-prefix",
            "1042015:",
            "--key-suffix",
            ".wtm2",
            "--case-source",
            "/cases/run",
            "--api",
            "GET /api",
            "--source-revision",
            "0123456789abcdef",
            "--evidence",
            "InterestTagCardServiceImpl.java:init scheduled refresh",
        ])
        .unwrap();

        assert!(matches!(
            parsed.background.protocol,
            BackgroundProtocolArg::Redis
        ));
        assert_eq!(parsed.background.ports, [20917, 20918]);
        assert_eq!(parsed.background.key_prefix.as_deref(), Some("1042015:"));
        assert_eq!(parsed.background.key_suffix.as_deref(), Some(".wtm2"));
    }

    #[test]
    fn accepts_runtime_state_redis_exact_keys_and_u64_memcached_bounds() {
        let redis = BackgroundTestCli::try_parse_from([
            "test",
            "--protocol",
            "redis",
            "--name",
            "startup-cache-warm",
            "--port",
            "20917",
            "--command",
            "GET",
            "--key",
            "cache:init:a",
            "--key",
            "cache:init:b",
            "--response-role",
            "runtime-state",
            "--initial-load-timeout-ms",
            "30000",
            "--case-source",
            "/cases/run",
            "--api",
            "GET /api/example",
            "--source-revision",
            "0123456789abcdef",
            "--evidence",
            "src/cache/warm.rs:init loads response-driving local state",
        ])
        .unwrap();
        assert!(matches!(
            redis.background.response_role,
            BackgroundResponseRoleArg::RuntimeState
        ));
        assert_eq!(redis.background.keys, ["cache:init:a", "cache:init:b"]);

        let memcached = BackgroundTestCli::try_parse_from([
            "test",
            "--protocol",
            "memcached",
            "--name",
            "profile-warm",
            "--breeze-resource",
            "user-profile",
            "--key-start",
            "5000000000",
            "--key-end",
            "5000000000",
            "--key-suffix",
            "profile",
            "--case-source",
            "/cases/run",
            "--api",
            "GET /api/example",
            "--source-revision",
            "0123456789abcdef",
            "--evidence",
            "src/profile/cache.rs:warm reads the profile cache",
        ])
        .unwrap();
        assert_eq!(memcached.background.key_start, Some(5_000_000_000));
        assert_eq!(memcached.background.key_end, Some(5_000_000_000));
    }
}
