use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    RewriteContext, RewriteDependencyRulePlanOptions, RewriteDependencyRuleSelector,
    apply_rewrite_dependency_rule, plan_rewrite_dependency_rule,
};

#[derive(Debug, Args)]
pub(super) struct DependencyRuleArgs {
    #[command(subcommand)]
    command: DependencyRuleCommand,
}

#[derive(Debug, Subcommand)]
enum DependencyRuleCommand {
    /// Validate current dirty-cluster evidence and preview one recorder rule.
    Plan(DependencyRulePlanArgs),
    /// Atomically apply the persisted, evidence-validated pending plan.
    Apply(DependencyRuleApplyArgs),
}

#[derive(Debug, Args)]
struct DependencyRulePlanArgs {
    #[command(subcommand)]
    protocol: DependencyRuleProtocolArgs,
}

#[derive(Debug, Subcommand)]
enum DependencyRuleProtocolArgs {
    /// Process-owned HTTP traffic unrelated to one case.
    Http(HttpDependencyRuleArgs),
    /// Process-owned Breeze-backed Memcached get traffic.
    Memcached(MemcachedDependencyRuleArgs),
    /// Process-owned Motan traffic unrelated to one case.
    Motan(MotanDependencyRuleArgs),
    /// Process-owned Redis traffic.
    Redis(RedisDependencyRuleArgs),
}

#[derive(Debug, Args)]
struct DependencyRuleCommonArgs {
    /// Current dirty-clusters evidence id returned by rewrite evidence.
    #[arg(long)]
    evidence_id: String,
    /// Stable recorder rule name.
    #[arg(long)]
    name: String,
    /// Single-line source file/symbol proof of process ownership and response relationship.
    #[arg(long)]
    source_evidence: String,
}

#[derive(Debug, Args)]
struct HttpDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long)]
    authority: String,
    #[arg(long)]
    method: String,
    #[arg(long)]
    path_prefix: String,
}

#[derive(Debug, Args)]
struct MemcachedDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    /// Breeze business namespace, for example `user-video`.
    #[arg(long)]
    breeze_resource: String,
    #[arg(long)]
    key_start: u64,
    #[arg(long)]
    key_end: u64,
    #[arg(long, default_value = ".")]
    key_separator: String,
    #[arg(long)]
    key_suffix: String,
    #[arg(long, default_value_t = 60_000)]
    initial_load_timeout_ms: u64,
}

#[derive(Debug, Args)]
struct MotanDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long)]
    group: String,
    #[arg(long)]
    interface_name: String,
    #[arg(long)]
    method_name: String,
}

#[derive(Debug, Args)]
struct RedisDependencyRuleArgs {
    #[command(subcommand)]
    mode: RedisDependencyRuleModeArgs,
}

#[derive(Debug, Subcommand)]
enum RedisDependencyRuleModeArgs {
    /// Process-owned Redis ZCOUNT traffic selected by key affixes.
    Zcount(RedisZcountDependencyRuleArgs),
    /// Process-owned Redis GET traffic selected by exact keys.
    Get(RedisExactKeyDependencyRuleArgs),
    /// Process-owned Redis SCARD traffic selected by exact keys.
    Scard(RedisExactKeyDependencyRuleArgs),
    /// Process-owned Redis HGETALL traffic selected by exact keys.
    Hgetall(RedisExactKeyDependencyRuleArgs),
}

#[derive(Debug, Args)]
struct RedisZcountDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long = "port", required = true)]
    ports: Vec<u16>,
    #[arg(long)]
    key_prefix: String,
    #[arg(long)]
    key_suffix: String,
}

#[derive(Debug, Args)]
struct RedisExactKeyDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long = "port", required = true)]
    ports: Vec<u16>,
    #[arg(long = "key", required = true)]
    keys: Vec<String>,
    #[arg(long, default_value_t = 60_000)]
    initial_load_timeout_ms: u64,
}

#[derive(Debug, Args)]
struct DependencyRuleApplyArgs {
    plan_id: String,
}

pub(super) fn run(target_root: PathBuf, args: DependencyRuleArgs, pretty: bool) -> Result<()> {
    match args.command {
        DependencyRuleCommand::Plan(args) => super::print_json(
            &plan_rewrite_dependency_rule(RewriteContext { target_root }, args.protocol.into())?,
            pretty,
        ),
        DependencyRuleCommand::Apply(args) => super::print_json(
            &apply_rewrite_dependency_rule(RewriteContext { target_root }, &args.plan_id)?,
            pretty,
        ),
    }
}

impl From<DependencyRuleProtocolArgs> for RewriteDependencyRulePlanOptions {
    fn from(value: DependencyRuleProtocolArgs) -> Self {
        match value {
            DependencyRuleProtocolArgs::Http(args) => dependency_rule_options(
                args.common,
                RewriteDependencyRuleSelector::Http {
                    authority: args.authority,
                    method: args.method,
                    path_prefix: args.path_prefix,
                },
            ),
            DependencyRuleProtocolArgs::Memcached(args) => dependency_rule_options(
                args.common,
                RewriteDependencyRuleSelector::Memcached {
                    breeze_resource: args.breeze_resource,
                    command: "get".to_string(),
                    key_start: args.key_start,
                    key_end: args.key_end,
                    key_separator: args.key_separator,
                    key_suffix: args.key_suffix,
                    initial_load_timeout_ms: args.initial_load_timeout_ms,
                },
            ),
            DependencyRuleProtocolArgs::Motan(args) => dependency_rule_options(
                args.common,
                RewriteDependencyRuleSelector::Motan {
                    group: args.group,
                    interface_name: args.interface_name,
                    method_name: args.method_name,
                },
            ),
            DependencyRuleProtocolArgs::Redis(args) => match args.mode {
                RedisDependencyRuleModeArgs::Zcount(args) => dependency_rule_options(
                    args.common,
                    RewriteDependencyRuleSelector::RedisZcount {
                        ports: args.ports,
                        key_prefix: args.key_prefix,
                        key_suffix: args.key_suffix,
                    },
                ),
                RedisDependencyRuleModeArgs::Get(args) => dependency_rule_options(
                    args.common,
                    RewriteDependencyRuleSelector::RedisGet {
                        ports: args.ports,
                        keys: args.keys,
                        initial_load_timeout_ms: args.initial_load_timeout_ms,
                    },
                ),
                RedisDependencyRuleModeArgs::Scard(args) => dependency_rule_options(
                    args.common,
                    RewriteDependencyRuleSelector::RedisScard {
                        ports: args.ports,
                        keys: args.keys,
                        initial_load_timeout_ms: args.initial_load_timeout_ms,
                    },
                ),
                RedisDependencyRuleModeArgs::Hgetall(args) => dependency_rule_options(
                    args.common,
                    RewriteDependencyRuleSelector::RedisHgetall {
                        ports: args.ports,
                        keys: args.keys,
                        initial_load_timeout_ms: args.initial_load_timeout_ms,
                    },
                ),
            },
        }
    }
}

fn dependency_rule_options(
    common: DependencyRuleCommonArgs,
    selector: RewriteDependencyRuleSelector,
) -> RewriteDependencyRulePlanOptions {
    RewriteDependencyRulePlanOptions {
        evidence_id: common.evidence_id,
        name: common.name,
        source_evidence: common.source_evidence,
        selector,
    }
}
