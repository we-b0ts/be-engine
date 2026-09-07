use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    RedisKeyPatternConfig, RewriteContext, RewriteDependencyOwnership,
    RewriteDependencyPayloadRulePlanOptions, RewriteDependencyRulePlanOptions,
    RewriteDependencyRuleSelector, apply_rewrite_dependency_rule,
    plan_rewrite_dependency_payload_rule, plan_rewrite_dependency_rule,
};

#[derive(Debug, Args)]
pub(super) struct DependencyRuleArgs {
    #[command(subcommand)]
    command: DependencyRuleCommand,
}

#[derive(Debug, Subcommand)]
enum DependencyRuleCommand {
    /// Classify current evidence and preview a rule only when process-owned.
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
    /// Validate a source-generated time value in a MySQL SQL template across text/prepared protocols.
    MysqlTime(Box<MysqlTimeArgs>),
    /// Classify source-proven MySQL reads using bounded tables and a SELECT template.
    Mysql(Box<MysqlDependencyRuleArgs>),
    /// Classify an HTTP dependency using an exact selector.
    Http(HttpDependencyRuleArgs),
    /// Plan a Memcached dependency rule.
    Memcached(MemcachedDependencyRuleArgs),
    /// Classify a Motan dependency using an exact selector.
    Motan(MotanDependencyRuleArgs),
    /// Classify a Redis dependency using a command-specific selector.
    Redis(RedisDependencyRuleArgs),
}

#[derive(Debug, Args)]
struct MysqlTimeArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    rule_id: String,
    /// Optional endpoint filter for evidence lookup; not written to the rule.
    #[arg(long, default_value = "")]
    target_host: String,
    #[arg(long, default_value_t = 3306)]
    target_port: u16,
    #[arg(long)]
    database: String,
    /// Optional user filter for evidence lookup; not written to the rule.
    #[arg(long, default_value = "")]
    username: String,
    /// SQL template: each ? represents one scalar value; other tokens stay exact.
    #[arg(long)]
    sql: String,
    /// Zero-based ? slot in the SQL template, independent of wire parameter positions.
    #[arg(long)]
    value_index: usize,
    #[arg(long, default_value = "5s")]
    tolerance: String,
    #[arg(long, default_value = "0s")]
    offset: String,
    #[arg(long, default_value = "%Y-%m-%d %H:%M:%S%.f")]
    format: String,
    #[arg(long, default_value = "+00:00")]
    timezone: String,
    /// Source file/symbol proving how this field obtains the current time.
    #[arg(long)]
    source_evidence: String,
}

#[derive(Debug, Args)]
struct DependencyRuleCommonArgs {
    /// Coordinator-issued evidence id returned by the applicable rule planner.
    #[arg(long)]
    evidence_id: String,
    /// Required ownership decision for the recorded dependency.
    #[arg(long, value_enum)]
    ownership: DependencyOwnershipArg,
    /// Stable recorder rule name; required only for process-owned dependencies.
    #[arg(long, required_if_eq("ownership", "process-owned"))]
    name: Option<String>,
    /// Source file/symbol proof; required for process-owned and request-owned dependencies.
    #[arg(
        long,
        required_if_eq_any([
            ("ownership", "process-owned"),
            ("ownership", "request-owned")
        ])
    )]
    source_evidence: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DependencyOwnershipArg {
    ProcessOwned,
    RequestOwned,
    Unresolved,
}

impl From<DependencyOwnershipArg> for RewriteDependencyOwnership {
    fn from(value: DependencyOwnershipArg) -> Self {
        match value {
            DependencyOwnershipArg::ProcessOwned => Self::ProcessOwned,
            DependencyOwnershipArg::RequestOwned => Self::RequestOwned,
            DependencyOwnershipArg::Unresolved => Self::Unresolved,
        }
    }
}

#[derive(Debug, Args)]
struct MysqlDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long)]
    target_host: String,
    #[arg(long, default_value_t = 3306)]
    target_port: u16,
    #[arg(long)]
    database: String,
    #[arg(long)]
    username: String,
    #[arg(
        long,
        help = "Single SELECT with {{table}}, AS {{table}}_suffix aliases and ? for variable literals"
    )]
    sql: String,
    #[arg(long = "table")]
    tables: Vec<String>,
    /// Table identifier pattern with one *, e.g. subtasks_* or *_archive. Repeatable.
    #[arg(long = "table-pattern")]
    table_patterns: Vec<String>,
    #[arg(long, requires_all = ["table_start", "table_end"])]
    table_prefix: Option<String>,
    #[arg(long, requires = "table_prefix")]
    table_start: Option<u32>,
    #[arg(long, requires = "table_prefix")]
    table_end: Option<u32>,
    #[arg(long, default_value_t = 4)]
    table_width: usize,
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
    #[command(subcommand)]
    mode: MemcachedDependencyRuleModeArgs,
}

#[derive(Debug, Subcommand)]
enum MemcachedDependencyRuleModeArgs {
    /// Classify a Breeze-backed Memcached GET dependency.
    Get(MemcachedGetDependencyRuleArgs),
    /// Normalize a source-generated protobuf Unix timestamp inside a Memcached SET value.
    ProtobufTimestamp(MemcachedProtobufTimestampRuleArgs),
}

#[derive(Debug, Args)]
struct MemcachedGetDependencyRuleArgs {
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
struct MemcachedProtobufTimestampRuleArgs {
    /// Coordinator-issued dirty-cluster evidence id describing a Memcached SET.
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    rule_id: String,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    key_prefix: String,
    #[arg(long, default_value = "")]
    key_suffix: String,
    #[arg(long)]
    field_number: u32,
    /// Source file/symbol proof that the selected protobuf field is Unix seconds.
    #[arg(long)]
    source_evidence: String,
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
    /// Redis ZCOUNT dependency selected by key affixes.
    Zcount(RedisZcountDependencyRuleArgs),
    /// Redis GET dependency selected by exact keys.
    Get(RedisExactKeyDependencyRuleArgs),
    /// Redis SCARD dependency selected by exact keys.
    Scard(RedisExactKeyDependencyRuleArgs),
    /// Redis HGETALL dependency selected by exact keys.
    Hgetall(RedisExactKeyDependencyRuleArgs),
    /// Bootstrap Redis HGET traffic selected by compact key shapes and an exact field.
    Hget(RedisHashReadDependencyRuleArgs),
    /// Bootstrap Redis HMGET traffic selected by compact key shapes and exact fields.
    Hmget(RedisHashReadDependencyRuleArgs),
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
struct RedisHashReadDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long = "port", required = true)]
    ports: Vec<u16>,
    /// Optional exact Redis key; repeat for each exceptional key.
    #[arg(long = "key")]
    keys: Vec<String>,
    /// Key shape containing one `<id>` numeric segment, for example `exp:list:<id>`.
    #[arg(long = "numeric-key-pattern")]
    key_patterns: Vec<String>,
    /// Exact HGET/HMGET field in wire order.
    #[arg(long = "field", required = true)]
    fields: Vec<String>,
}

#[derive(Debug, Args)]
struct DependencyRuleApplyArgs {
    plan_id: String,
}

pub(super) fn run(target_root: PathBuf, args: DependencyRuleArgs, pretty: bool) -> Result<()> {
    match args.command {
        DependencyRuleCommand::Plan(args) => match DependencyPlan::try_from(args.protocol)? {
            DependencyPlan::Ownership(options) => super::print_json(
                &plan_rewrite_dependency_rule(RewriteContext { target_root }, options)?,
                pretty,
            ),
            DependencyPlan::Payload(options) => super::print_json(
                &plan_rewrite_dependency_payload_rule(RewriteContext { target_root }, options)?,
                pretty,
            ),
        },
        DependencyRuleCommand::Apply(args) => super::print_json(
            &apply_rewrite_dependency_rule(RewriteContext { target_root }, &args.plan_id)?,
            pretty,
        ),
    }
}

enum DependencyPlan {
    Ownership(RewriteDependencyRulePlanOptions),
    Payload(RewriteDependencyPayloadRulePlanOptions),
}

impl TryFrom<DependencyRuleProtocolArgs> for DependencyPlan {
    type Error = anyhow::Error;

    fn try_from(value: DependencyRuleProtocolArgs) -> Result<Self> {
        Ok(Self::Ownership(match value {
            DependencyRuleProtocolArgs::MysqlTime(args) => RewriteDependencyRulePlanOptions {
                evidence_id: args.evidence_id,
                ownership: RewriteDependencyOwnership::RequestOwned,
                name: Some(args.rule_id),
                source_evidence: Some(args.source_evidence),
                selector: RewriteDependencyRuleSelector::MysqlSqlTime {
                    selector: traffic_e2e::MysqlTimeSelector {
                        target_host: args.target_host,
                        target_port: args.target_port,
                        database: args.database,
                        username: args.username,
                        sql: args.sql,
                        value_index: args.value_index,
                        tolerance: args.tolerance,
                        offset: args.offset,
                        format: args.format,
                        timezone: args.timezone,
                    },
                },
            },
            DependencyRuleProtocolArgs::Mysql(args) => {
                let table_series =
                    args.table_prefix
                        .map(|prefix| traffic_e2e::MysqlBackgroundTableSeries {
                            prefix,
                            start: args.table_start.expect("clap requires table-start"),
                            end: args.table_end.expect("clap requires table-end"),
                            width: args.table_width,
                        });
                dependency_rule_options(
                    args.common,
                    RewriteDependencyRuleSelector::Mysql {
                        selector: traffic_e2e::MysqlBackgroundSelector {
                            target_host: args.target_host,
                            target_port: args.target_port,
                            database: args.database,
                            username: args.username,
                            sql: args.sql,
                            tables: args.tables,
                            table_patterns: args.table_patterns,
                            table_series,
                        },
                    },
                )
            }
            DependencyRuleProtocolArgs::Http(args) => dependency_rule_options(
                args.common,
                RewriteDependencyRuleSelector::Http {
                    authority: args.authority,
                    method: args.method,
                    path_prefix: args.path_prefix,
                },
            ),
            DependencyRuleProtocolArgs::Memcached(args) => match args.mode {
                MemcachedDependencyRuleModeArgs::Get(args) => dependency_rule_options(
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
                MemcachedDependencyRuleModeArgs::ProtobufTimestamp(args) => {
                    return Ok(Self::Payload(RewriteDependencyPayloadRulePlanOptions {
                        evidence_id: args.evidence_id,
                        rule_id: args.rule_id,
                        port: args.port,
                        key_prefix: args.key_prefix,
                        key_suffix: args.key_suffix,
                        field_number: args.field_number,
                        source_evidence: args.source_evidence,
                    }));
                }
            },
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
                RedisDependencyRuleModeArgs::Hget(args) => redis_hash_options("HGET", args)?,
                RedisDependencyRuleModeArgs::Hmget(args) => redis_hash_options("HMGET", args)?,
            },
        }))
    }
}

fn redis_hash_options(
    command: &str,
    args: RedisHashReadDependencyRuleArgs,
) -> Result<RewriteDependencyRulePlanOptions> {
    ensure!(
        !args.keys.is_empty() || !args.key_patterns.is_empty(),
        "Redis {command} requires at least one --key or --numeric-key-pattern"
    );
    ensure!(
        command != "HGET" || args.fields.len() == 1,
        "Redis HGET requires exactly one --field"
    );
    let patterns = args
        .key_patterns
        .into_iter()
        .map(|pattern| parse_numeric_key_pattern(command, &pattern))
        .collect::<Result<Vec<_>>>()?;
    Ok(dependency_rule_options(
        args.common,
        RewriteDependencyRuleSelector::RedisHashRead {
            command: command.to_string(),
            ports: args.ports,
            keys: args.keys,
            key_patterns: patterns,
            fields: args.fields,
        },
    ))
}

fn parse_numeric_key_pattern(command: &str, value: &str) -> Result<RedisKeyPatternConfig> {
    ensure!(
        value.matches("<id>").count() == 1,
        "Redis {command} --numeric-key-pattern must contain exactly one <id> segment"
    );
    let (prefix, suffix) = value
        .split_once("<id>")
        .expect("validated pattern contains the marker");
    Ok(RedisKeyPatternConfig {
        prefix: prefix.to_string(),
        suffix: suffix.to_string(),
        numeric_middle: true,
    })
}

fn dependency_rule_options(
    common: DependencyRuleCommonArgs,
    selector: RewriteDependencyRuleSelector,
) -> RewriteDependencyRulePlanOptions {
    RewriteDependencyRulePlanOptions {
        evidence_id: common.evidence_id,
        ownership: common.ownership.into(),
        name: common.name,
        source_evidence: common.source_evidence,
        selector,
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        dependency_rule: DependencyRuleArgs,
    }

    #[test]
    fn mysql_time_cli_plans_request_owned_values_without_ownership_reclassification() {
        let parsed = TestCli::try_parse_from([
            "test",
            "plan",
            "mysql-time",
            "--evidence-id",
            "current",
            "--rule-id",
            "last-used",
            "--database",
            "app",
            "--sql",
            "UPDATE api_keys SET last_used_at=? WHERE id=?",
            "--value-index",
            "0",
            "--source-evidence",
            "security.py:auth assigns datetime.utcnow()",
        ])
        .unwrap();
        let DependencyRuleCommand::Plan(plan) = parsed.dependency_rule.command else {
            panic!("expected plan")
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("expected value plan")
        };
        assert_eq!(options.ownership, RewriteDependencyOwnership::RequestOwned);
        let RewriteDependencyRuleSelector::MysqlSqlTime { selector } = options.selector else {
            panic!("expected MySQL time")
        };
        assert!(selector.target_host.is_empty());
        assert!(selector.username.is_empty());
        assert_eq!(selector.value_index, 0);
        assert_eq!(selector.tolerance, "5s");
        assert_eq!(selector.timezone, "+00:00");
    }

    #[test]
    fn ownership_is_required() {
        let error = TestCli::try_parse_from([
            "test",
            "plan",
            "motan",
            "--evidence-id",
            "evidence-dirty-clusters",
            "--group",
            "yf-tkv-rpc",
            "--interface-name",
            "com.weibo.api.mcq.rpc.KafkaService",
            "--method-name",
            "sender",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("--ownership"));
    }

    #[test]
    fn request_owned_does_not_require_a_rule_name() {
        let parsed = TestCli::try_parse_from([
            "test",
            "plan",
            "motan",
            "--evidence-id",
            "evidence-dirty-clusters",
            "--ownership",
            "request-owned",
            "--source-evidence",
            "TrafficProcessorImpl.java:onCompletion audit sender",
            "--group",
            "yf-tkv-rpc",
            "--interface-name",
            "com.weibo.api.mcq.rpc.KafkaService",
            "--method-name",
            "sender",
        ])
        .unwrap();
        let DependencyRuleCommand::Plan(plan) = parsed.dependency_rule.command else {
            panic!("expected plan command")
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("expected ownership plan")
        };

        assert_eq!(options.ownership, RewriteDependencyOwnership::RequestOwned);
        assert!(options.name.is_none());
    }

    #[test]
    fn process_owned_requires_a_rule_name() {
        let error = TestCli::try_parse_from([
            "test",
            "plan",
            "motan",
            "--evidence-id",
            "evidence-dirty-clusters",
            "--ownership",
            "process-owned",
            "--source-evidence",
            "MapiConfigLoader.java:init scheduled refresh",
            "--group",
            "kunpeng-config-rpc",
            "--interface-name",
            "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc",
            "--method-name",
            "getConfigByName",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("--name"));
    }

    #[test]
    fn unresolved_requires_neither_rule_name_nor_source_evidence() {
        TestCli::try_parse_from([
            "test",
            "plan",
            "motan",
            "--evidence-id",
            "evidence-dirty-clusters",
            "--ownership",
            "unresolved",
            "--group",
            "yf-tkv-rpc",
            "--interface-name",
            "com.weibo.api.mcq.rpc.KafkaService",
            "--method-name",
            "sender",
        ])
        .unwrap();
    }

    #[test]
    fn mysql_cli_requires_bounded_table_series_and_preserves_alias_template() {
        let base = [
            "test",
            "plan",
            "mysql",
            "--evidence-id",
            "evidence-dirty-clusters",
            "--ownership",
            "process-owned",
            "--name",
            "video-recovery",
            "--source-evidence",
            "src/recovery.py:run startup scan",
            "--target-host",
            "db.internal",
            "--database",
            "app",
            "--username",
            "user",
            "--sql",
            "SELECT {{table}}.id AS {{table}}_id FROM {{table}} WHERE status='RUNNING'",
            "--table-prefix",
            "subtasks_",
            "--table-start",
            "0",
        ];
        let error = TestCli::try_parse_from(base).unwrap_err();
        assert!(error.to_string().contains("--table-end"));
        let parsed =
            TestCli::try_parse_from(base.into_iter().chain(["--table-end", "1023"])).unwrap();
        let DependencyRuleCommand::Plan(plan) = parsed.dependency_rule.command else {
            panic!("expected plan");
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("expected ownership");
        };
        let RewriteDependencyRuleSelector::Mysql { selector } = options.selector else {
            panic!("expected mysql selector");
        };
        assert_eq!(options.ownership, RewriteDependencyOwnership::ProcessOwned);
        assert_eq!(selector.target_port, 3306);
        assert_eq!(selector.sql, base[18]);
        let series = selector.table_series.unwrap();
        assert_eq!((series.start, series.end, series.width), (0, 1023, 4));

        let parsed = TestCli::try_parse_from(base[..19].iter().copied().chain([
            "--table-pattern",
            "subtasks_*",
            "--table-pattern",
            "*_archive",
        ]))
        .unwrap();
        let DependencyRuleCommand::Plan(plan) = parsed.dependency_rule.command else {
            panic!("expected plan");
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("expected ownership");
        };
        let RewriteDependencyRuleSelector::Mysql { selector } = options.selector else {
            panic!("expected mysql");
        };
        assert_eq!(selector.table_patterns, ["subtasks_*", "*_archive"]);
        assert!(selector.tables.is_empty() && selector.table_series.is_none());
    }
}
