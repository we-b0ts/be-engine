mod redis;
use redis::RedisDependencyRuleArgs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
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
    /// Preview an evidence-backed ownership, value or cross-case scope rule.
    Plan(Box<DependencyRulePlanArgs>),
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
    /// Classify HTTP ownership or plan cross-case replay scope.
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
    #[arg(long, required_unless_present = "time_values")]
    value_index: Option<usize>,
    /// Optional exact JSON Pointer when the legacy value slot contains a JSON document.
    #[arg(long, requires = "value_index")]
    json_pointer: Option<String>,
    #[arg(long)]
    tolerance: Option<String>,
    #[arg(long)]
    offset: Option<String>,
    #[arg(long)]
    format: Option<String>,
    #[arg(long)]
    timezone: Option<String>,
    /// Repeatable JSON time location with value_index, optional json_pointer and time options.
    #[arg(long = "time-value", value_name = "JSON", value_parser = parse_mysql_time_value)]
    time_values: Vec<traffic_e2e::MysqlTimeValueSelector>,
    /// Source file/symbol proving how this field obtains the current time.
    #[arg(long)]
    source_evidence: String,
}

fn parse_mysql_time_value(
    value: &str,
) -> std::result::Result<traffic_e2e::MysqlTimeValueSelector, String> {
    serde_json::from_str(value).map_err(|error| format!("invalid MySQL time value JSON: {error}"))
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
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct HttpDependencyRuleArgs {
    #[command(subcommand)]
    mode: Option<HttpDependencyMode>,
    #[arg(long, required = true)]
    evidence_id: Option<String>,
    #[arg(long, value_enum, required = true)]
    ownership: Option<DependencyOwnershipArg>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    source_evidence: Option<String>,
    #[arg(long, required = true)]
    authority: Option<String>,
    #[arg(long, required = true)]
    method: Option<String>,
    #[arg(long, required = true)]
    path_prefix: Option<String>,
}

#[derive(Debug, Subcommand)]
enum HttpDependencyMode {
    /// Share finite, exactly matched HTTP exchanges across cases of one recording run.
    CrossCase(HttpRequestRuleArgs),
    /// Compare source-proven HTTP request JSON arrays without element-order constraints.
    Unordered(HttpUnorderedArgs),
}

#[derive(Debug, Args)]
struct HttpRequestRuleArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    rule_id: String,
    #[arg(long)]
    host: String,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    method: String,
    #[arg(long)]
    path: String,
    /// Source file/symbol proving the selected dependency rule semantics.
    #[arg(long)]
    source_evidence: String,
}

#[derive(Debug, Args)]
struct HttpUnorderedArgs {
    #[command(flatten)]
    common: HttpRequestRuleArgs,
    /// Non-root JSON Pointer; an entire * segment selects array elements.
    #[arg(long)]
    json_pointer: String,
}

fn http_options(args: HttpDependencyRuleArgs) -> Result<RewriteDependencyRulePlanOptions> {
    if let Some(mode) = args.mode {
        let (args, selector) = match mode {
            HttpDependencyMode::CrossCase(args) => {
                let selector = RewriteDependencyRuleSelector::HttpCrossCase {
                    selector: traffic_e2e::HttpCrossCaseSelector {
                        host: args.host.clone(),
                        port: args.port,
                        method: args.method.clone(),
                        path: args.path.clone(),
                    },
                };
                (args, selector)
            }
            HttpDependencyMode::Unordered(args) => {
                let selector = RewriteDependencyRuleSelector::HttpUnordered {
                    selector: traffic_e2e::HttpUnorderedSelector {
                        host: args.common.host.clone(),
                        port: args.common.port,
                        method: args.common.method.clone(),
                        path: args.common.path.clone(),
                        pointer: args.json_pointer,
                    },
                };
                (args.common, selector)
            }
        };
        return Ok(RewriteDependencyRulePlanOptions {
            evidence_id: args.evidence_id,
            ownership: RewriteDependencyOwnership::RequestOwned,
            name: Some(args.rule_id),
            source_evidence: Some(args.source_evidence),
            selector,
        });
    }
    let ownership = args.ownership.context("--ownership is required")?;
    ensure!(
        !matches!(ownership, DependencyOwnershipArg::ProcessOwned) || args.name.is_some(),
        "--name is required for process-owned HTTP"
    );
    ensure!(
        matches!(ownership, DependencyOwnershipArg::Unresolved) || args.source_evidence.is_some(),
        "--source-evidence is required"
    );
    Ok(RewriteDependencyRulePlanOptions {
        evidence_id: args.evidence_id.context("--evidence-id is required")?,
        ownership: ownership.into(),
        name: args.name,
        source_evidence: args.source_evidence,
        selector: RewriteDependencyRuleSelector::Http {
            authority: args.authority.context("--authority is required")?,
            method: args.method.context("--method is required")?,
            path_prefix: args.path_prefix.context("--path-prefix is required")?,
        },
    })
}

#[cfg(test)]
mod http_unordered_cli_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        rule: DependencyRuleArgs,
    }

    #[test]
    fn http_unordered_uses_dependency_value_inputs_without_an_ownership_flag() {
        let cli = Cli::try_parse_from([
            "test",
            "plan",
            "http",
            "unordered",
            "--evidence-id",
            "evidence-current",
            "--rule-id",
            "departments",
            "--host",
            "erp.example.test",
            "--port",
            "80",
            "--method",
            "POST",
            "--path",
            "/membership",
            "--json-pointer",
            "/department_ids",
            "--source-evidence",
            "service.py:216 membership uses an unordered set",
        ])
        .unwrap();
        let DependencyRuleCommand::Plan(args) = cli.rule.command else {
            panic!("expected plan");
        };
        let DependencyPlan::Ownership(options) = args.protocol.try_into().unwrap() else {
            panic!("expected dependency plan");
        };
        assert_eq!(options.ownership, RewriteDependencyOwnership::RequestOwned);
        assert!(
            matches!(options.selector, RewriteDependencyRuleSelector::HttpUnordered { selector } if selector.pointer == "/department_ids")
        );
    }
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
                        time_values: if args.time_values.is_empty() {
                            vec![traffic_e2e::MysqlTimeValueSelector {
                                value_index: args
                                    .value_index
                                    .expect("clap requires value-index or time-value"),
                                json_pointer: args.json_pointer,
                                tolerance: args.tolerance.unwrap_or_else(|| "5s".into()),
                                offset: args.offset.unwrap_or_else(|| "0s".into()),
                                format: args
                                    .format
                                    .unwrap_or_else(|| "%Y-%m-%d %H:%M:%S%.f".into()),
                                timezone: args.timezone.unwrap_or_else(|| "+00:00".into()),
                            }]
                        } else {
                            ensure!(
                                args.value_index.is_none()
                                    && args.json_pointer.is_none()
                                    && args.tolerance.is_none()
                                    && args.offset.is_none()
                                    && args.format.is_none()
                                    && args.timezone.is_none(),
                                "--time-value cannot be combined with legacy single-value options"
                            );
                            args.time_values
                        },
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
            DependencyRuleProtocolArgs::Http(args) => http_options(args)?,
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
            DependencyRuleProtocolArgs::Redis(args) => redis::options(args)?,
        }))
    }
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
    fn redis_cross_case_promotes_one_existing_request_rule() {
        let parsed = TestCli::try_parse_from([
            "test",
            "plan",
            "redis",
            "cross-case",
            "--evidence-id",
            "current",
            "--rule-id",
            "tauth-token-time",
            "--source-evidence",
            "tauth.py: module cache shares the token",
        ])
        .unwrap();
        let DependencyRuleCommand::Plan(plan) = parsed.dependency_rule.command else {
            panic!("plan")
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("scope")
        };
        assert_eq!(options.ownership, RewriteDependencyOwnership::RequestOwned);
        assert_eq!(options.name.as_deref(), Some("tauth-token-time"));
        assert!(matches!(
            options.selector,
            RewriteDependencyRuleSelector::RedisCrossCase { rule_id }
                if rule_id == "tauth-token-time"
        ));
    }

    #[test]
    fn http_cross_case_is_a_request_scope_plan_without_ownership_or_query_flags() {
        let parsed = TestCli::try_parse_from([
            "test",
            "plan",
            "http",
            "cross-case",
            "--evidence-id",
            "current",
            "--rule-id",
            "token",
            "--host",
            "erp.example.test",
            "--port",
            "80",
            "--method",
            "POST",
            "--path",
            "/token",
            "--source-evidence",
            "erp.py:ensure_token shared cache",
        ])
        .unwrap();
        let DependencyRuleCommand::Plan(plan) = parsed.dependency_rule.command else {
            panic!("plan")
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("scope")
        };
        assert_eq!(options.ownership, RewriteDependencyOwnership::RequestOwned);
        assert!(matches!(
            options.selector,
            RewriteDependencyRuleSelector::HttpCrossCase { .. }
        ));
        let legacy = TestCli::try_parse_from([
            "test",
            "plan",
            "http",
            "--evidence-id",
            "current",
            "--ownership",
            "process-owned",
            "--name",
            "refresh",
            "--source-evidence",
            "refresh.py:timer",
            "--authority",
            "config.example.test",
            "--method",
            "GET",
            "--path-prefix",
            "/config",
        ])
        .unwrap();
        let DependencyRuleCommand::Plan(plan) = legacy.dependency_rule.command else {
            panic!("plan")
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("ownership")
        };
        assert!(matches!(
            options.selector,
            RewriteDependencyRuleSelector::Http { .. }
        ));
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
        assert_eq!(selector.time_values[0].value_index, 0);
        assert_eq!(selector.time_values[0].tolerance, "5s");
        assert_eq!(selector.time_values[0].timezone, "+00:00");
    }

    #[test]
    fn mysql_time_cli_accepts_atomic_scalar_and_json_locations() {
        let parsed = TestCli::try_parse_from([
            "test",
            "plan",
            "mysql-time",
            "--evidence-id",
            "current",
            "--rule-id",
            "kind-times",
            "--database",
            "app",
            "--sql",
            "UPDATE kinds SET json=?, updated_at=? WHERE id=?",
            "--time-value",
            r#"{"value_index":0,"json_pointer":"/spec/observedAt","format":"%+"}"#,
            "--time-value",
            r#"{"value_index":1}"#,
            "--source-evidence",
            "kind.py:updated_at and service.py:observedAt use current time",
        ])
        .unwrap();
        let DependencyRuleCommand::Plan(plan) = parsed.dependency_rule.command else {
            panic!("expected plan")
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("expected value plan")
        };
        let RewriteDependencyRuleSelector::MysqlSqlTime { selector } = options.selector else {
            panic!("expected MySQL time")
        };
        assert_eq!(selector.time_values.len(), 2);
        assert_eq!(
            selector.time_values[0].json_pointer.as_deref(),
            Some("/spec/observedAt")
        );
        assert_eq!(selector.time_values[0].format, "%+");
        assert_eq!(selector.time_values[1].value_index, 1);
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
