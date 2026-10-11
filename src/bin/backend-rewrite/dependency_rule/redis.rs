//! Redis dependency rule CLI selectors and conversion.
use super::*;
mod lock;
mod publish;
mod time_shift;
#[derive(Debug, Args)]
#[command(
    after_help = "Redis write argument timestamps (ZADD score / ZREMRANGEBYSCORE maximum) use:\n  backend-rewrite rule plan --evidence-id ID --dependency-request RULE_JSON\nSee `backend-rewrite rule plan --help` for the existing request-rule entrypoint."
)]
pub(super) struct RedisDependencyRuleArgs {
    #[command(subcommand)]
    mode: RedisDependencyRuleModeArgs,
}

#[derive(Debug, Subcommand)]
enum RedisDependencyRuleModeArgs {
    /// Correlate source-proven random SET NX tokens with single-key release references.
    Lock(lock::RedisLockArgs),
    /// Bind source-proven UUID v4 identities at an explicit PUBLISH payload position.
    Publish(publish::RedisPublishArgs),
    /// Share one source-proven GET/HGET token read across cases of a completed recording.
    CrossCase(RedisCrossCaseArgs),
    /// Preserve source-proven relative lifetimes in matched GET/HGET JSON responses.
    TimeShift(time_shift::RedisTimeShiftArgs),
    /// Source-proven unordered JSON arrays or Protobuf repeated fields in string writes.
    Unordered(RedisUnorderedArgs),
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
    /// Process-owned Redis HSCAN traffic selected by exact keys or compact key shapes.
    Hscan(RedisScanDependencyRuleArgs),
}

#[derive(Debug, Args)]
struct RedisCrossCaseArgs {
    #[arg(long)]
    evidence_id: String,
    /// Existing case-scoped Redis time-shift rule to promote.
    #[arg(long)]
    rule_id: String,
    /// Source cache initialization and reuse proof.
    #[arg(long)]
    source_evidence: String,
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
struct RedisScanDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long = "port", required = true)]
    ports: Vec<u16>,
    /// Optional exact Redis key; repeat for each exceptional key.
    #[arg(long = "key")]
    keys: Vec<String>,
    /// Key shape containing one `<id>` numeric segment, for example `dingtalk:card_inbox:<id>`.
    #[arg(long = "numeric-key-pattern")]
    key_patterns: Vec<String>,
}

pub(super) fn options(args: RedisDependencyRuleArgs) -> Result<RewriteDependencyRulePlanOptions> {
    Ok(match args.mode {
        RedisDependencyRuleModeArgs::CrossCase(args) => {
            return Ok(RewriteDependencyRulePlanOptions {
                evidence_id: args.evidence_id,
                ownership: RewriteDependencyOwnership::RequestOwned,
                name: Some(args.rule_id.clone()),
                source_evidence: Some(args.source_evidence),
                selector: RewriteDependencyRuleSelector::RedisCrossCase {
                    rule_id: args.rule_id,
                },
            });
        }
        RedisDependencyRuleModeArgs::Lock(args) => return lock::options(args),
        RedisDependencyRuleModeArgs::Publish(args) => return publish::options(args),
        RedisDependencyRuleModeArgs::TimeShift(args) => return time_shift::options(args),
        RedisDependencyRuleModeArgs::Unordered(args) => return unordered_options(args),
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
        RedisDependencyRuleModeArgs::Hscan(args) => redis_hscan_options(args)?,
    })
}

fn redis_hscan_options(
    args: RedisScanDependencyRuleArgs,
) -> Result<RewriteDependencyRulePlanOptions> {
    ensure!(
        !args.keys.is_empty() || !args.key_patterns.is_empty(),
        "Redis HSCAN requires at least one --key or --numeric-key-pattern"
    );
    let patterns = args
        .key_patterns
        .into_iter()
        .map(|pattern| parse_numeric_key_pattern("HSCAN", &pattern))
        .collect::<Result<Vec<_>>>()?;
    Ok(dependency_rule_options(
        args.common,
        RewriteDependencyRuleSelector::RedisHscan {
            ports: args.ports,
            keys: args.keys,
            key_patterns: patterns,
        },
    ))
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

pub(super) fn parse_numeric_key_pattern(
    command: &str,
    value: &str,
) -> Result<RedisKeyPatternConfig> {
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

#[cfg(test)]
mod hscan_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: RedisDependencyRuleArgs,
    }

    #[test]
    fn hscan_uses_a_key_or_numeric_key_pattern_without_fields_or_timeout() {
        let cli = Cli::try_parse_from([
            "test",
            "hscan",
            "--evidence-id",
            "evidence-source-process-traffic",
            "--ownership",
            "process-owned",
            "--name",
            "dingtalk-card-inbox-recovery",
            "--source-evidence",
            "card_inbox.py:list_pending runs in the process recovery task",
            "--port",
            "6379",
            "--numeric-key-pattern",
            "dingtalk:card_inbox:<id>",
        ])
        .unwrap();

        let options = options(cli.args).unwrap();
        assert!(matches!(
            options.selector,
            RewriteDependencyRuleSelector::RedisHscan {
                ports,
                keys,
                key_patterns,
            } if ports == [6379]
                && keys.is_empty()
                && key_patterns == [RedisKeyPatternConfig {
                    prefix: "dingtalk:card_inbox:".to_string(),
                    suffix: String::new(),
                    numeric_middle: true,
                }]
        ));
    }

    #[test]
    fn hscan_requires_a_key_selector() {
        let cli = Cli::try_parse_from([
            "test",
            "hscan",
            "--evidence-id",
            "evidence-source-process-traffic",
            "--ownership",
            "process-owned",
            "--name",
            "dingtalk-card-inbox-recovery",
            "--source-evidence",
            "card_inbox.py:list_pending runs in the process recovery task",
            "--port",
            "6379",
        ])
        .unwrap();

        assert!(
            options(cli.args)
                .unwrap_err()
                .to_string()
                .contains("requires at least one --key or --numeric-key-pattern")
        );
    }
}

#[derive(Debug, Args)]
struct RedisUnorderedArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    rule_id: String,
    #[arg(long)]
    host: String,
    #[arg(long)]
    port: u16,
    /// Exact key; conflicts with affix selectors.
    #[arg(long, conflicts_with_all = ["key_prefix", "key_suffix", "numeric_key_pattern"])]
    key: Option<String>,
    #[arg(long, conflicts_with = "numeric_key_pattern")]
    key_prefix: Option<String>,
    #[arg(long, conflicts_with = "numeric_key_pattern")]
    key_suffix: Option<String>,
    /// Key shape containing one numeric <id> segment.
    #[arg(long)]
    numeric_key_pattern: Option<String>,
    /// JSON Pointer (empty selects root); * selects array elements.
    #[arg(
        long,
        conflicts_with = "protobuf_path",
        required_unless_present = "protobuf_path"
    )]
    json_pointer: Option<String>,
    /// Typed JSON object: {"field_path":[3],"element_type":"string","display_path":"value.departments"}.
    #[arg(
        long,
        conflicts_with = "json_pointer",
        required_unless_present = "json_pointer"
    )]
    protobuf_path: Option<String>,
    /// Source file/symbol proof that ordering is irrelevant and key scope is shared.
    #[arg(long)]
    source_evidence: String,
}
fn unordered_options(args: RedisUnorderedArgs) -> Result<RewriteDependencyRulePlanOptions> {
    use traffic_e2e::{RedisUnorderedField, RedisUnorderedSelector, RedisValueKeySelector};
    let key = if let Some(value) = args.key {
        RedisValueKeySelector::Exact { value }
    } else if let Some(value) = args.numeric_key_pattern {
        let pattern = parse_numeric_key_pattern("unordered", &value)?;
        RedisValueKeySelector::Numeric {
            prefix: pattern.prefix,
            suffix: pattern.suffix,
        }
    } else {
        ensure!(
            args.key_prefix.is_some() || args.key_suffix.is_some(),
            "Redis unordered requires --key, key affixes, or --numeric-key-pattern"
        );
        RedisValueKeySelector::Affix {
            prefix: args.key_prefix.unwrap_or_default(),
            suffix: args.key_suffix.unwrap_or_default(),
        }
    };
    let field = if let Some(pointer) = args.json_pointer {
        RedisUnorderedField::Json { pointer }
    } else {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Path {
            field_path: traffic_e2e::ProtobufFieldPath,
            element_type: traffic_e2e::ProtobufRepeatedElementType,
            display_path: String,
        }
        let path: Path =
            serde_json::from_str(&args.protobuf_path.context("missing unordered field")?)?;
        RedisUnorderedField::Protobuf {
            field_path: path.field_path,
            element_type: path.element_type,
            display_path: path.display_path,
        }
    };
    Ok(RewriteDependencyRulePlanOptions {
        evidence_id: args.evidence_id,
        ownership: RewriteDependencyOwnership::RequestOwned,
        name: Some(args.rule_id),
        source_evidence: Some(args.source_evidence),
        selector: RewriteDependencyRuleSelector::RedisUnordered {
            selector: RedisUnorderedSelector {
                host: args.host,
                port: args.port,
                key,
                field,
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Debug, Parser)]
    struct Cli {
        #[command(flatten)]
        rule: DependencyRuleArgs,
    }
    #[test]
    fn redis_unordered_uses_existing_plan_entrypoint_without_ownership() {
        let base = [
            "test",
            "plan",
            "redis",
            "unordered",
            "--evidence-id",
            "current",
            "--rule-id",
            "members",
            "--host",
            "redis.test",
            "--port",
            "6379",
            "--source-evidence",
            "service.py:42 set semantics",
        ];
        for flags in [
            vec!["--key-prefix", "erp:", "--json-pointer", "/groups/*/ids"],
            vec!["--key-suffix", ":members", "--json-pointer", ""],
            vec![
                "--numeric-key-pattern",
                "erp:<id>",
                "--protobuf-path",
                r#"{"field_path":[4],"element_type":"string","display_path":"value.ids"}"#,
            ],
        ] {
            let cli = Cli::try_parse_from(base.into_iter().chain(flags)).unwrap();
            let DependencyRuleCommand::Plan(plan) = cli.rule.command else {
                panic!("plan expected")
            };
            let DependencyPlan::Ownership(plan) = DependencyPlan::try_from(plan.protocol).unwrap()
            else {
                panic!("value plan expected")
            };
            assert_eq!(plan.ownership, RewriteDependencyOwnership::RequestOwned);
            assert!(matches!(
                plan.selector,
                RewriteDependencyRuleSelector::RedisUnordered { .. }
            ));
        }
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--key",
                "one",
                "--key-prefix",
                "erp:",
                "--json-pointer",
                "/ids"
            ]))
            .is_err()
        );
    }
}
