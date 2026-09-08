//! Build protocol-specific evidence plans for coordinator-owned rules.
use super::*;
use crate::{
    BackgroundDependencyFeedback, BackgroundDependencyPlan,
    BreezeMemcachedBackgroundDependencyFeedback, BreezeMemcachedBackgroundDependencyPlan,
    MemcachedTimestampRulePlan, MotanBackgroundDependencyFeedback, MotanBackgroundDependencyPlan,
    MysqlBackgroundDependencyFeedback, MysqlBackgroundDependencyPlan,
    RedisBackgroundDependencyFeedback, RedisBackgroundDependencyPlan, plan_background_dependency,
    plan_breeze_memcached_background_dependency, plan_motan_background_dependency,
    plan_mysql_background_dependency, plan_redis_background_dependency,
    resolve_e2e_response_rule_evidence,
};
use std::path::PathBuf;

pub(super) enum DependencyRulePlan {
    HttpCrossCase(crate::HttpCrossCasePlan),
    MysqlTime(crate::MysqlTimeRulePlan),
    Mysql(MysqlBackgroundDependencyPlan),
    Http(BackgroundDependencyPlan),
    Memcached(BreezeMemcachedBackgroundDependencyPlan),
    MemcachedTimestamp(MemcachedTimestampRulePlan),
    Motan(MotanBackgroundDependencyPlan),
    Redis(RedisBackgroundDependencyPlan),
}

struct ExactKeyRedisPlanInput<'a> {
    rules_path: PathBuf,
    replay_report_path: PathBuf,
    record: &'a RewriteDependencyRulePlanRecord,
    ports: &'a [u16],
    keys: &'a [String],
    initial_load_timeout_ms: u64,
    source_revision: String,
    command: &'static str,
}

impl DependencyRulePlan {
    pub(super) fn report(&self) -> Result<Value> {
        match self {
            Self::HttpCrossCase(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::MysqlTime(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Http(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Mysql(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Memcached(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::MemcachedTimestamp(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Motan(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Redis(plan) => Ok(serde_json::to_value(plan.report())?),
        }
    }

    pub(super) fn apply(self) -> Result<Value> {
        match self {
            Self::HttpCrossCase(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::MysqlTime(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Http(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Mysql(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Memcached(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::MemcachedTimestamp(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Motan(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Redis(plan) => Ok(serde_json::to_value(plan.apply()?)?),
        }
    }

    pub(super) fn reused_existing(&self) -> Option<&str> {
        match self {
            Self::HttpCrossCase(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_rule_id)
            }
            Self::MysqlTime(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_rule_id)
            }
            Self::Http(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            Self::Memcached(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            Self::MemcachedTimestamp(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_rule_id)
            }
            Self::Motan(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            Self::Redis(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            Self::Mysql(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            _ => None,
        }
    }

    pub(super) fn effective_name(&self) -> &str {
        match self {
            Self::HttpCrossCase(plan) => &plan.report().effective_rule_id,
            Self::MysqlTime(plan) => &plan.report().effective_rule_id,
            Self::Http(plan) => &plan.report().effective_name,
            Self::Mysql(plan) => &plan.report().effective_name,
            Self::Memcached(plan) => &plan.report().effective_name,
            Self::MemcachedTimestamp(plan) => &plan.report().effective_rule_id,
            Self::Motan(plan) => &plan.report().effective_name,
            Self::Redis(plan) => &plan.report().effective_name,
        }
    }
}

pub(super) fn spec_from_selector(
    selector: RewriteDependencyRuleSelector,
) -> RewriteDependencyRuleSpec {
    match selector {
        RewriteDependencyRuleSelector::HttpCrossCase { selector } => {
            RewriteDependencyRuleSpec::HttpCrossCase { selector }
        }
        RewriteDependencyRuleSelector::MysqlSqlTime { selector } => {
            RewriteDependencyRuleSpec::MysqlSqlTime { selector }
        }
        RewriteDependencyRuleSelector::Mysql { selector } => {
            RewriteDependencyRuleSpec::Mysql { selector }
        }
        RewriteDependencyRuleSelector::Http {
            authority,
            method,
            path_prefix,
        } => RewriteDependencyRuleSpec::Http {
            authority,
            method,
            path_prefix,
        },
        RewriteDependencyRuleSelector::Memcached {
            breeze_resource,
            command,
            key_start,
            key_end,
            key_separator,
            key_suffix,
            initial_load_timeout_ms,
        } => RewriteDependencyRuleSpec::Memcached {
            breeze_resource,
            command,
            key_start,
            key_end,
            key_separator,
            key_suffix,
            initial_load_timeout_ms,
        },
        RewriteDependencyRuleSelector::Motan {
            group,
            interface_name,
            method_name,
        } => RewriteDependencyRuleSpec::Motan {
            group,
            interface_name,
            method_name,
        },
        RewriteDependencyRuleSelector::RedisZcount {
            ports,
            key_prefix,
            key_suffix,
        } => RewriteDependencyRuleSpec::RedisZcount {
            ports,
            key_prefix,
            key_suffix,
        },
        RewriteDependencyRuleSelector::RedisGet {
            ports,
            keys,
            initial_load_timeout_ms,
        } => RewriteDependencyRuleSpec::RedisGet {
            ports,
            keys,
            initial_load_timeout_ms,
        },
        RewriteDependencyRuleSelector::RedisScard {
            ports,
            keys,
            initial_load_timeout_ms,
        } => RewriteDependencyRuleSpec::RedisScard {
            ports,
            keys,
            initial_load_timeout_ms,
        },
        RewriteDependencyRuleSelector::RedisHgetall {
            ports,
            keys,
            initial_load_timeout_ms,
        } => RewriteDependencyRuleSpec::RedisHgetall {
            ports,
            keys,
            initial_load_timeout_ms,
        },
        RewriteDependencyRuleSelector::RedisHashRead {
            command,
            ports,
            keys,
            key_patterns,
            fields,
        } => RewriteDependencyRuleSpec::RedisHashRead {
            command,
            ports,
            keys,
            key_patterns,
            fields,
        },
    }
}

pub(super) fn build_plan(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteDependencyRulePlanRecord,
) -> Result<DependencyRulePlan> {
    if let RewriteDependencyRuleSpec::MemcachedProtobufTimestamp {
        rule_id,
        port,
        key_prefix,
        key_suffix,
        field_number,
    } = &record.spec
    {
        return Ok(DependencyRulePlan::MemcachedTimestamp(
            plan_memcached_timestamp_rule(MemcachedTimestampRuleFeedback {
                policy_path: target_root.join(".traffic-e2e/verification.yaml"),
                rule_id: rule_id.clone(),
                port: *port,
                key_prefix: key_prefix.clone(),
                key_suffix: key_suffix.clone(),
                field_number: *field_number,
                source_evidence: record.source_evidence.clone(),
            })?,
        ));
    }
    let case_source = state
        .case_source
        .clone()
        .context("dependency rule plan requires a finalized case source")?;
    let api = state
        .group_id
        .as_deref()
        .context("dependency rule plan requires a prepared API group")?;
    let source_revision = state
        .source_revision
        .clone()
        .context("dependency rule plan requires a source revision")?;
    let replay_report_path = resolve_e2e_response_rule_evidence(
        E2eRunContext {
            target_root: target_root.to_path_buf(),
            case_source: case_source.clone(),
            run_key: None,
        },
        api,
    )?
    .replay;
    if let RewriteDependencyRuleSpec::HttpCrossCase { selector } = &record.spec {
        return Ok(DependencyRulePlan::HttpCrossCase(
            crate::plan_http_cross_case(crate::HttpCrossCaseFeedback {
                policy_path: target_root.join(".traffic-e2e/verification.yaml"),
                case_source,
                replay_report_path,
                rule_id: record.name.clone(),
                selector: selector.clone(),
                source_evidence: record.source_evidence.clone(),
            })?,
        ));
    }
    if let RewriteDependencyRuleSpec::MysqlSqlTime { selector } = &record.spec {
        return Ok(DependencyRulePlan::MysqlTime(crate::plan_mysql_time_rule(
            crate::MysqlTimeRuleFeedback {
                policy_path: target_root.join(".traffic-e2e/verification.yaml"),
                replay_report_path,
                api: state.api.clone(),
                rule_id: record.name.clone(),
                selector: selector.clone(),
                source_evidence: record.source_evidence.clone(),
            },
        )?));
    }
    let rules_path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(crate::config::SOURCE_TRAFFIC_POLICY_FILE);
    match &record.spec {
        RewriteDependencyRuleSpec::Mysql { selector } => Ok(DependencyRulePlan::Mysql(
            plan_mysql_background_dependency(MysqlBackgroundDependencyFeedback {
                rules_path,
                replay_report_path,
                name: record.name.clone(),
                selector: selector.clone(),
                source_revision,
                source_evidence: record.source_evidence.clone(),
            })?,
        )),
        RewriteDependencyRuleSpec::Http {
            authority,
            method,
            path_prefix,
        } => Ok(DependencyRulePlan::Http(plan_background_dependency(
            BackgroundDependencyFeedback {
                rules_path,
                replay_report_path,
                name: record.name.clone(),
                authority: authority.clone(),
                method: method.clone(),
                path_prefix: path_prefix.clone(),
                source_revision,
                source_evidence: record.source_evidence.clone(),
            },
        )?)),
        RewriteDependencyRuleSpec::Memcached {
            breeze_resource,
            command,
            key_start,
            key_end,
            key_separator,
            key_suffix,
            initial_load_timeout_ms,
        } => Ok(DependencyRulePlan::Memcached(
            plan_breeze_memcached_background_dependency(
                BreezeMemcachedBackgroundDependencyFeedback {
                    rules_path,
                    replay_report_path,
                    name: record.name.clone(),
                    breeze_resource: breeze_resource.clone(),
                    command: command.clone(),
                    key_start: *key_start,
                    key_end: *key_end,
                    key_separator: key_separator.clone(),
                    key_suffix: key_suffix.clone(),
                    initial_load_timeout_ms: *initial_load_timeout_ms,
                    source_revision,
                    source_evidence: record.source_evidence.clone(),
                },
            )?,
        )),
        RewriteDependencyRuleSpec::MemcachedProtobufTimestamp { .. }
        | RewriteDependencyRuleSpec::MysqlSqlTime { .. }
        | RewriteDependencyRuleSpec::HttpCrossCase { .. } => {
            unreachable!("Memcached payload plans return before background evidence resolution")
        }
        RewriteDependencyRuleSpec::Motan {
            group,
            interface_name,
            method_name,
        } => Ok(DependencyRulePlan::Motan(plan_motan_background_dependency(
            MotanBackgroundDependencyFeedback {
                rules_path,
                replay_report_path,
                name: record.name.clone(),
                group: group.clone(),
                interface_name: interface_name.clone(),
                method_name: method_name.clone(),
                source_revision,
                source_evidence: record.source_evidence.clone(),
            },
        )?)),
        RewriteDependencyRuleSpec::RedisZcount {
            ports,
            key_prefix,
            key_suffix,
        } => Ok(DependencyRulePlan::Redis(plan_redis_background_dependency(
            RedisBackgroundDependencyFeedback {
                rules_path,
                replay_report_path,
                name: record.name.clone(),
                ports: ports.clone(),
                command: "ZCOUNT".to_string(),
                keys: Vec::new(),
                key_patterns: Vec::new(),
                key_prefix: key_prefix.clone(),
                key_suffix: key_suffix.clone(),
                initial_load_timeout_ms: None,
                fields: Vec::new(),
                source_revision,
                source_evidence: record.source_evidence.clone(),
            },
        )?)),
        RewriteDependencyRuleSpec::RedisGet {
            ports,
            keys,
            initial_load_timeout_ms,
        } => plan_exact_key_redis_background_dependency(ExactKeyRedisPlanInput {
            rules_path,
            replay_report_path,
            record,
            ports,
            keys,
            initial_load_timeout_ms: *initial_load_timeout_ms,
            source_revision,
            command: "GET",
        }),
        RewriteDependencyRuleSpec::RedisScard {
            ports,
            keys,
            initial_load_timeout_ms,
        } => plan_exact_key_redis_background_dependency(ExactKeyRedisPlanInput {
            rules_path,
            replay_report_path,
            record,
            ports,
            keys,
            initial_load_timeout_ms: *initial_load_timeout_ms,
            source_revision,
            command: "SCARD",
        }),
        RewriteDependencyRuleSpec::RedisHgetall {
            ports,
            keys,
            initial_load_timeout_ms,
        } => plan_exact_key_redis_background_dependency(ExactKeyRedisPlanInput {
            rules_path,
            replay_report_path,
            record,
            ports,
            keys,
            initial_load_timeout_ms: *initial_load_timeout_ms,
            source_revision,
            command: "HGETALL",
        }),
        RewriteDependencyRuleSpec::RedisHashRead {
            command,
            ports,
            keys,
            key_patterns,
            fields,
        } => Ok(DependencyRulePlan::Redis(plan_redis_background_dependency(
            RedisBackgroundDependencyFeedback {
                rules_path,
                replay_report_path,
                name: record.name.clone(),
                ports: ports.clone(),
                command: command.clone(),
                keys: keys.clone(),
                key_patterns: key_patterns.clone(),
                key_prefix: String::new(),
                key_suffix: String::new(),
                initial_load_timeout_ms: None,
                fields: fields.clone(),
                source_revision,
                source_evidence: record.source_evidence.clone(),
            },
        )?)),
    }
}

fn plan_exact_key_redis_background_dependency(
    input: ExactKeyRedisPlanInput<'_>,
) -> Result<DependencyRulePlan> {
    let ExactKeyRedisPlanInput {
        rules_path,
        replay_report_path,
        record,
        ports,
        keys,
        initial_load_timeout_ms,
        source_revision,
        command,
    } = input;
    Ok(DependencyRulePlan::Redis(plan_redis_background_dependency(
        RedisBackgroundDependencyFeedback {
            rules_path,
            replay_report_path,
            name: record.name.clone(),
            ports: ports.to_vec(),
            command: command.to_string(),
            keys: keys.to_vec(),
            key_patterns: Vec::new(),
            key_prefix: String::new(),
            key_suffix: String::new(),
            initial_load_timeout_ms: Some(initial_load_timeout_ms),
            fields: Vec::new(),
            source_revision,
            source_evidence: record.source_evidence.clone(),
        },
    )?))
}
