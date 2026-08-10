use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::fingerprint;
use super::model::{
    RewriteDependencyRuleAppliedRecord, RewriteDependencyRulePlanRecord,
    RewriteDependencyRuleReport, RewriteDependencyRuleSpec, RewriteIssueKind, RewritePhase,
    RewriteRecordingRefreshState, RewriteState,
};
use super::{action, evidence};
use crate::{
    BackgroundDependencyFeedback, BackgroundDependencyPlan,
    BreezeMemcachedBackgroundDependencyFeedback, BreezeMemcachedBackgroundDependencyPlan,
    E2eRunContext, MotanBackgroundDependencyFeedback, MotanBackgroundDependencyPlan,
    RedisBackgroundDependencyFeedback, RedisBackgroundDependencyPlan, RedisKeyPatternConfig,
    plan_background_dependency, plan_breeze_memcached_background_dependency,
    plan_motan_background_dependency, plan_redis_background_dependency,
    resolve_e2e_response_rule_evidence,
};

#[derive(Debug, Clone)]
pub struct RewriteDependencyRulePlanOptions {
    pub evidence_id: String,
    pub name: String,
    pub source_evidence: String,
    pub selector: RewriteDependencyRuleSelector,
}

#[derive(Debug, Clone)]
pub enum RewriteDependencyRuleSelector {
    Http {
        authority: String,
        method: String,
        path_prefix: String,
    },
    Memcached {
        breeze_resource: String,
        command: String,
        key_start: u64,
        key_end: u64,
        key_separator: String,
        key_suffix: String,
        initial_load_timeout_ms: u64,
    },
    Motan {
        group: String,
        interface_name: String,
        method_name: String,
    },
    RedisZcount {
        ports: Vec<u16>,
        key_prefix: String,
        key_suffix: String,
    },
    RedisGet {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisScard {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisHgetall {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisHashRead {
        command: String,
        ports: Vec<u16>,
        keys: Vec<String>,
        key_patterns: Vec<RedisKeyPatternConfig>,
        fields: Vec<String>,
    },
}

enum DependencyRulePlan {
    Http(BackgroundDependencyPlan),
    Memcached(BreezeMemcachedBackgroundDependencyPlan),
    Motan(MotanBackgroundDependencyPlan),
    Redis(RedisBackgroundDependencyPlan),
}

struct ExactKeyRedisPlanInput<'a> {
    config_path: PathBuf,
    replay_report_path: PathBuf,
    record: &'a RewriteDependencyRulePlanRecord,
    ports: &'a [u16],
    keys: &'a [String],
    initial_load_timeout_ms: u64,
    source_revision: String,
    command: &'static str,
}

impl DependencyRulePlan {
    fn report(&self) -> Result<Value> {
        match self {
            Self::Http(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Memcached(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Motan(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Redis(plan) => Ok(serde_json::to_value(plan.report())?),
        }
    }

    fn apply(self) -> Result<Value> {
        match self {
            Self::Http(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Memcached(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Motan(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Redis(plan) => Ok(serde_json::to_value(plan.apply()?)?),
        }
    }

    fn reused_existing(&self) -> Option<&str> {
        match self {
            Self::Http(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            Self::Memcached(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            Self::Motan(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            Self::Redis(plan) if plan.report().reused_existing => {
                Some(&plan.report().effective_name)
            }
            _ => None,
        }
    }

    fn effective_name(&self) -> &str {
        match self {
            Self::Http(plan) => &plan.report().effective_name,
            Self::Memcached(plan) => &plan.report().effective_name,
            Self::Motan(plan) => &plan.report().effective_name,
            Self::Redis(plan) => &plan.report().effective_name,
        }
    }
}

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteDependencyRulePlanOptions,
) -> Result<RewriteDependencyRuleReport> {
    let spec = spec_from_selector(options.selector);
    let issue = dependency_issue(state, &spec)?;
    validate_plan_evidence(target_root, state, &issue.id, &options.evidence_id, &spec)?;
    let spec_json = serde_json::to_string(&spec)?;
    let mut record = RewriteDependencyRulePlanRecord {
        id: format!(
            "dependency-plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                &options.evidence_id,
                &options.name,
                &spec_json,
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        evidence_id: options.evidence_id,
        name: options.name,
        source_evidence: options.source_evidence,
        spec,
        reused_existing: false,
        effective_name: None,
    };
    let plan = build_plan(target_root, state, &record)?;
    if plan.effective_name() != record.name {
        record.effective_name = Some(plan.effective_name().to_string());
    }
    if let Some(effective_name) = plan.reused_existing() {
        record.reused_existing = true;
        record.effective_name = Some(effective_name.to_string());
    }
    let report = plan.report()?;
    state.rule_plan = None;
    state.recorder_capture_plan = None;
    state.dependency_rule_plan = Some(record.clone());
    state.bump();
    Ok(RewriteDependencyRuleReport {
        plan_id: record.id.clone(),
        issue_id: issue.id,
        traffic_e2e_report: report,
        evidence_reclassification: None,
        next_command: action::dependency_rule_apply_command(target_root, &record.id),
    })
}

pub(super) fn apply(
    target_root: &Path,
    state: &mut RewriteState,
    plan_id: &str,
) -> Result<RewriteDependencyRuleReport> {
    let record = pending_plan_for_apply(state, plan_id)?;
    let report = build_plan(target_root, state, &record)?.apply()?;
    state.dependency_rule_plan = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(RewriteDependencyRuleReport {
        plan_id: record.id,
        issue_id: record.issue_id,
        traffic_e2e_report: report,
        evidence_reclassification: None,
        next_command: action::next_command_for_api(target_root, &state.api),
    })
}

fn dependency_issue(
    state: &RewriteState,
    spec: &RewriteDependencyRuleSpec,
) -> Result<super::model::RewriteIssue> {
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    ensure!(
        issue.kind == RewriteIssueKind::Dependency
            || (issue.kind == RewriteIssueKind::Response
                && matches!(spec, RewriteDependencyRuleSpec::RedisHashRead { .. })),
        "background dependency rules require a dependency issue; bootstrap Redis hash reads also accept a response issue"
    );
    Ok(issue)
}

fn pending_plan_for_apply(
    state: &RewriteState,
    plan_id: &str,
) -> Result<RewriteDependencyRulePlanRecord> {
    let record = state
        .dependency_rule_plan
        .clone()
        .context("rewrite workflow has no pending dependency rule plan")?;
    ensure!(
        record.id == plan_id,
        "dependency rule plan is stale or belongs to another issue"
    );
    let issue = dependency_issue(state, &record.spec)?;
    ensure!(
        issue.id == record.issue_id,
        "active rewrite issue changed after dependency rule planning"
    );
    Ok(record)
}

fn validate_plan_evidence(
    target_root: &Path,
    state: &RewriteState,
    issue_id: &str,
    evidence_id: &str,
    spec: &RewriteDependencyRuleSpec,
) -> Result<()> {
    if state
        .dependency_rule_plan
        .as_ref()
        .is_some_and(|plan| plan.issue_id == issue_id && plan.evidence_id == evidence_id)
    {
        return Ok(());
    }

    let expected_query = if matches!(spec, RewriteDependencyRuleSpec::RedisHashRead { .. })
        && state
            .active_issue
            .as_ref()
            .is_some_and(|issue| issue.kind == RewriteIssueKind::Response)
    {
        "pre_readiness_traffic"
    } else {
        "dirty_clusters"
    };
    let valid = evidence::commands(target_root, state)
        .into_iter()
        .any(|command| {
            evidence::query(target_root, state, &command.query_id).is_ok_and(|report| {
                report.query == expected_query && report.evidence_id == evidence_id
            })
        });
    ensure!(
        valid,
        "dependency rule evidence is stale, has the wrong query kind, or belongs to another issue"
    );
    Ok(())
}

pub(super) fn pending_cache_snapshot_refresh(
    state: &RewriteState,
    plan_id: &str,
) -> Result<Option<RewriteDependencyRuleAppliedRecord>> {
    let record = pending_plan_for_apply(state, plan_id)?;
    if !matches!(
        record.spec,
        RewriteDependencyRuleSpec::RedisZcount { .. }
            | RewriteDependencyRuleSpec::RedisGet { .. }
            | RewriteDependencyRuleSpec::RedisScard { .. }
            | RewriteDependencyRuleSpec::RedisHgetall { .. }
            | RewriteDependencyRuleSpec::RedisHashRead { .. }
    ) {
        return Ok(None);
    }
    Ok(Some(RewriteDependencyRuleAppliedRecord {
        plan_id: record.id,
        issue_id: record.issue_id,
        evidence_id: record.evidence_id,
        api: state.api.clone(),
        rule_name: record.effective_name.unwrap_or(record.name),
        source_evidence: record.source_evidence,
    }))
}

pub(super) fn schedule_cache_snapshot_refresh(
    target_root: &Path,
    state: &mut RewriteState,
    applied: RewriteDependencyRuleAppliedRecord,
) -> Result<()> {
    ensure!(
        state
            .recording_refresh
            .as_ref()
            .and_then(|refresh| refresh.recording_run_id.as_ref())
            .is_none(),
        "a full recording refresh has already started; wait for it to finish before applying another dependency rule"
    );
    let config_revision = fingerprint::recorder_config_revision(target_root)?;
    let refresh = state
        .recording_refresh
        .get_or_insert_with(|| RewriteRecordingRefreshState {
            applied: Vec::new(),
            dependency_rules: Vec::new(),
            recorder_config_revision: config_revision.clone(),
            recording_run_id: None,
        });
    refresh.recorder_config_revision = config_revision;
    if !refresh
        .dependency_rules
        .iter()
        .any(|record| record.plan_id == applied.plan_id)
    {
        refresh.dependency_rules.push(applied);
    }
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.route = None;
    state.phase = RewritePhase::AwaitingRecordingRefresh;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(())
}

fn spec_from_selector(selector: RewriteDependencyRuleSelector) -> RewriteDependencyRuleSpec {
    match selector {
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

fn build_plan(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteDependencyRulePlanRecord,
) -> Result<DependencyRulePlan> {
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
            case_source,
            run_key: None,
        },
        api,
    )?
    .replay;
    let config_path = target_root.join(".traffic-e2e/recorder.toml");
    match &record.spec {
        RewriteDependencyRuleSpec::Http {
            authority,
            method,
            path_prefix,
        } => Ok(DependencyRulePlan::Http(plan_background_dependency(
            BackgroundDependencyFeedback {
                config_path,
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
                    config_path,
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
        RewriteDependencyRuleSpec::Motan {
            group,
            interface_name,
            method_name,
        } => Ok(DependencyRulePlan::Motan(plan_motan_background_dependency(
            MotanBackgroundDependencyFeedback {
                config_path,
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
                config_path,
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
            config_path,
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
            config_path,
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
            config_path,
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
                config_path,
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
        config_path,
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
            config_path,
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

#[cfg(test)]
mod tests;
