use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;

use super::fingerprint;
use super::model::{
    RewriteDependencyRuleAppliedRecord, RewriteDependencyRulePlanRecord,
    RewriteDependencyRuleReport, RewriteDependencyRuleSpec, RewriteIssueKind, RewritePhase,
    RewriteRecordingRefreshState, RewriteState,
};
use super::{action, evidence};
use crate::{
    E2eRunContext, MemcachedTimestampRuleFeedback, RedisKeyPatternConfig,
    plan_memcached_timestamp_rule,
};

mod planner;
use planner::{build_plan, spec_from_selector};

#[derive(Debug, Clone)]
pub struct RewriteDependencyRulePlanOptions {
    pub evidence_id: String,
    pub ownership: RewriteDependencyOwnership,
    pub name: Option<String>,
    pub source_evidence: Option<String>,
    pub selector: RewriteDependencyRuleSelector,
}

#[derive(Debug, Clone)]
pub struct RewriteDependencyPayloadRulePlanOptions {
    pub evidence_id: String,
    pub rule_id: String,
    pub port: u16,
    pub key_prefix: String,
    pub key_suffix: String,
    pub field_number: u32,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteDependencyPayloadRulePlanReport {
    pub issue_id: String,
    pub evidence_id: String,
    pub plan_id: String,
    pub traffic_e2e_report: Value,
    pub next_command: super::model::RewriteCommandSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteDependencyOwnership {
    ProcessOwned,
    RequestOwned,
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteDependencyRulePlanReport {
    pub ownership: RewriteDependencyOwnership,
    pub issue_id: String,
    pub evidence_id: String,
    pub process_owned_rule_applicable: bool,
    pub target_implementation_required: bool,
    pub selector: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic_e2e_report: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_change: Option<String>,
    pub next_command: super::model::RewriteCommandSpec,
}

#[derive(Debug, Clone)]
pub enum RewriteDependencyRuleSelector {
    RedisCrossCase {
        rule_id: String,
    },
    RedisTimeShift {
        selector: crate::RedisTimeShiftSelector,
    },
    HttpUnordered {
        selector: crate::HttpUnorderedSelector,
    },
    RedisUnordered {
        selector: crate::RedisUnorderedSelector,
    },
    HttpCrossCase {
        selector: crate::HttpCrossCaseSelector,
    },
    MysqlSqlTime {
        selector: crate::MysqlTimeSelector,
    },
    Mysql {
        selector: crate::MysqlBackgroundSelector,
    },
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
    RedisHscan {
        ports: Vec<u16>,
        keys: Vec<String>,
        key_patterns: Vec<RedisKeyPatternConfig>,
    },
    RedisHashRead {
        command: String,
        ports: Vec<u16>,
        keys: Vec<String>,
        key_patterns: Vec<RedisKeyPatternConfig>,
        fields: Vec<String>,
    },
}

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteDependencyRulePlanOptions,
) -> Result<RewriteDependencyRulePlanReport> {
    let spec = spec_from_selector(options.selector.clone());
    let request_rule = matches!(
        &spec,
        RewriteDependencyRuleSpec::MysqlSqlTime { .. }
            | RewriteDependencyRuleSpec::HttpCrossCase { .. }
            | RewriteDependencyRuleSpec::HttpUnordered { .. }
            | RewriteDependencyRuleSpec::RedisUnordered { .. }
            | RewriteDependencyRuleSpec::RedisTimeShift { .. }
            | RewriteDependencyRuleSpec::RedisCrossCase { .. }
    );
    ensure!(
        !request_rule || options.ownership == RewriteDependencyOwnership::RequestOwned,
        "value and scope rules do not change dependency ownership; use request-owned"
    );
    let issue = dependency_issue(state, &spec)?;
    validate_plan_evidence(target_root, state, &issue.id, &options.evidence_id, &spec)?;
    let selector = serde_json::to_value(&spec)?;
    if !request_rule && options.ownership != RewriteDependencyOwnership::ProcessOwned {
        return classify_non_process_owned(target_root, state, issue, options, selector);
    }
    let name = options
        .name
        .context("a rule name is required when planning a dependency rule")?;
    let source_evidence = options
        .source_evidence
        .context("--source-evidence is required when planning a dependency rule")?;
    let spec_json = serde_json::to_string(&spec)?;
    let mut record = RewriteDependencyRulePlanRecord {
        review_fingerprint: None,
        id: format!(
            "dependency-plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                &options.evidence_id,
                &name,
                &spec_json,
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        evidence_id: options.evidence_id.clone(),
        name,
        source_evidence,
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
    if matches!(
        record.spec,
        RewriteDependencyRuleSpec::RedisUnordered { .. }
            | RewriteDependencyRuleSpec::RedisTimeShift { .. }
            | RewriteDependencyRuleSpec::RedisCrossCase { .. }
    ) {
        record.review_fingerprint = Some(fingerprint::id(&[&serde_json::to_string(&report)?]));
    }
    state.rule_plan = None;
    state.recorder_capture_plan = None;
    state.dependency_rule_plan = Some(record.clone());
    state.bump();
    Ok(RewriteDependencyRulePlanReport {
        ownership: options.ownership,
        issue_id: issue.id,
        evidence_id: options.evidence_id,
        process_owned_rule_applicable: !request_rule,
        target_implementation_required: false,
        selector,
        plan_id: Some(record.id.clone()),
        traffic_e2e_report: Some(report),
        required_change: None,
        next_command: action::dependency_rule_apply_command(target_root, &record.id),
    })
}

pub(super) fn plan_memcached_timestamp(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteDependencyPayloadRulePlanOptions,
) -> Result<RewriteDependencyPayloadRulePlanReport> {
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    ensure!(
        matches!(
            issue.kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        ),
        "Memcached SET payload rules require response, replay, or dependency evidence"
    );
    validate_memcached_timestamp_evidence(
        target_root,
        state,
        &issue.id,
        &options.evidence_id,
        options.port,
    )?;
    let spec = RewriteDependencyRuleSpec::MemcachedProtobufTimestamp {
        rule_id: options.rule_id.clone(),
        port: options.port,
        key_prefix: options.key_prefix,
        key_suffix: options.key_suffix,
        field_number: options.field_number,
    };
    let spec_json = serde_json::to_string(&spec)?;
    let mut record = RewriteDependencyRulePlanRecord {
        review_fingerprint: None,
        id: format!(
            "dependency-plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                "memcached_protobuf_timestamp",
                &spec_json,
                &options.evidence_id,
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        evidence_id: options.evidence_id.clone(),
        name: options.rule_id,
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
    let traffic_e2e_report = plan.report()?;
    state.rule_plan = None;
    state.recorder_capture_plan = None;
    state.dependency_rule_plan = Some(record.clone());
    state.bump();
    Ok(RewriteDependencyPayloadRulePlanReport {
        issue_id: issue.id,
        evidence_id: options.evidence_id,
        plan_id: record.id.clone(),
        traffic_e2e_report,
        next_command: action::dependency_rule_apply_command(target_root, &record.id),
    })
}

fn classify_non_process_owned(
    target_root: &Path,
    state: &mut RewriteState,
    issue: super::model::RewriteIssue,
    options: RewriteDependencyRulePlanOptions,
    selector: Value,
) -> Result<RewriteDependencyRulePlanReport> {
    let (required_change, owner, cause) = match options.ownership {
        RewriteDependencyOwnership::RequestOwned => {
            let source_evidence = options
                .source_evidence
                .as_deref()
                .context("--source-evidence is required when --ownership request-owned")?;
            crate::config::process_owned_dependencies::validate_source_evidence(source_evidence)?;
            (
                format!(
                    "implement the recorded request-owned dependency call in target code; selector={}; source_evidence={source_evidence}",
                    serde_json::to_string(&selector)?
                ),
                super::model::RewriteIssueOwner::TargetCode,
                "request_owned_dependency_not_implemented",
            )
        }
        RewriteDependencyOwnership::Unresolved => (
            format!(
                "determine whether the recorded dependency is request-owned or process-owned before changing recorder classification; selector={}",
                serde_json::to_string(&selector)?
            ),
            super::model::RewriteIssueOwner::SourceInvestigation,
            "dependency_ownership_unresolved",
        ),
        RewriteDependencyOwnership::ProcessOwned => unreachable!("handled before classification"),
    };
    let active_issue = state
        .active_issue
        .as_mut()
        .context("rewrite workflow has no active issue")?;
    ensure!(
        active_issue.id == issue.id,
        "active rewrite issue changed while classifying dependency ownership"
    );
    active_issue.owner = owner;
    active_issue.summary = required_change.clone();
    active_issue.possible_causes = vec![cause.to_string()];
    state.dependency_rule_plan = None;
    state.bump();
    Ok(RewriteDependencyRulePlanReport {
        ownership: options.ownership,
        issue_id: issue.id,
        evidence_id: options.evidence_id,
        process_owned_rule_applicable: false,
        target_implementation_required: options.ownership
            == RewriteDependencyOwnership::RequestOwned,
        selector,
        plan_id: None,
        traffic_e2e_report: None,
        required_change: Some(required_change),
        next_command: action::next_command_for_api(target_root, &state.api),
    })
}

pub(super) fn apply(
    target_root: &Path,
    state: &mut RewriteState,
    plan_id: &str,
) -> Result<RewriteDependencyRuleReport> {
    let record = pending_plan_for_apply(state, plan_id)?;
    if matches!(
        record.spec,
        RewriteDependencyRuleSpec::HttpCrossCase { .. }
            | RewriteDependencyRuleSpec::HttpUnordered { .. }
            | RewriteDependencyRuleSpec::RedisUnordered { .. }
            | RewriteDependencyRuleSpec::RedisTimeShift { .. }
            | RewriteDependencyRuleSpec::RedisCrossCase { .. }
    ) {
        validate_plan_evidence(
            target_root,
            state,
            &record.issue_id,
            &record.evidence_id,
            &record.spec,
        )?;
    }
    if !matches!(
        &record.spec,
        RewriteDependencyRuleSpec::MemcachedProtobufTimestamp { .. }
            | RewriteDependencyRuleSpec::MysqlSqlTime { .. }
            | RewriteDependencyRuleSpec::HttpCrossCase { .. }
            | RewriteDependencyRuleSpec::HttpUnordered { .. }
            | RewriteDependencyRuleSpec::RedisUnordered { .. }
            | RewriteDependencyRuleSpec::RedisTimeShift { .. }
            | RewriteDependencyRuleSpec::RedisCrossCase { .. }
    ) && state.case_source.is_some()
        && state.group_id.is_some()
    {
        crate::e2e_run::ensure_focused_background_reclassification_revisable(
            E2eRunContext {
                target_root: target_root.to_path_buf(),
                case_source: state
                    .case_source
                    .clone()
                    .context("rewrite workflow has no case source to reclassify")?,
                run_key: None,
            },
            state
                .group_id
                .as_deref()
                .context("rewrite workflow has no focused API to reclassify")?,
        )?;
    }
    let plan = build_plan(target_root, state, &record)?;
    if let Some(reviewed) = &record.review_fingerprint {
        ensure!(
            *reviewed == fingerprint::id(&[&serde_json::to_string(&plan.report()?)?]),
            "dependency rule policy or evidence changed after plan; rerun plan before apply"
        );
    }
    let report = plan.apply()?;
    state.dependency_rule_plan = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(RewriteDependencyRuleReport {
        plan_id: record.id,
        issue_id: record.issue_id,
        traffic_e2e_report: report,
        evidence_reclassification: None,
        cache_snapshot_overlay: None,
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
        (matches!(
            spec,
            RewriteDependencyRuleSpec::MemcachedProtobufTimestamp { .. }
                | RewriteDependencyRuleSpec::MysqlSqlTime { .. }
                | RewriteDependencyRuleSpec::HttpCrossCase { .. }
                | RewriteDependencyRuleSpec::HttpUnordered { .. }
                | RewriteDependencyRuleSpec::RedisUnordered { .. }
                | RewriteDependencyRuleSpec::RedisTimeShift { .. }
                | RewriteDependencyRuleSpec::RedisCrossCase { .. }
        ) && matches!(
            issue.kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        )) || issue.kind == RewriteIssueKind::Dependency
            || (issue.kind == RewriteIssueKind::Response
                && matches!(
                    spec,
                    RewriteDependencyRuleSpec::RedisHashRead { .. }
                        | RewriteDependencyRuleSpec::RedisHscan { .. }
                )),
        "dependency rule is not applicable to the active issue"
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
    if !matches!(
        spec,
        RewriteDependencyRuleSpec::HttpCrossCase { .. }
            | RewriteDependencyRuleSpec::HttpUnordered { .. }
            | RewriteDependencyRuleSpec::RedisUnordered { .. }
            | RewriteDependencyRuleSpec::RedisTimeShift { .. }
            | RewriteDependencyRuleSpec::RedisCrossCase { .. }
    ) && state
        .dependency_rule_plan
        .as_ref()
        .is_some_and(|plan| plan.issue_id == issue_id && plan.evidence_id == evidence_id)
    {
        return Ok(());
    }

    let expected_query = if matches!(
        spec,
        RewriteDependencyRuleSpec::RedisHashRead { .. }
            | RewriteDependencyRuleSpec::RedisHscan { .. }
    ) && state
        .active_issue
        .as_ref()
        .is_some_and(|issue| issue.kind == RewriteIssueKind::Response)
    {
        "source_process_traffic"
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

fn validate_memcached_timestamp_evidence(
    target_root: &Path,
    state: &RewriteState,
    issue_id: &str,
    evidence_id: &str,
    port: u16,
) -> Result<()> {
    if state.dependency_rule_plan.as_ref().is_some_and(|plan| {
        plan.issue_id == issue_id
            && plan.evidence_id == evidence_id
            && matches!(
                plan.spec,
                RewriteDependencyRuleSpec::MemcachedProtobufTimestamp {
                    port: planned_port,
                    ..
                } if planned_port == port
            )
    }) {
        return Ok(());
    }
    let valid = evidence::commands(target_root, state)
        .into_iter()
        .filter_map(|command| evidence::query(target_root, state, &command.query_id).ok())
        .any(|report| {
            report.evidence_id == evidence_id
                && report.query == "dirty_clusters"
                && report
                    .facts
                    .get("clusters")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .any(|cluster| {
                        cluster.get("protocol").and_then(Value::as_str) == Some("memcached")
                            && cluster.pointer("/endpoint/port").and_then(Value::as_u64)
                                == Some(u64::from(port))
                            && cluster
                                .get("operations")
                                .and_then(Value::as_object)
                                .is_some_and(|operations| {
                                    operations
                                        .keys()
                                        .any(|operation| operation.eq_ignore_ascii_case("set"))
                                })
                    })
        });
    ensure!(
        valid,
        "Memcached timestamp-rule evidence is stale, does not describe a SET on port {port}, or belongs to another issue"
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
            | RewriteDependencyRuleSpec::RedisHscan { .. }
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
    let config_revision = fingerprint::project_config_revision(target_root)?;
    let rules_revision = fingerprint::source_traffic_policy_revision(target_root)?;
    let baseline_case_source = state.case_source.clone();
    let refresh = state
        .recording_refresh
        .get_or_insert_with(|| RewriteRecordingRefreshState {
            applied: Vec::new(),
            dependency_rules: Vec::new(),
            baseline_case_source: baseline_case_source.clone(),
            project_config_revision: config_revision.clone(),
            source_traffic_policy_revision: rules_revision.clone(),
            recording_run_id: None,
        });
    refresh.project_config_revision = config_revision;
    refresh.source_traffic_policy_revision = rules_revision;
    if refresh.baseline_case_source.is_none() {
        refresh.baseline_case_source = baseline_case_source;
    }
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

#[cfg(test)]
mod tests;

/// Endpoint value/scope rules can affect dependencies from any API.
pub(super) fn invalidate_dependency_matching_validation(state: &mut RewriteState) {
    state.e2e_current = false;
    state.comparison_current = false;
    state.target_quality_fingerprint = None;
    for item in &mut state.api_inventory {
        item.e2e_current = false;
        item.comparison_current = false;
        item.verified_target_fingerprint = None;
        if item.status == super::model::RewriteApiStatus::Complete {
            item.status = super::model::RewriteApiStatus::RevalidationPending;
        }
    }
    for slice in state.parked_slices.values_mut() {
        slice.e2e_current = false;
        slice.comparison_current = false;
        slice.target_fingerprint = None;
    }
}
