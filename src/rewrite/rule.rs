use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::fingerprint;
use super::model::{
    RewriteMemcachedTimestampRuleSpec, RewriteRulePlanRecord, RewriteRuleReport, RewriteState,
};
use super::{action, evidence};
use crate::{
    ComparisonResponseRuleFeedback, DynamicResponseMechanism, E2eRunContext,
    MemcachedTimestampRuleFeedback, MemcachedTimestampRulePlan, ResponseRuleFeedback,
    ResponseRuleKind, ResponseRulePlan, plan_comparison_response_rule,
    plan_memcached_timestamp_rule, plan_response_rule, resolve_e2e_response_rule_evidence,
};

#[derive(Debug, Clone)]
pub struct RewriteRulePlanOptions {
    pub evidence_id: String,
    pub kind: ResponseRuleKind,
    pub json_pointer: Option<String>,
    pub dynamic_mechanisms: Vec<DynamicResponseMechanism>,
    pub source_evidence: Option<String>,
    pub source_example: Option<String>,
    pub target_example: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RewriteMemcachedTimestampRulePlanOptions {
    pub evidence_id: String,
    pub rule_id: String,
    pub port: u16,
    pub key_prefix: String,
    pub key_suffix: String,
    pub field_number: u32,
    pub source_evidence: String,
}

enum VerificationRulePlan {
    Response(ResponseRulePlan),
    MemcachedTimestamp(MemcachedTimestampRulePlan),
}

impl VerificationRulePlan {
    fn report(&self) -> Result<Value> {
        match self {
            Self::Response(plan) => project_response_report(plan.report()),
            Self::MemcachedTimestamp(plan) => Ok(project_memcached_report(plan.report())),
        }
    }

    fn apply(self) -> Result<Value> {
        match self {
            Self::Response(plan) => project_response_report(&plan.apply()?),
            Self::MemcachedTimestamp(plan) => Ok(project_memcached_report(&plan.apply()?)),
        }
    }
}

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    validate_plan_evidence(target_root, state, &issue.id, &options.evidence_id)?;
    let pointer = options
        .json_pointer
        .or_else(|| {
            issue
                .representative
                .as_ref()
                .map(|representative| representative.pointer.clone())
        })
        .or_else(|| {
            issue.comparison_observation.as_ref().and_then(|value| {
                value
                    .get("pointer")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        })
        .context("rule plan requires a representative JSON Pointer")?;
    let record = RewriteRulePlanRecord {
        id: format!(
            "plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                &format!("{:?}", options.kind),
                &pointer,
                &options.evidence_id,
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        kind: rule_kind(options.kind).to_string(),
        json_pointer: pointer,
        dynamic_mechanisms: options
            .dynamic_mechanisms
            .iter()
            .map(|mechanism| mechanism_name(*mechanism).to_string())
            .collect(),
        source_evidence: options.source_evidence,
        source_example: options.source_example,
        target_example: options.target_example,
        memcached_timestamp: None,
        evidence_id: options.evidence_id,
    };
    let traffic_plan = build_plan(target_root, state, &record)?;
    let traffic_report = traffic_plan.report()?;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.rule_plan = Some(record.clone());
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id.clone(),
        issue_id: issue.id,
        traffic_e2e_report: traffic_report,
        next_command: action::rule_apply_command(target_root, &record.id),
    })
}

pub(super) fn plan_memcached_timestamp(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteMemcachedTimestampRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    ensure!(
        matches!(
            issue.kind,
            super::model::RewriteIssueKind::Response
                | super::model::RewriteIssueKind::Dependency
                | super::model::RewriteIssueKind::Replay
        ),
        "Memcached SET payload rules require response, replay, or dependency dirty evidence"
    );
    validate_memcached_plan_evidence(
        target_root,
        state,
        &issue.id,
        &options.evidence_id,
        options.port,
    )?;
    let spec = RewriteMemcachedTimestampRuleSpec {
        rule_id: options.rule_id,
        port: options.port,
        key_prefix: options.key_prefix,
        key_suffix: options.key_suffix,
        field_number: options.field_number,
        source_evidence: options.source_evidence,
    };
    let spec_json = serde_json::to_string(&spec)?;
    let record = RewriteRulePlanRecord {
        id: format!(
            "plan-{}",
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
        kind: "memcached_protobuf_timestamp".to_string(),
        json_pointer: String::new(),
        dynamic_mechanisms: Vec::new(),
        source_evidence: None,
        source_example: None,
        target_example: None,
        memcached_timestamp: Some(spec),
        evidence_id: options.evidence_id,
    };
    let traffic_plan = build_plan(target_root, state, &record)?;
    let traffic_report = traffic_plan.report()?;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.rule_plan = Some(record.clone());
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id.clone(),
        issue_id: issue.id,
        traffic_e2e_report: traffic_report,
        next_command: action::rule_apply_command(target_root, &record.id),
    })
}

pub(super) fn apply(
    target_root: &Path,
    state: &mut RewriteState,
    plan_id: &str,
) -> Result<RewriteRuleReport> {
    let record = pending_plan_for_apply(state, plan_id)?;
    let projected = build_plan(target_root, state, &record)?.apply()?;
    state.rule_plan = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id,
        issue_id: record.issue_id,
        traffic_e2e_report: projected,
        next_command: action::next_command_for_api(target_root, &state.api),
    })
}

fn build_plan(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteRulePlanRecord,
) -> Result<VerificationRulePlan> {
    if let Some(spec) = &record.memcached_timestamp {
        return Ok(VerificationRulePlan::MemcachedTimestamp(
            plan_memcached_timestamp_rule(MemcachedTimestampRuleFeedback {
                policy_path: target_root.join(".traffic-e2e/verification.yaml"),
                rule_id: spec.rule_id.clone(),
                port: spec.port,
                key_prefix: spec.key_prefix.clone(),
                key_suffix: spec.key_suffix.clone(),
                field_number: spec.field_number,
                source_evidence: spec.source_evidence.clone(),
            })?,
        ));
    }
    let kind = parse_rule_kind(&record.kind)?;
    let mechanisms = record
        .dynamic_mechanisms
        .iter()
        .map(|value| parse_mechanism(value))
        .collect::<Result<Vec<_>>>()?;
    let policy_path = target_root.join(".traffic-e2e/verification.yaml");
    let comparison_run = state.comparison_run_id.as_ref().map(|run_id| {
        target_root
            .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("comparison-recordings")
            .join(run_id)
    });
    if kind == ResponseRuleKind::Counter
        || state
            .active_issue
            .as_ref()
            .is_some_and(|issue| issue.kind == super::model::RewriteIssueKind::Comparison)
    {
        let comparison_run = comparison_run.context("comparison rule requires a comparison run")?;
        return Ok(VerificationRulePlan::Response(
            plan_comparison_response_rule(ComparisonResponseRuleFeedback {
                policy_path,
                kind,
                api: state.api.clone(),
                json_pointers: vec![record.json_pointer.clone()],
                dynamic_mechanisms: mechanisms,
                source_evidence: record.source_evidence.clone(),
                source_example: record.source_example.clone(),
                target_example: record.target_example.clone(),
                comparison_report: comparison_run.join("comparison-report.json"),
            })?,
        ));
    }
    let case_source = state
        .case_source
        .clone()
        .context("replay rule requires a finalized case source")?;
    let api = state
        .group_id
        .as_deref()
        .context("replay rule requires a prepared API group")?;
    let evidence = resolve_e2e_response_rule_evidence(
        E2eRunContext {
            target_root: target_root.to_path_buf(),
            case_source,
            run_key: None,
        },
        api,
    )?;
    Ok(VerificationRulePlan::Response(plan_response_rule(
        ResponseRuleFeedback {
            policy_path,
            kind,
            api: state.api.clone(),
            json_pointers: vec![record.json_pointer.clone()],
            dynamic_mechanisms: mechanisms,
            source_evidence: record.source_evidence.clone(),
            source_example: record.source_example.clone(),
            target_example: record.target_example.clone(),
            assertion_report: evidence.assertions,
            aggregate_report: evidence.aggregate,
        },
    )?))
}

fn pending_plan_for_apply(state: &RewriteState, plan_id: &str) -> Result<RewriteRulePlanRecord> {
    let record = state
        .rule_plan
        .clone()
        .context("rewrite workflow has no pending rule plan")?;
    ensure!(
        record.id == plan_id,
        "rule plan is stale or belongs to another issue"
    );
    ensure!(
        state.active_issue.as_ref().map(|issue| issue.id.as_str())
            == Some(record.issue_id.as_str()),
        "active rewrite issue changed after rule planning"
    );
    Ok(record)
}

fn validate_plan_evidence(
    target_root: &Path,
    state: &RewriteState,
    issue_id: &str,
    evidence_id: &str,
) -> Result<()> {
    if state
        .rule_plan
        .as_ref()
        .is_some_and(|plan| plan.issue_id == issue_id && plan.evidence_id == evidence_id)
    {
        return Ok(());
    }

    let valid = evidence::commands(target_root, state)
        .into_iter()
        .any(|command| {
            evidence::query(target_root, state, &command.query_id)
                .is_ok_and(|report| report.evidence_id == evidence_id)
        });
    ensure!(
        valid,
        "evidence id is stale or belongs to another active issue"
    );
    Ok(())
}

fn validate_memcached_plan_evidence(
    target_root: &Path,
    state: &RewriteState,
    issue_id: &str,
    evidence_id: &str,
    port: u16,
) -> Result<()> {
    if state.rule_plan.as_ref().is_some_and(|plan| {
        plan.issue_id == issue_id
            && plan.evidence_id == evidence_id
            && plan
                .memcached_timestamp
                .as_ref()
                .is_some_and(|spec| spec.port == port)
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

fn project_response_report(report: &crate::ResponseRuleReport) -> Result<Value> {
    Ok(json!({
        "kind": report.kind,
        "api": report.api,
        "json_pointers": report.json_pointers,
        "matching_cases": report.matching_cases,
        "selected_difference_cases": report.selected_difference_cases,
        "unselected_difference_pointers": report.unselected_difference_pointers,
        "aggregate_dirty": report.aggregate_dirty,
        "changed": report.changed,
        "applied": report.applied,
        "added_rule_ids": report.added_rule_ids,
        "diff": report.diff,
    }))
}

fn project_memcached_report(report: &crate::MemcachedTimestampRuleReport) -> Value {
    json!({
        "kind": "memcached_protobuf_timestamp",
        "requested_rule_id": report.requested_rule_id,
        "effective_rule_id": report.effective_rule_id,
        "resource": {
            "kind": report.resource_kind,
            "port": report.port,
        },
        "command": report.command,
        "key": {
            "prefix": report.key_prefix,
            "suffix": report.key_suffix,
            "numeric_middle_required": true,
        },
        "protobuf_field_number": report.protobuf_field_number,
        "mechanism": report.mechanism,
        "fixed_tolerance_seconds": report.fixed_tolerance_seconds,
        "reused_existing": report.reused_existing,
        "changed": report.changed,
        "applied": report.applied,
        "diff": report.diff,
    })
}

fn rule_kind(kind: ResponseRuleKind) -> &'static str {
    match kind {
        ResponseRuleKind::Dynamic => "dynamic",
        ResponseRuleKind::Unordered => "unordered",
        ResponseRuleKind::Counter => "counter",
    }
}

fn parse_rule_kind(value: &str) -> Result<ResponseRuleKind> {
    match value {
        "dynamic" => Ok(ResponseRuleKind::Dynamic),
        "unordered" => Ok(ResponseRuleKind::Unordered),
        "counter" => Ok(ResponseRuleKind::Counter),
        _ => anyhow::bail!("unsupported rewrite rule kind {value:?}"),
    }
}

fn mechanism_name(mechanism: DynamicResponseMechanism) -> &'static str {
    match mechanism {
        DynamicResponseMechanism::Timestamp => "timestamp",
        DynamicResponseMechanism::Duration => "duration",
        DynamicResponseMechanism::Uuid => "uuid",
        DynamicResponseMechanism::Random => "random",
        DynamicResponseMechanism::Nonce => "nonce",
        DynamicResponseMechanism::RandomSalt => "random_salt",
        DynamicResponseMechanism::DynamicDerived => "dynamic_derived",
    }
}

#[cfg(test)]
mod tests;

fn parse_mechanism(value: &str) -> Result<DynamicResponseMechanism> {
    match value {
        "timestamp" => Ok(DynamicResponseMechanism::Timestamp),
        "duration" => Ok(DynamicResponseMechanism::Duration),
        "uuid" => Ok(DynamicResponseMechanism::Uuid),
        "random" => Ok(DynamicResponseMechanism::Random),
        "nonce" => Ok(DynamicResponseMechanism::Nonce),
        "random_salt" => Ok(DynamicResponseMechanism::RandomSalt),
        "dynamic_derived" => Ok(DynamicResponseMechanism::DynamicDerived),
        _ => anyhow::bail!("unsupported dynamic mechanism {value:?}"),
    }
}
