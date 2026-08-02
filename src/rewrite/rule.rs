use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::fingerprint;
use super::model::{RewriteRulePlanRecord, RewriteRuleReport, RewriteState};
use super::{action, evidence};
use crate::{
    ComparisonResponseRuleFeedback, DynamicResponseMechanism, E2eRunContext, ResponseRuleFeedback,
    ResponseRuleKind, ResponseRulePlan, plan_comparison_response_rule, plan_response_rule,
    resolve_e2e_response_rule_evidence,
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

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    validate_evidence(target_root, state, &options.evidence_id)?;
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
        evidence_id: options.evidence_id,
    };
    let traffic_plan = build_plan(target_root, state, &record)?;
    let traffic_report = project_report(traffic_plan.report())?;
    state.dependency_rule_plan = None;
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
    validate_evidence(target_root, state, &record.evidence_id)?;
    let report = build_plan(target_root, state, &record)?.apply()?;
    let projected = project_report(&report)?;
    state.rule_plan = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id,
        issue_id: record.issue_id,
        traffic_e2e_report: projected,
        next_command: action::command(
            target_root,
            vec![
                "traffic-e2e".to_string(),
                "rewrite".to_string(),
                "next".to_string(),
            ],
            Vec::new(),
        ),
    })
}

fn build_plan(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteRulePlanRecord,
) -> Result<ResponseRulePlan> {
    let kind = parse_rule_kind(&record.kind)?;
    let mechanisms = record
        .dynamic_mechanisms
        .iter()
        .map(|value| parse_mechanism(value))
        .collect::<Result<Vec<_>>>()?;
    let policy_path = target_root.join(".traffic-e2e/verification.yaml");
    let comparison_run = state.comparison_run_id.as_ref().map(|run_id| {
        target_root
            .join(".traffic-e2e/artifacts/comparison-recordings")
            .join(run_id)
    });
    if kind == ResponseRuleKind::Counter
        || state
            .active_issue
            .as_ref()
            .is_some_and(|issue| issue.kind == super::model::RewriteIssueKind::Comparison)
    {
        let comparison_run = comparison_run.context("comparison rule requires a comparison run")?;
        return plan_comparison_response_rule(ComparisonResponseRuleFeedback {
            policy_path,
            kind,
            api: state.api.clone(),
            json_pointers: vec![record.json_pointer.clone()],
            dynamic_mechanisms: mechanisms,
            source_evidence: record.source_evidence.clone(),
            source_example: record.source_example.clone(),
            target_example: record.target_example.clone(),
            comparison_report: comparison_run.join("comparison-report.json"),
        });
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
    plan_response_rule(ResponseRuleFeedback {
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
    })
}

fn validate_evidence(target_root: &Path, state: &RewriteState, evidence_id: &str) -> Result<()> {
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

fn project_report(report: &crate::ResponseRuleReport) -> Result<Value> {
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
