//! Verification rule planning and report projection over authenticated execution evidence.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
use traffic_engine::{
    E2eRunContext, ResponseBodyRuleEvidence, ResponseBodyRuleFeedback, ResponseBodyRulePlan,
    ResponseRuleFeedback, ResponseRuleKind, ResponseRulePlan, plan_response_body_rule,
    plan_response_rule, resolve_e2e_response_rule_evidence,
};
use traffic_rewrite_model::rewrite::model::{RewriteRulePlanRecord, RewriteState};
pub mod generated_values;
pub mod record;

pub enum VerificationRulePlan {
    Generated(Box<crate::GeneratedValueRulePlan>),
    Response(Box<ResponseRulePlan>),
    Body(Box<ResponseBodyRulePlan>),
}

impl VerificationRulePlan {
    pub fn report(&self) -> Result<Value> {
        match self {
            Self::Generated(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Response(plan) => project_response_report(plan.report()),
            Self::Body(plan) => Ok(project_body_report(plan.report())),
        }
    }

    pub fn apply(self) -> Result<Value> {
        match self {
            Self::Generated(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Response(plan) => project_response_report(&plan.apply()?),
            Self::Body(plan) => Ok(project_body_report(&plan.apply()?)),
        }
    }
}

pub fn build_plan(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteRulePlanRecord,
) -> Result<VerificationRulePlan> {
    if has_generated_rule(record) {
        return Ok(VerificationRulePlan::Generated(Box::new(
            generated_values::build(target_root, state, record)?,
        )));
    }
    if let Some(spec) = &record.response_body {
        let evidence = {
            let case_source = state
                .case_source
                .clone()
                .context("response rule requires a finalized case source")?;
            let group_id = state
                .group_id
                .as_deref()
                .context("response rule requires a prepared API group")?;
            let evidence = resolve_e2e_response_rule_evidence(
                E2eRunContext {
                    target_root: target_root.to_path_buf(),
                    case_source,
                    run_key: None,
                },
                group_id,
            )?;
            ResponseBodyRuleEvidence::FocusedE2e {
                assertion_report: evidence.assertions,
                aggregate_report: evidence.aggregate,
            }
        };
        return Ok(VerificationRulePlan::Body(Box::new(
            plan_response_body_rule(ResponseBodyRuleFeedback {
                policy_path: target_root.join(".traffic-e2e/verification.yaml"),
                api: state.api.clone(),
                codec: spec.codec,
                unordered_paths: spec.unordered_paths.clone(),
                unordered_joined_string_paths: spec.unordered_joined_string_paths.clone(),
                docx_timestamps: spec.docx_timestamps.clone(),
                evidence,
            })?,
        )));
    }
    let kind = parse_rule_kind(&record.kind)?;
    let policy_path = target_root.join(".traffic-e2e/verification.yaml");
    {}
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
    Ok(VerificationRulePlan::Response(Box::new(
        plan_response_rule(ResponseRuleFeedback {
            time: record.time,
            policy_path,
            kind,
            api: state.api.clone(),
            json_pointers: vec![record.json_pointer.clone()],
            source_evidence: record.source_evidence.clone(),
            source_example: record.source_example.clone(),
            target_example: record.target_example.clone(),
            separator: record.separator.clone(),
            assertion_report: evidence.assertions,
            aggregate_report: evidence.aggregate,
        })?,
    )))
}

pub fn has_generated_rule(record: &RewriteRulePlanRecord) -> bool {
    !record.response_jwts.is_empty()
        || record.dependency_request.is_some()
        || record.dynamic_value.is_some()
        || record.mysql_time.is_some()
        || record.redis_time.is_some()
        || !record.header_dates.is_empty()
}

pub fn project_response_report(report: &crate::ResponseRuleReport) -> Result<Value> {
    Ok(json!({
        "kind": report.kind,
        "api": report.api,
        "json_pointers": report.json_pointers,
        "separator": report.separator,
        "time": report.time,
        "matching_cases": report.matching_cases,
        "selected_difference_cases": report.selected_difference_cases,
        "residual_difference_cases": report.residual_difference_cases,
        "unselected_difference_pointers": report.unselected_difference_pointers,
        "aggregate_dirty": report.aggregate_dirty,
        "changed": report.changed,
        "applied": report.applied,
        "added_rule_ids": report.added_rule_ids,
        "diff": report.diff,
    }))
}

pub fn project_body_report(report: &crate::ResponseBodyRuleReport) -> Value {
    json!({
        "kind": "response_body",
        "api": report.api,
        "rule_id": report.rule_id,
        "body_codec": report.codec,
        "matching_cases": report.matching_cases,
        "selected_difference_cases": report.selected_difference_cases,
        "residual_difference_cases": report.residual_difference_cases,
        "discovered_unordered_paths": report.discovered_unordered_paths,
        "effective_unordered_paths": report.effective_unordered_paths,
        // Always emit joined-string paths (empty when none) so downstream
        // tooling sees that the rule family exists for every structured codec.
        "discovered_unordered_joined_string_paths": report.discovered_unordered_joined_string_paths,
        "effective_unordered_joined_string_paths": report.effective_unordered_joined_string_paths,
        "offline_verification": report.offline_verification,
        "order_only": report.order_only,
        "changed": report.changed,
        "applied": report.applied,
        "diff": report.diff,
    })
}

pub fn rule_kind(kind: ResponseRuleKind) -> &'static str {
    match kind {
        ResponseRuleKind::Timestamp => "timestamp",
        ResponseRuleKind::Duration => "duration",
        ResponseRuleKind::Uuid => "uuid",
        ResponseRuleKind::Random => "random",
        ResponseRuleKind::Jwt => "jwt",
        ResponseRuleKind::Unordered => "unordered",
        ResponseRuleKind::UnorderedJoinedString => "unordered_joined_string",
    }
}

pub fn parse_rule_kind(value: &str) -> Result<ResponseRuleKind> {
    match value {
        "timestamp" => Ok(ResponseRuleKind::Timestamp),
        "duration" => Ok(ResponseRuleKind::Duration),
        "uuid" => Ok(ResponseRuleKind::Uuid),
        "random" => Ok(ResponseRuleKind::Random),
        "unordered" => Ok(ResponseRuleKind::Unordered),
        "unordered_joined_string" => Ok(ResponseRuleKind::UnorderedJoinedString),
        _ => anyhow::bail!("unsupported rewrite rule kind {value:?}"),
    }
}
