use crate::unified_rule::UnifiedRulePlanRecordMethods;
use std::path::Path;
use traffic_rewrite_rules::rewrite::response_rule::{
    VerificationRulePlan, build_plan, has_generated_rule, record,
};

use anyhow::{Context, Result, ensure};
use serde_json::json;

use super::fingerprint;
use super::model::{RewriteRulePlanRecord, RewriteRuleReport, RewriteState};
use super::{action, evidence};
mod generated_values;
use crate::ResponseBodyCodec;

pub use traffic_rewrite_rules::rewrite::response_rule::record::RewriteRulePlanOptions;

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    crate::policy::retired_authoring()?;
    if !options.response_jwts.is_empty()
        || !options.header_dates.is_empty()
        || options.dynamic_value.is_some()
        || options.mysql_time.is_some()
        || options.redis_time.is_some()
        || options.dependency_request.is_some()
    {
        return generated_values::plan(target_root, state, options);
    }
    if let Some(jwt) = options.jwt {
        ensure!(
            options.body_codec == ResponseBodyCodec::Json
                && options.kind.is_none()
                && options.json_pointer.is_none()
                && options.source_example.is_none()
                && options.target_example.is_none()
                && options.separator.is_none()
                && options.time.is_none()
                && options.unordered_paths.is_empty()
                && options.unordered_joined_string_paths.is_empty()
                && options.docx_timestamps.is_empty(),
            "JWT request rules cannot carry response rule options"
        );
        return super::jwt_rule::plan(
            target_root,
            state,
            options.evidence_id,
            options.source_evidence,
            jwt,
        );
    }
    match options.body_codec {
        ResponseBodyCodec::Json => plan_json(target_root, state, options),
        ResponseBodyCodec::Protobuf | ResponseBodyCodec::Hessian2 | ResponseBodyCodec::Docx => {
            plan_response_body(target_root, state, options)
        }
        codec => anyhow::bail!("response rule cannot be planned for body codec {codec:?}"),
    }
}

fn plan_json(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    ensure!(
        options.unordered_paths.is_empty()
            && options.unordered_joined_string_paths.is_empty()
            && options.docx_timestamps.is_empty(),
        "JSON response rules cannot carry typed response-body paths"
    );
    let kind = options
        .kind
        .context("JSON response rule plan requires --kind")?;
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    validate_plan_evidence(target_root, state, &issue.id, &options.evidence_id)?;
    let mut record = record::json(state, &issue, kind, options)?;
    let traffic_plan = build_plan(target_root, state, &record)?;
    if let VerificationRulePlan::Response(plan) = &traffic_plan {
        record.generated_witnesses = plan.time_evidence_witnesses();
    }
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

fn plan_response_body(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    ensure!(
        options.kind.is_none()
            && options.json_pointer.is_none()
            && options.source_evidence.is_none()
            && options.source_example.is_none()
            && options.target_example.is_none()
            && options.separator.is_none()
            && options.time.is_none(),
        "typed response-body rules cannot carry JSON rule arguments"
    );
    match options.body_codec {
        ResponseBodyCodec::Docx => ensure!(
            options.unordered_paths.is_empty() && options.unordered_joined_string_paths.is_empty(),
            "DOCX response-body rules use --docx-timestamp, not typed collection paths"
        ),
        ResponseBodyCodec::Protobuf | ResponseBodyCodec::Hessian2 => ensure!(
            options.docx_timestamps.is_empty(),
            "protobuf and Hessian2 response-body rules cannot carry DOCX timestamps"
        ),
        _ => {}
    }
    validate_response_body_plan_evidence(
        target_root,
        state,
        &issue.id,
        &options.evidence_id,
        options.body_codec,
    )?;
    let record = record::body(state, &issue, options)?;
    let traffic_report = build_plan(target_root, state, &record)?.report()?;
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
    if record.unified.is_some() {
        return super::unified_rule::apply(target_root, state, record);
    }
    if record.time.is_some() {
        crate::GeneratedValueRulePlan::ensure_evidence_current(&record.generated_witnesses)?;
    }
    if record.jwt.is_some() {
        return super::jwt_rule::apply(target_root, state, record);
    }
    let projected = build_plan(target_root, state, &record)?.apply()?;
    state.rule_plan = None;
    super::rule_replay::request(state);
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id,
        issue_id: record.issue_id,
        traffic_e2e_report: projected,
        next_command: action::next_command(target_root),
    })
}

pub(super) fn pending_plan_for_apply(
    state: &RewriteState,
    plan_id: &str,
) -> Result<RewriteRulePlanRecord> {
    let record = state
        .rule_plan
        .clone()
        .context("rewrite workflow has no pending rule plan")?;
    ensure!(
        record.id == plan_id,
        "rule plan is stale or belongs to another issue"
    );
    ensure!(
        record
            .unified
            .as_ref()
            .is_some_and(|plan| !plan.is_api_issue())
            || state.active_issue.as_ref().map(|issue| issue.id.as_str())
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
    if let Some(plan) = state
        .rule_plan
        .as_ref()
        .filter(|plan| plan.issue_id == issue_id && plan.evidence_id == evidence_id)
    {
        if has_generated_rule(plan) || plan.time.is_some() {
            crate::GeneratedValueRulePlan::ensure_evidence_current(&plan.generated_witnesses)
                .context("pending generated-value evidence is stale; recover the plan and run fresh Replay")?;
        }
        return Ok(());
    }

    for command in evidence::commands(target_root, state) {
        let Ok(report) = evidence::query(target_root, state, &command.query_id) else {
            continue;
        };
        if report.evidence_id == evidence_id {
            evidence::policy_freshness::ensure_plannable(&report)?;
            return Ok(());
        }
    }
    anyhow::bail!(
        "evidence id is stale or belongs to another active issue; query current evidence again. If verification.yaml changed, run fresh Replay using the existing recordings before planning"
    )
}

fn validate_response_body_plan_evidence(
    target_root: &Path,
    state: &RewriteState,
    issue_id: &str,
    evidence_id: &str,
    codec: ResponseBodyCodec,
) -> Result<()> {
    if state.rule_plan.as_ref().is_some_and(|plan| {
        plan.issue_id == issue_id
            && plan.evidence_id == evidence_id
            && plan
                .response_body
                .as_ref()
                .is_some_and(|body| body.codec == codec)
    }) {
        return Ok(());
    }

    let valid = evidence::commands(target_root, state)
        .into_iter()
        .filter_map(|command| evidence::query(target_root, state, &command.query_id).ok())
        .any(|report| {
            report.evidence_id == evidence_id
                && report.query == "representatives"
                && evidence::supports_response_body_codec(&report.facts, codec)
        });
    ensure!(
        valid,
        "response-body evidence is stale, belongs to another issue, or does not support the selected codec"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
