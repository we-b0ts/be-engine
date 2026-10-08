use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::fingerprint;
use super::model::{
    RewriteResponseBodyRuleSpec, RewriteRulePlanRecord, RewriteRuleReport, RewriteState,
};
use super::{action, evidence};
mod generated_values;
use crate::{
    ComparisonResponseRuleFeedback, DocxTimestampRule, E2eRunContext, ResponseBodyCodec,
    ResponseBodyJoinedStringPath, ResponseBodyRuleEvidence, ResponseBodyRuleFeedback,
    ResponseBodyRulePlan, ResponseBodyUnorderedPath, ResponseRuleFeedback, ResponseRuleKind,
    ResponseRulePlan, plan_comparison_response_rule, plan_response_body_rule, plan_response_rule,
    resolve_e2e_response_rule_evidence,
};

#[derive(Debug, Clone)]
pub struct RewriteRulePlanOptions {
    pub header_dates: Vec<crate::ResponseHeaderDateRule>,
    pub dynamic_value: Option<crate::DynamicValueRule>,
    pub evidence_id: String,
    pub jwt: Option<super::jwt_rule::JwtRulePlanOptions>,
    pub body_codec: ResponseBodyCodec,
    pub kind: Option<ResponseRuleKind>,
    pub time: Option<crate::ResponseTimeRule>,
    pub json_pointer: Option<String>,
    pub source_evidence: Option<String>,
    pub source_example: Option<String>,
    pub target_example: Option<String>,
    pub separator: Option<String>,
    pub unordered_paths: Vec<ResponseBodyUnorderedPath>,
    pub unordered_joined_string_paths: Vec<ResponseBodyJoinedStringPath>,
    pub docx_timestamps: Vec<DocxTimestampRule>,
}

enum VerificationRulePlan {
    Generated(Box<crate::GeneratedValueRulePlan>),
    Response(Box<ResponseRulePlan>),
    Body(Box<ResponseBodyRulePlan>),
}

impl VerificationRulePlan {
    fn report(&self) -> Result<Value> {
        match self {
            Self::Generated(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::Response(plan) => project_response_report(plan.report()),
            Self::Body(plan) => Ok(project_body_report(plan.report())),
        }
    }

    fn apply(self) -> Result<Value> {
        match self {
            Self::Generated(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::Response(plan) => project_response_report(&plan.apply()?),
            Self::Body(plan) => Ok(project_body_report(&plan.apply()?)),
        }
    }
}

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    if !options.header_dates.is_empty() || options.dynamic_value.is_some() {
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
        header_dates: Vec::new(),
        dynamic_value: None,
        id: format!(
            "plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                &format!("{kind:?}"),
                &pointer,
                &options.evidence_id,
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        kind: rule_kind(kind).to_string(),
        json_pointer: pointer,
        time: options.time,
        source_evidence: options.source_evidence,
        source_example: options.source_example,
        target_example: options.target_example,
        separator: options.separator,
        response_body: None,
        jwt: None,
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
    let spec = RewriteResponseBodyRuleSpec {
        codec: options.body_codec,
        unordered_paths: options.unordered_paths,
        unordered_joined_string_paths: options.unordered_joined_string_paths,
        docx_timestamps: options.docx_timestamps,
    };
    let spec_json = serde_json::to_string(&spec)?;
    let record = RewriteRulePlanRecord {
        header_dates: Vec::new(),
        dynamic_value: None,
        id: format!(
            "plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                "response_body",
                &spec_json,
                &options.evidence_id,
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        kind: "response_body".to_string(),
        json_pointer: String::new(),
        time: None,
        source_evidence: None,
        source_example: None,
        target_example: None,
        separator: None,
        response_body: Some(spec),
        jwt: None,
        evidence_id: options.evidence_id,
    };
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
        next_command: action::next_command_for_selected_api(target_root, state, &state.api),
    })
}

fn build_plan(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteRulePlanRecord,
) -> Result<VerificationRulePlan> {
    if record.dynamic_value.is_some() || !record.header_dates.is_empty() {
        return Ok(VerificationRulePlan::Generated(Box::new(
            generated_values::build(target_root, state, record)?,
        )));
    }
    if let Some(spec) = &record.response_body {
        let evidence = if state
            .active_issue
            .as_ref()
            .is_some_and(|issue| issue.kind == super::model::RewriteIssueKind::Comparison)
        {
            let comparison_run = state
                .comparison_run_id
                .as_ref()
                .context("comparison response rule requires a comparison run")?;
            ResponseBodyRuleEvidence::Comparison {
                comparison_report: target_root
                    .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
                    .join("comparison-recordings")
                    .join(comparison_run)
                    .join("comparison-report.json"),
            }
        } else {
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
        return Ok(VerificationRulePlan::Response(Box::new(
            plan_comparison_response_rule(ComparisonResponseRuleFeedback {
                time: record.time,
                policy_path,
                kind,
                api: state.api.clone(),
                json_pointers: vec![record.json_pointer.clone()],
                source_evidence: record.source_evidence.clone(),
                source_example: record.source_example.clone(),
                target_example: record.target_example.clone(),
                separator: record.separator.clone(),
                comparison_report: comparison_run.join("comparison-report.json"),
            })?,
        )));
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

fn project_response_report(report: &crate::ResponseRuleReport) -> Result<Value> {
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

fn project_body_report(report: &crate::ResponseBodyRuleReport) -> Value {
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

fn rule_kind(kind: ResponseRuleKind) -> &'static str {
    match kind {
        ResponseRuleKind::Timestamp => "timestamp",
        ResponseRuleKind::Duration => "duration",
        ResponseRuleKind::Uuid => "uuid",
        ResponseRuleKind::Random => "random",
        ResponseRuleKind::Unordered => "unordered",
        ResponseRuleKind::UnorderedJoinedString => "unordered_joined_string",
        ResponseRuleKind::Counter => "counter",
    }
}

fn parse_rule_kind(value: &str) -> Result<ResponseRuleKind> {
    match value {
        "timestamp" => Ok(ResponseRuleKind::Timestamp),
        "duration" => Ok(ResponseRuleKind::Duration),
        "uuid" => Ok(ResponseRuleKind::Uuid),
        "random" => Ok(ResponseRuleKind::Random),
        "unordered" => Ok(ResponseRuleKind::Unordered),
        "unordered_joined_string" => Ok(ResponseRuleKind::UnorderedJoinedString),
        "counter" => Ok(ResponseRuleKind::Counter),
        _ => anyhow::bail!("unsupported rewrite rule kind {value:?}"),
    }
}

#[cfg(test)]
mod tests;
