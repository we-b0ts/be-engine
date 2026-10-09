//! Coordinator lifecycle for case-local identities and response header dates.
use super::*;
use crate::{DynamicValueRuleFeedback, GeneratedValueRulePlan, ResponseHeaderDateRuleFeedback};

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    mut options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    ensure!(
        options.jwt.is_none()
            && options.body_codec == ResponseBodyCodec::Json
            && options.kind.is_none()
            && options.time.is_none()
            && options.json_pointer.is_none()
            && options.source_example.is_none()
            && options.target_example.is_none()
            && options.separator.is_none()
            && options.unordered_paths.is_empty()
            && options.unordered_joined_string_paths.is_empty()
            && options.docx_timestamps.is_empty(),
        "generated value rules cannot carry request/body rule options"
    );
    ensure!(
        (usize::from(options.dynamic_value.is_some())
            + usize::from(options.dependency_request.is_some())
            + usize::from(!options.header_dates.is_empty()))
            == 1,
        "plan one generated value rule family at a time"
    );
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    validate_plan_evidence(target_root, state, &issue.id, &options.evidence_id)?;
    if let Some(rule) = &mut options.dynamic_value {
        ensure!(
            matches!(
                issue.kind,
                super::super::model::RewriteIssueKind::Response
                    | super::super::model::RewriteIssueKind::Replay
                    | super::super::model::RewriteIssueKind::Dependency
            ),
            "dynamic identity rules require Replay dependency evidence"
        );
        rule.api = super::super::api_selector::public_api(&state.api).into();
        if rule.source_evidence.is_empty() {
            rule.source_evidence = options.source_evidence.clone().unwrap_or_default();
        }
    }
    if let Some(rule) = &mut options.dependency_request {
        ensure!(
            issue.kind != super::super::model::RewriteIssueKind::Comparison,
            "dependency requests require Replay evidence"
        );
        let api = &state.api;
        let (method, path) = api
            .split_once(' ')
            .context("dependency request scope requires HTTP method and path")?;
        let object = rule
            .as_object_mut()
            .context("dependency request rule requires an object")?;
        object.insert("case".into(), json!({"method":method,"path":path}));
        object
            .entry("source_evidence")
            .or_insert_with(|| json!(options.source_evidence.clone().unwrap_or_default()));
    }
    for rule in &mut options.header_dates {
        if rule.source_evidence.is_empty() {
            rule.source_evidence = options.source_evidence.clone().unwrap_or_default();
        }
    }
    let kind = if options.dynamic_value.is_some() {
        "dynamic_value"
    } else if options.dependency_request.is_some() {
        "dependency_request"
    } else {
        "response_header_date"
    };
    let selection = serde_json::to_string(&(
        options.dynamic_value.as_ref(),
        &options.header_dates,
        &options.dependency_request,
    ))?;
    let record = RewriteRulePlanRecord {
        id: format!(
            "plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                kind,
                &selection,
                &options.evidence_id
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        kind: kind.into(),
        json_pointer: String::new(),
        time: None,
        source_evidence: options.source_evidence,
        source_example: None,
        target_example: None,
        separator: None,
        response_body: None,
        jwt: None,
        evidence_id: options.evidence_id,
        dynamic_value: options.dynamic_value,
        dependency_request: options.dependency_request,
        header_dates: options.header_dates,
    };
    let report = build(target_root, state, &record)?.report().clone();
    state.rule_plan = Some(record.clone());
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id.clone(),
        issue_id: issue.id,
        traffic_e2e_report: serde_json::to_value(report)?,
        next_command: action::rule_apply_command(target_root, &record.id),
    })
}

pub(super) fn build(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteRulePlanRecord,
) -> Result<GeneratedValueRulePlan> {
    let policy_path = target_root.join(".traffic-e2e/verification.yaml");
    let evidence = if state
        .active_issue
        .as_ref()
        .is_some_and(|issue| issue.kind == super::super::model::RewriteIssueKind::Comparison)
    {
        ResponseBodyRuleEvidence::Comparison {
            comparison_report: target_root
                .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
                .join("comparison-recordings")
                .join(
                    state
                        .comparison_run_id
                        .as_ref()
                        .context("header date plan requires a comparison run")?,
                )
                .join("comparison-report.json"),
        }
    } else {
        let evidence = resolve_e2e_response_rule_evidence(
            E2eRunContext {
                target_root: target_root.into(),
                case_source: state
                    .case_source
                    .clone()
                    .context("generated rule requires finalized recordings")?,
                run_key: None,
            },
            state
                .group_id
                .as_deref()
                .context("generated rule requires a prepared group")?,
        )?;
        if let Some(rule) = &record.dependency_request {
            return crate::plan_dependency_request_rule(crate::DependencyRequestRuleFeedback {
                policy_path,
                rule: rule.clone(),
                replay_report: evidence.replay,
            });
        }
        if let Some(rule) = &record.dynamic_value {
            return crate::plan_dynamic_value_rule(DynamicValueRuleFeedback {
                policy_path,
                rule: rule.clone(),
                replay_report: evidence.replay,
            });
        }
        ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report: evidence.assertions,
            aggregate_report: evidence.aggregate,
        }
    };
    crate::plan_response_header_date_rule(ResponseHeaderDateRuleFeedback {
        policy_path,
        api: super::super::api_selector::public_api(&state.api).into(),
        rules: record.header_dates.clone(),
        evidence,
    })
}
