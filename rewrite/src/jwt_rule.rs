//! Coordinator plan/apply adapter for global JWT request rules.
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::path::Path;

use super::{
    action, evidence, fingerprint,
    model::{RewriteRulePlanRecord, RewriteRuleReport, RewriteState},
};
#[cfg(test)]
use crate::request_rules::{
    JwtAlgorithm, JwtTokenLocation,
    keys::{self, SigningKeySource},
};
#[cfg(test)]
use serde_json::Value;
pub use traffic_rewrite_rules::rewrite::jwt_plan::JwtRulePlanOptions;
use traffic_rewrite_rules::rewrite::jwt_plan::{build, build_spec};

#[cfg(test)]
use traffic_rewrite_evidence::jwt_evidence::{evidence_facts, facts, signing_key_discovery};

pub(super) fn plan(
    root: &Path,
    state: &mut RewriteState,
    evidence_id: String,
    source_evidence: Option<String>,
    options: JwtRulePlanOptions,
) -> Result<RewriteRuleReport> {
    crate::policy::retired_authoring()?;
    let source_evidence = source_evidence.filter(|s| !s.trim().is_empty()).context("JWT rule requires --source-evidence confirming the source and target authentication path, key source, and expiration leeway")?;
    super::validate_single_line("JWT source evidence", &source_evidence)?;
    let issue = state
        .active_issue
        .as_ref()
        .context("JWT rule requires an active issue")?;
    let command = evidence::commands(root, state)
        .into_iter()
        .find(|c| c.query_id.ends_with("jwt-time-validity"))
        .context("JWT evidence query is unavailable for this issue")?;
    let report = evidence::query(root, state, &command.query_id)?;
    ensure!(
        report.evidence_id == evidence_id,
        "JWT evidence is stale or belongs to another issue"
    );
    let spec = build_spec(root, state, options)?;
    let (_, _, traffic_report) = build(root, state, &spec)?;
    let record = RewriteRulePlanRecord {
        unified: None,
        generated_witnesses: Vec::new(),
        response_jwts: Vec::new(),
        header_dates: Vec::new(),
        dynamic_value: None,
        mysql_time: None,
        redis_time: None,
        dependency_request: None,
        time: None,
        id: format!(
            "plan-{}",
            fingerprint::id(&[&issue.id, &evidence_id, &serde_json::to_string(&spec)?])
                .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        kind: "jwt".into(),
        json_pointer: String::new(),
        source_evidence: Some(source_evidence),
        source_example: None,
        target_example: None,
        separator: None,
        response_body: None,
        jwt: Some(spec),
        evidence_id,
    };
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.rule_plan = Some(record.clone());
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id.clone(),
        issue_id: record.issue_id,
        traffic_e2e_report: traffic_report,
        next_command: action::rule_apply_command(root, &record.id),
    })
}

pub(super) fn apply(
    root: &Path,
    state: &mut RewriteState,
    record: RewriteRulePlanRecord,
) -> Result<RewriteRuleReport> {
    crate::policy::retired_authoring()?;
    ensure!(
        matches!(
            super::traffic_operation::state(root)?,
            super::traffic_operation::TrafficOperationState::Absent
        ),
        "cannot apply JWT rules during an active traffic operation"
    );
    let spec = record.jwt.as_ref().context("JWT plan payload missing")?;
    let (path, updated, mut report) = build(root, state, spec)?;
    crate::config::edit::write_atomic(&path, updated.as_bytes())?;
    report["applied"] = json!(true);
    state.rule_plan = None;
    super::rule_replay::request(state);
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id,
        issue_id: record.issue_id,
        traffic_e2e_report: report,
        next_command: action::next_command(root),
    })
}

pub(super) fn invalidate_global(state: &mut RewriteState) {
    state.target_quality_fingerprint = None;
    for item in &mut state.api_inventory {
        item.e2e_current = false;
        item.verified_target_fingerprint = None;
        if item.status == super::model::RewriteApiStatus::Complete {
            item.status = super::model::RewriteApiStatus::RevalidationPending;
        }
    }
    for slice in state.parked_slices.values_mut() {
        slice.e2e_current = false;
        slice.target_fingerprint = None;
    }
}

#[cfg(test)]
mod tests;
