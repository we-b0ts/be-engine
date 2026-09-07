//! Coordinator plan/apply adapter for global JWT request rules.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

use super::{
    action, evidence, fingerprint,
    model::{RewriteRulePlanRecord, RewriteRuleReport, RewriteState},
};
use crate::e2e_run::jwt_evidence::{self, JwtTimeEvidence};
use crate::request_rules::{
    JwtAlgorithm, JwtRule, JwtTime,
    keys::{self, KeyBinding, SigningKeySource},
    policy,
};

mod discovery;

pub(super) fn evidence_facts(root: &Path, state: &RewriteState) -> Result<Value> {
    let mut result = serde_json::to_value(facts(root, state)?)?;
    result["signing_key_discovery"] = discovery::query(root);
    Ok(result)
}

#[derive(Debug, Clone)]
pub struct JwtRulePlanOptions {
    pub id: String,
    pub header: String,
    pub algorithm: JwtAlgorithm,
    pub signing_key_ref: String,
    pub key_source: Option<SigningKeySource>,
    pub leeway_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtPlanRecord {
    rule: JwtRule,
    binding: KeyBinding,
    policy_revision: String,
    bindings_revision: String,
    evidence_revision: String,
    leeway_seconds: i64,
}

pub(super) fn facts(root: &Path, state: &RewriteState) -> Result<JwtTimeEvidence> {
    let evidence = jwt_evidence::query(
        evidence::e2e_context(root, state)?,
        evidence::group_id(state)?,
    )?;
    ensure!(
        state
            .active_issue
            .as_ref()
            .is_some_and(|i| i.attempt == evidence.attempt),
        "JWT evidence belongs to another attempt"
    );
    Ok(evidence)
}

pub(super) fn plan(
    root: &Path,
    state: &mut RewriteState,
    evidence_id: String,
    source_evidence: Option<String>,
    options: JwtRulePlanOptions,
) -> Result<RewriteRuleReport> {
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
    let facts = facts(root, state)?;
    let (_, config) = crate::e2e_run::resolve_project(root)?;
    let (binding, _) = keys::prepare_binding(root, &options.signing_key_ref, options.key_source)?;
    let spec = JwtPlanRecord {
        rule: JwtRule {
            id: options.id,
            header: options.header,
            scheme: "bearer".into(),
            algorithm: options.algorithm,
            time: JwtTime::PreserveRelative,
            signing_key_ref: options.signing_key_ref,
        },
        binding,
        policy_revision: jwt_evidence::digest(&std::fs::read(&config.replay_policy)?),
        bindings_revision: bindings_revision(root)?,
        evidence_revision: jwt_evidence::digest(&serde_json::to_vec(&facts)?),
        leeway_seconds: options.leeway_seconds,
    };
    let (_, _, traffic_report) = build(root, state, &spec)?;
    let record = RewriteRulePlanRecord {
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

fn bindings_revision(root: &Path) -> Result<String> {
    Ok(jwt_evidence::digest(&serde_json::to_vec(&keys::bindings(
        root,
    )?)?))
}

fn build(
    root: &Path,
    state: &RewriteState,
    spec: &JwtPlanRecord,
) -> Result<(std::path::PathBuf, String, Value)> {
    let (_, config) = crate::e2e_run::resolve_project(root)?;
    let original = std::fs::read_to_string(&config.replay_policy)?;
    ensure!(
        jwt_evidence::digest(original.as_bytes()) == spec.policy_revision,
        "verification policy changed after JWT planning; rerun plan"
    );
    ensure!(
        bindings_revision(root)? == spec.bindings_revision,
        "JWT key bindings changed after planning; rerun plan"
    );
    let key = keys::resolve_source(root, &spec.binding.source)?;
    ensure!(
        keys::revision(&key, &spec.binding.challenge) == spec.binding.revision,
        "JWT signing key changed after planning; rerun plan"
    );
    let facts = facts(root, state)?;
    ensure!(
        jwt_evidence::digest(&serde_json::to_vec(&facts)?) == spec.evidence_revision,
        "JWT attempt evidence changed after planning; rerun plan"
    );
    let case_source = evidence::case_source(root, state)?;
    let selected = facts
        .candidates
        .iter()
        .filter(|c| c.header == spec.rule.header && c.algorithm == spec.rule.algorithm)
        .collect::<Vec<_>>();
    ensure!(
        !selected.is_empty(),
        "no expired JWT evidence matches this rule"
    );
    for case in &selected {
        let path = crate::case_group::resolve_published_case_dir(&case_source, &case.case_id)?
            .join("request.json");
        ensure!(
            jwt_evidence::digest(&std::fs::read(&path)?) == case.request_fingerprint,
            "JWT request evidence changed"
        );
        let request = serde_json::from_slice(&crate::request_headers::load_request_file(&path)?)?;
        jwt_evidence::verify_candidate(case, &request, &key, spec.leeway_seconds)?;
    }
    let coverage = coverage(&case_source, &spec.rule, &key)?;
    let updated = policy::add(&original, &spec.rule)?;
    let rendered = serde_yaml::to_string(&crate::request_rules::RequestRules {
        jwt: vec![spec.rule.clone()],
    })?;
    let report = json!({
        "kind": "jwt", "policy": config.replay_policy, "rule": spec.rule,
        "signing_key_source": spec.binding.source, "signature_verified": true,
        "evidence_cases": selected.len(), "coverage": coverage,
        "changed": original != updated, "applied": false,
        "requires_rerecording": false, "requires_request_execution": true,
        "diff": format!("@@ request_rules @@\n{rendered}"),
        "does_not_prove": ["JWT expiry may coexist with other authentication or target defects; execute the original cases again"]
    });
    Ok((config.replay_policy, updated, report))
}

fn coverage(source: &Path, rule: &JwtRule, key: &[u8]) -> Result<Value> {
    let mut matched = 0;
    let mut invalid = 0;
    let mut apis = std::collections::BTreeSet::new();
    let paths = crate::case_group::published_request_paths(source)?;
    ensure!(
        paths.len() <= 100_000,
        "JWT coverage exceeds supported recording bound"
    );
    for path in paths {
        let request: Value =
            serde_json::from_slice(&crate::request_headers::load_request_file(&path)?)?;
        let Some(raw) = crate::request_rules::jwt::request_token(&request, &rule.header)? else {
            continue;
        };
        let Some(token) = crate::request_rules::jwt::Token::parse(&raw)? else {
            continue;
        };
        if token.algorithm != rule.algorithm {
            continue;
        }
        if !token.verify(key) {
            invalid += 1;
            continue;
        }
        if !token.has_time_claims() {
            continue;
        }
        crate::request_rules::jwt::request_timestamp(&request)?;
        for claim in ["exp", "iat", "nbf"] {
            token.integer_claim(claim)?;
        }
        matched += 1;
        apis.insert(format!(
            "{} {}",
            request["method"].as_str().unwrap_or_default(),
            request["uri"]
                .as_str()
                .unwrap_or_default()
                .split('?')
                .next()
                .unwrap_or_default()
        ));
    }
    Ok(
        json!({ "matching_cases": matched, "distinct_request_paths": apis.len(), "unverified_tokens_preserved": invalid, "scope": "all APIs with the matching header, algorithm and valid signature" }),
    )
}

pub(super) fn apply(
    root: &Path,
    state: &mut RewriteState,
    record: RewriteRulePlanRecord,
) -> Result<RewriteRuleReport> {
    ensure!(
        matches!(
            super::traffic_operation::state(root)?,
            super::traffic_operation::TrafficOperationState::Absent
        ),
        "cannot apply JWT rules during an active traffic operation"
    );
    let spec = record.jwt.as_ref().context("JWT plan payload missing")?;
    let (path, updated, mut report) = build(root, state, spec)?;
    let previous = keys::bindings(root)?;
    let mut bindings = previous.clone();
    bindings.insert(spec.rule.signing_key_ref.clone(), spec.binding.clone());
    keys::write_bindings(root, &bindings)?;
    if let Err(error) = crate::config::edit::write_atomic(&path, updated.as_bytes()) {
        keys::write_bindings(root, &previous)
            .context("JWT policy write failed and binding rollback failed")?;
        return Err(error);
    }
    report["applied"] = json!(true);
    state.rule_plan = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: record.id,
        issue_id: record.issue_id,
        traffic_e2e_report: report,
        next_command: action::next_command_for_api(root, &state.api),
    })
}

pub(super) fn invalidate_global(state: &mut RewriteState) {
    state.target_quality_fingerprint = None;
    super::process_outputs::defer_for_target_change(state, "jwt-request-rules-changed");
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

#[cfg(test)]
mod tests;
