//! Evidence-backed policy edits for captured identities and response header dates.
mod dependency_request;
mod evidence;
mod header_evidence;
mod request_evidence;
mod response_evidence;
mod response_jwt;
use super::super::{
    config::{fingerprint, load_replay_policy},
    dynamic_values::DynamicValueRule,
    response_headers::ResponseHeaderDateRule,
};
use super::{
    document::{render_dependency_rules, replace_dependency_rules, replace_response_rules},
    response_body::ResponseBodyRuleEvidence,
};
use anyhow::{Context, Result, ensure};
pub use dependency_request::{DependencyRequestRuleFeedback, plan_dependency_request_rule};
pub use response_jwt::{ResponseJwtRuleFeedback, plan_response_jwt_rule};
use serde::Serialize;
use std::{fs, path::PathBuf};

#[cfg(test)]
mod tests;

pub struct DynamicValueRuleFeedback {
    pub policy_path: PathBuf,
    pub rule: DynamicValueRule,
    pub replay_report: PathBuf,
}

pub struct ResponseHeaderDateRuleFeedback {
    pub policy_path: PathBuf,
    pub api: String,
    pub rules: Vec<ResponseHeaderDateRule>,
    pub evidence: ResponseBodyRuleEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedValueRuleReport {
    pub kind: String,
    pub api: String,
    pub policy_fingerprint: String,
    pub matching_cases: usize,
    pub selected_difference_cases: usize,
    pub added_rule_ids: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub requires_fresh_replay: bool,
    pub diff: String,
}

pub struct GeneratedValueRulePlan {
    policy_path: PathBuf,
    original: String,
    updated: String,
    witnesses: Vec<(PathBuf, String)>,
    key_witnesses: Vec<crate::request_rules::keys::ResolvedSigningKey>,
    report: GeneratedValueRuleReport,
}

impl GeneratedValueRulePlan {
    pub fn report(&self) -> &GeneratedValueRuleReport {
        &self.report
    }
    pub fn apply(self) -> Result<GeneratedValueRuleReport> {
        ensure!(
            fs::read_to_string(&self.policy_path)? == self.original,
            "verification policy changed after planning; the pending plan is stale. Run fresh Replay using the existing recordings and current verification.yaml, query new evidence, and plan again before applying"
        );
        for (path, identity) in &self.witnesses {
            ensure!(
                fingerprint(&super::read_published_report(
                    path,
                    "generated value witness"
                )?) == *identity,
                "generated value evidence changed after planning"
            );
        }
        for key in &self.key_witnesses {
            key.ensure_current()?;
        }
        if self.original != self.updated {
            crate::config::edit::write_atomic(&self.policy_path, self.updated.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_dynamic_value_rule(
    feedback: DynamicValueRuleFeedback,
) -> Result<GeneratedValueRulePlan> {
    feedback.rule.validate()?;
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let witnesses =
        evidence::dynamic(&feedback.rule, &feedback.replay_report, &loaded.fingerprint)?;
    if let Some(existing) = loaded
        .document
        .dynamic_values
        .iter()
        .find(|rule| rule.id == feedback.rule.id)
    {
        ensure!(
            existing == &feedback.rule,
            "dynamic value rule id already has a different definition"
        );
    } else {
        loaded.document.dynamic_values.push(feedback.rule.clone());
    }
    let rendered = render_dependency_rules(&loaded.document)?;
    let updated = replace_dependency_rules(&original, &loaded.document)?;
    Ok(GeneratedValueRulePlan {
        policy_path: feedback.policy_path,
        report: GeneratedValueRuleReport {
            kind: "dynamic_value".into(),
            api: feedback.rule.api,
            policy_fingerprint: loaded.fingerprint,
            matching_cases: 1,
            selected_difference_cases: 1,
            added_rule_ids: vec![feedback.rule.id],
            changed: original != updated,
            applied: false,
            requires_fresh_replay: true,
            diff: rendered,
        },
        original,
        updated,
        witnesses,
        key_witnesses: vec![],
    })
}

pub fn plan_response_header_date_rule(
    feedback: ResponseHeaderDateRuleFeedback,
) -> Result<GeneratedValueRulePlan> {
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let rules = std::collections::BTreeMap::from([(feedback.api.clone(), feedback.rules.clone())]);
    super::super::response_headers::validate(&rules)?;
    let (matching_cases, selected_difference_cases, witnesses) =
        header_evidence::validate(&feedback, &loaded.fingerprint)?;
    let entries = loaded
        .document
        .response_rules
        .headers
        .entry(feedback.api.clone())
        .or_default();
    for rule in &feedback.rules {
        if let Some(existing) = entries
            .iter()
            .find(|existing| existing.id(&feedback.api) == rule.id(&feedback.api))
        {
            ensure!(
                existing == rule,
                "response header date selector already has another definition"
            );
        } else {
            entries.push(rule.clone());
        }
    }
    let updated = replace_response_rules(&original, &loaded.document.response_rules)?;
    Ok(GeneratedValueRulePlan {
        policy_path: feedback.policy_path,
        report: GeneratedValueRuleReport {
            kind: "response_header_date".into(),
            api: feedback.api.clone(),
            policy_fingerprint: loaded.fingerprint,
            matching_cases,
            selected_difference_cases,
            added_rule_ids: feedback
                .rules
                .iter()
                .map(|rule| rule.id(&feedback.api))
                .collect(),
            changed: original != updated,
            applied: false,
            requires_fresh_replay: true,
            diff: super::document::render_response_rules(&loaded.document.response_rules)?,
        },
        original,
        updated,
        witnesses,
        key_witnesses: vec![],
    })
}
