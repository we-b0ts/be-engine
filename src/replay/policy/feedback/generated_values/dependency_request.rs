//! Planning for bounded dependency request contracts with protected witnesses.
use super::*;
use crate::replay::policy::{config::ReplayDependencyRule, request_contract};
use serde_json::Value;

pub struct DependencyRequestRuleFeedback {
    pub policy_path: PathBuf,
    pub rule: Value,
    pub replay_report: PathBuf,
}

pub fn plan_dependency_request_rule(
    feedback: DependencyRequestRuleFeedback,
) -> Result<GeneratedValueRulePlan> {
    let rule: ReplayDependencyRule = serde_json::from_value(feedback.rule)?;
    if super::mysql_response::is_rule(&rule) {
        return super::mysql_response::plan(
            DependencyRequestRuleFeedback {
                rule: serde_json::to_value(&rule)?,
                ..feedback
            },
            rule,
        );
    }
    ensure!(
        request_contract::is_request_rule(&rule),
        "dependency request planning requires a Redis argument or HTTP multipart contract"
    );
    request_contract::validate(&rule)?;
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let mut witnesses = Vec::new();
    let report: Value =
        serde_json::from_slice(&evidence::read(feedback.replay_report, &mut witnesses)?)?;
    ensure!(
        report["finalized"] == true,
        "dependency request planning requires finalized Replay"
    );
    crate::replay::ReplayEvidencePolicyFreshness::new(
        report["replay_policy"]["fingerprint"].as_str(),
        &loaded.fingerprint,
    )
    .ensure_current("dependency request evidence")?;
    let runtime = request_contract::RequestContracts::load(
        std::slice::from_ref(&rule),
        &feedback.policy_path,
        &Default::default(),
    )?;
    let matching_cases = request_contract::evidence::verify(
        &runtime,
        &rule,
        &report,
        &loaded.document.dynamic_values,
        &mut witnesses,
    )?;
    if let Some(existing) = loaded
        .document
        .dependency_rules
        .iter()
        .find(|r| r.id == rule.id)
    {
        ensure!(
            serde_json::to_value(existing)? == serde_json::to_value(&rule)?,
            "dependency rule id already has a different definition"
        );
    } else {
        loaded.document.dependency_rules.push(rule.clone());
    }
    let updated = replace_dependency_rules(&original, &loaded.document)?;
    Ok(GeneratedValueRulePlan {
        policy_path: feedback.policy_path,
        report: GeneratedValueRuleReport {
            kind: "dependency_request".into(),
            api: rule
                .case_selector
                .as_ref()
                .map(|c| format!("{} {}", c.method, c.path))
                .unwrap_or_default(),
            policy_fingerprint: loaded.fingerprint,
            matching_cases,
            selected_difference_cases: matching_cases,
            added_rule_ids: vec![rule.id],
            changed: original != updated,
            applied: false,
            requires_fresh_replay: true,
            diff: render_dependency_rules(&loaded.document)?,
        },
        original,
        updated,
        witnesses,
        key_witnesses: runtime.signing_keys(),
    })
}
