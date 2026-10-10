//! Evidence-backed signed JWT response contracts and private key freshness.
use super::*;
use crate::replay::{
    assertion::{jwt::JwtComparison, read_replay_request_times},
    policy::response::{ResponseJwtRule, validate_response_rules},
    read_actual_response_body, read_expected_response_body,
};
use crate::request_rules::keys::ResolvedSigningKey;

pub struct ResponseJwtRuleFeedback {
    pub policy_path: PathBuf,
    pub api: String,
    pub rules: Vec<ResponseJwtRule>,
    pub evidence: ResponseBodyRuleEvidence,
}

pub fn plan_response_jwt_rule(feedback: ResponseJwtRuleFeedback) -> Result<GeneratedValueRulePlan> {
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    ensure!(
        !feedback.rules.is_empty(),
        "JWT response planning requires at least one rule"
    );
    let (method, path) = super::super::super::response::parse_api(&feedback.api)?;
    let mut witnesses = Vec::new();
    let observations = super::response_evidence::collect(
        &feedback.evidence,
        &feedback.api,
        &loaded.fingerprint,
        &mut witnesses,
    )?;
    let root = feedback
        .policy_path
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap_or(std::path::Path::new("."));
    let mut keys = Vec::new();
    let entries = &mut loaded
        .document
        .response_rules
        .json
        .entry(feedback.api.clone())
        .or_default()
        .jwt;
    for rule in &feedback.rules {
        rule.validate()?;
        keys.push(ResolvedSigningKey::resolve(root, &rule.signing_key_source)?);
        if let Some(existing) = entries.iter().find(|old| old.pointer == rule.pointer) {
            ensure!(
                existing == rule,
                "JWT response selector already has another definition"
            );
        } else {
            entries.push(rule.clone());
        }
    }
    validate_response_rules(&loaded.document.response_rules)?;
    let fields = loaded
        .document
        .response_rules
        .matching_replay_fields(method, path)
        .into_iter()
        .filter(|field| {
            field
                .jwt
                .as_ref()
                .is_some_and(|rule| feedback.rules.contains(rule))
        })
        .collect::<Vec<_>>();
    let mut matching_cases = 0;
    let mut selected_difference_cases = 0;
    let mut selected_rules = std::collections::BTreeSet::new();
    for observation in observations {
        let request = PathBuf::from(&observation.request_path);
        let expected = PathBuf::from(&observation.expected_response_path);
        let actual = PathBuf::from(&observation.actual_response_path);
        let request_bytes = super::evidence::read(request.clone(), &mut witnesses)?;
        let request_document: serde_json::Value = serde_json::from_slice(&request_bytes)?;
        ensure!(
            request_document["method"] == observation.method
                && super::super::super::pattern::uri_path(
                    request_document["uri"].as_str().unwrap_or_default()
                ) == observation.path,
            "JWT request identity differs from assertion evidence"
        );
        let source_bytes = super::evidence::read(expected.clone(), &mut witnesses)?;
        let target_bytes = super::evidence::read(actual.clone(), &mut witnesses)?;
        ensure!(
            fingerprint(&source_bytes) == observation.expected_response_fingerprint
                && fingerprint(&target_bytes) == observation.actual_response_fingerprint,
            "JWT response evidence changed since assertion"
        );
        ensure!(
            observation.gateway_protocol == crate::replay::ResponseGatewayProtocol::Http,
            "JWT response rules require HTTP JSON evidence"
        );
        let (source_body, target_body, times) = match feedback.evidence {
            ResponseBodyRuleEvidence::FocusedE2e { .. } => (
                read_expected_response_body(&expected, observation.gateway_protocol)?,
                read_actual_response_body(&actual, observation.gateway_protocol)?,
                read_replay_request_times(&request, &actual)?,
            ),
        };
        let source = crate::json_value::parse(&source_body)
            .context("source JWT response requires complete unique-member JSON")?;
        let target = crate::json_value::parse(&target_body)
            .context("target JWT response requires complete unique-member JSON")?;
        let mut comparison = JwtComparison::load(&fields, &feedback.policy_path, &source, &target);
        let mut changed = false;
        let mut selected = false;
        for field in &fields {
            for pointer in super::super::super::response::select_json_pointers(
                &field.pointer,
                &source,
                &target,
            ) {
                let left = source
                    .pointer(&pointer)
                    .context("source JWT field is absent")?;
                let right = target
                    .pointer(&pointer)
                    .context("target JWT field is absent")?;
                comparison.compare(field, &pointer, times).map_err(|kind| {
                    anyhow::anyhow!("JWT response contract failed at {pointer}: {kind:?}")
                })?;
                selected = true;
                changed |= left != right;
                if left != right {
                    selected_rules.insert(field.id.clone());
                }
            }
        }
        matching_cases += usize::from(selected);
        selected_difference_cases += usize::from(changed);
    }
    ensure!(
        matching_cases > 0
            && selected_difference_cases > 0
            && feedback
                .rules
                .iter()
                .all(|rule| selected_rules.contains(&rule.id(&feedback.api))),
        "JWT response planning requires a verified dynamic difference for every selected rule"
    );
    for key in &keys {
        key.ensure_current()?;
    }
    let updated = replace_response_rules(&original, &loaded.document.response_rules)?;
    Ok(GeneratedValueRulePlan {
        policy_path: feedback.policy_path,
        report: GeneratedValueRuleReport {
            kind: "response_jwt".into(),
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
            diff: super::super::document::render_response_rules(&loaded.document.response_rules)?,
        },
        original,
        updated,
        witnesses,
        key_witnesses: keys,
    })
}

#[cfg(test)]
mod tests;
