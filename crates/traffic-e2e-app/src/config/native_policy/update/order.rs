//! The acquisition owner retains precedence while typed proofs remain untouched.
use super::*;

pub(super) fn capture_responses(
    rules: &mut [PolicyRule],
    proposed: &SourceTrafficPolicyConfig,
) -> Result<()> {
    let mut positions = Vec::new();
    let mut ordered = Vec::new();
    for (index, entry) in rules.iter().enumerate() {
        let Some(rule) = entry.as_native() else {
            continue;
        };
        let n::NativeEffect::CaptureHttpResponse(effect) = &rule.effect else {
            continue;
        };
        let actual = semantic(super::super::capture_response(rule, effect));
        let rank = proposed
            .http_response_rewrite
            .iter()
            .position(|candidate| semantic(candidate.clone()) == actual)
            .context("updated capture response is absent from the proposed Source selectors")?;
        positions.push(index);
        ordered.push((rank, entry.clone()));
    }
    ordered.sort_by_key(|(rank, _)| *rank);
    for (index, (_, entry)) in positions.into_iter().zip(ordered) {
        rules[index] = entry;
    }
    Ok(())
}

fn semantic(
    mut rule: crate::config::HttpResponseRewriteRuleConfig,
) -> crate::config::HttpResponseRewriteRuleConfig {
    // Rule ids and the DTO's rendered proof are presentation. The typed rule
    // itself, including every original nested proof, is cloned without changes.
    rule.name.clear();
    rule.source_evidence.clear();
    rule
}
