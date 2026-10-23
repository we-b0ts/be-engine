//! Modify acquisition/ownership effects without rebuilding unrelated policies.
use super::*;
use crate::policy::{NativeDomain, PolicyRule, Proof, TrafficPolicy};
mod order;

pub(crate) fn empty_policy() -> Result<String> {
    crate::policy::render_policy(&TrafficPolicy {
        format: crate::policy::POLICY_FORMAT.into(),
        source_revision: None,
        rules: Vec::new(),
    })
}

pub(crate) fn render_updated(
    original: &str,
    proposed: &SourceTrafficPolicyConfig,
    proof: &Proof,
) -> Result<String> {
    let mut document = crate::policy::parse_policy(original)?;
    let compiled = crate::policy::compile_policy(&document)?;
    let before = project_source_policy(&compiled.native)?;
    if before == *proposed {
        return Ok(original.into());
    }
    let mut generated = reverse::rules(proposed, proof)?;
    let mut retained = Vec::new();
    let mut capture_paths = std::collections::BTreeSet::new();
    for entry in document.rules {
        let Some(old) = entry.as_native() else {
            retained.push(entry);
            continue;
        };
        if !matches!(
            old.effect.domain(),
            NativeDomain::Capture | NativeDomain::Classification
        ) {
            retained.push(entry);
            continue;
        }
        if let n::NativeEffect::CaptureHttp(capture) = &old.effect {
            let paths = capture
                .case_paths
                .iter()
                .filter(|path| proposed.http.case_path_patterns.contains(path))
                .cloned()
                .collect::<Vec<_>>();
            capture_paths.extend(paths.iter().cloned());
            if paths.is_empty() {
                continue;
            }
            if paths == capture.case_paths
                && proposed.http.source_revision == capture.source_revision
            {
                retained.push(entry);
            } else {
                let mut replacement = old.clone();
                replacement.proof = proof.clone();
                replacement.proof.source.clear();
                replacement.effect = n::NativeEffect::CaptureHttp(n::CaptureHttpEffect {
                    source_revision: proposed.http.source_revision.clone(),
                    case_paths: paths,
                });
                retained.push(replacement.into());
            }
            continue;
        }
        if unchanged(old, proposed)? {
            generated.retain(|next| !same_key(old, next));
            retained.push(entry);
        } else if let Some(next) = generated.iter_mut().find(|next| same_key(old, next)) {
            next.id = old.id.clone();
            reverse::preserve_nested(old, next)?;
        }
    }
    for mut next in generated {
        if let n::NativeEffect::CaptureHttp(effect) = &mut next.effect {
            effect
                .case_paths
                .retain(|path| !capture_paths.contains(path));
            if effect.case_paths.is_empty() {
                continue;
            }
            if retained.iter().any(|rule| rule.id() == next.id) {
                let suffix = crate::verification_progress::fingerprint(&serde_json::to_vec(
                    &effect.case_paths,
                )?);
                next.id = format!(
                    "source-capture-http-{}",
                    suffix.rsplit(':').next().unwrap_or(&suffix)
                );
            }
        }
        retained.push(PolicyRule::from(next));
    }
    order::capture_responses(&mut retained, proposed)?;
    document.rules = retained;
    crate::policy::compile_policy(&document)
        .context("updated Source effects violate unified policy capabilities or ownership")?;
    crate::policy::render_policy(&document)
}

fn unchanged(rule: &n::NativeRule, proposed: &SourceTrafficPolicyConfig) -> Result<bool> {
    let compiled = crate::policy::compile_native(rule)?;
    let previous = project_source_policy(&[compiled])?;
    Ok(match &rule.effect {
        n::NativeEffect::CaptureBreeze(_) => previous
            .breeze_capture
            .iter()
            .all(|capture| proposed.breeze_capture.contains(capture)),
        n::NativeEffect::CaptureHttpResponse(_) => previous
            .http_response_rewrite
            .iter()
            .all(|capture| proposed.http_response_rewrite.contains(capture)),
        n::NativeEffect::ProcessOwned(_) => previous
            .process_owned_dependencies
            .iter()
            .all(|owned| proposed.process_owned_dependencies.contains(owned)),
        _ => false,
    })
}
fn same_key(left: &n::NativeRule, right: &n::NativeRule) -> bool {
    match (&left.effect, &right.effect) {
        (n::NativeEffect::CaptureBreeze(left), n::NativeEffect::CaptureBreeze(right)) => {
            left.snapshot_dir == right.snapshot_dir
        }
        (n::NativeEffect::CaptureHttpResponse(_), n::NativeEffect::CaptureHttpResponse(_))
        | (n::NativeEffect::ProcessOwned(_), n::NativeEffect::ProcessOwned(_)) => {
            left.id == right.id
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
