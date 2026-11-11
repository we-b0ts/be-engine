//! Typed acquisition/ownership effects for internal Source-owner updates.
//! This is not a parser or compatibility format: its input is an owner DTO.
mod origin;
mod process;
use super::*;
use crate::policy::Proof;
use crate::policy::native::Proven;

pub(super) fn rules(
    config: &SourceTrafficPolicyConfig,
    proof: &Proof,
) -> Result<Vec<n::NativeRule>> {
    config.validate()?;
    ensure!(
        config.http.allowed_unused_http_hosts.is_empty(),
        "unbounded unused HTTP hosts have no unified rule effect; use a Source-proven process-owned HTTP selector or narrow capture scope; sharing does not authorize unused work"
    );
    let mut rules = Vec::new();
    if !config.http.case_path_patterns.is_empty() {
        rules.push(rule(
            "source-capture-http".into(),
            n::NativeEffect::CaptureHttp(n::CaptureHttpEffect {
                source_revision: config.http.source_revision.clone(),
                case_paths: config.http.case_path_patterns.clone(),
            }),
            proof,
        ));
    }
    for capture in &config.breeze_capture {
        if capture.capture_resources.is_empty() {
            continue;
        }
        let hash = crate::verification_progress::fingerprint(
            capture.snapshot_dir.to_string_lossy().as_bytes(),
        );
        let id = format!("source-breeze-{}", hash.rsplit(':').next().unwrap_or(&hash));
        rules.push(rule(
            id,
            n::NativeEffect::CaptureBreeze(n::CaptureBreezeEffect {
                snapshot_dir: capture.snapshot_dir.clone(),
                resources: capture.capture_resources.clone(),
            }),
            proof,
        ));
    }
    for capture in &config.http_response_rewrite {
        let contract = match &capture.plugin {
            None => n::CaptureResponseContract::Urls {
                pointers: capture
                    .pointers
                    .iter()
                    .map(|pointer| Proven {
                        contract: pointer.clone(),
                        proof: Some(proof.clone()),
                    })
                    .collect(),
            },
            Some(super::super::HttpResponseRewritePluginConfig::PlutoEciKubeconfig {
                kubectl_binary,
                proxy_listen,
            }) => n::CaptureResponseContract::Kubeconfig {
                kubectl_binary: kubectl_binary.clone(),
                proxy_listen: *proxy_listen,
            },
            Some(super::super::HttpResponseRewritePluginConfig::Documents { rules }) => {
                n::CaptureResponseContract::Documents {
                    rules: rules.clone(),
                }
            }
        };
        rules.push(rule(
            capture.name.clone(),
            n::NativeEffect::CaptureHttpResponse(n::CaptureResponseEffect {
                authorities: capture.authorities.clone(),
                methods: capture.methods.clone(),
                path: match &capture.path_pattern {
                    Some(value) => n::CapturePath::Pattern {
                        value: value.clone(),
                    },
                    None => n::CapturePath::Exact {
                        value: capture.path.clone(),
                    },
                },
                status_codes: capture.status_codes.clone(),
                content_types: capture.content_types.clone(),
                contract,
            }),
            proof,
        ));
    }
    // Owner DTOs may describe several paths under the same authority. Preserve
    // explicit ids where unique, and give additional selectors a stable bounded
    // id instead of collapsing their independently proven scopes.
    let mut seen = std::collections::BTreeSet::new();
    for entry in &mut rules {
        if entry.id.len() > 96 || !seen.insert(entry.id.clone()) {
            let suffix =
                crate::verification_progress::fingerprint(&serde_json::to_vec(&entry.effect)?);
            let suffix = suffix.rsplit(':').next().unwrap_or(&suffix);
            let base = entry.id.chars().take(64).collect::<String>();
            entry.id = format!("{base}-{suffix}");
            ensure!(
                seen.insert(entry.id.clone()),
                "duplicate Source effect selector"
            );
        }
    }
    for owned in &config.process_owned_dependencies {
        rules.push(process::rule(owned, proof)?);
    }
    for rule in &rules {
        crate::policy::compile_native(rule)?;
    }
    Ok(rules)
}

fn rule(id: String, effect: n::NativeEffect, proof: &Proof) -> n::NativeRule {
    let mut proof = proof.clone();
    if matches!(effect, n::NativeEffect::CaptureHttp(_)) {
        proof.source.clear();
    }
    n::NativeRule {
        id,
        selector: Default::default(),
        effect,
        proof: Some(proof),
        when: None,
    }
}

/// Unchanged nested selectors retain their complete original facts. A newly
/// introduced selector must carry the current update's explicit proof.
pub(super) fn preserve_nested(old: &n::NativeRule, next: &mut n::NativeRule) -> Result<()> {
    if let (Some(old), Some(next_proof)) = (&old.proof, &next.proof)
        && old != next_proof
    {
        next.proof = Some(Proof {
            source: old.merged_source(next_proof)?,
            fact: if old.fact == next_proof.fact {
                old.fact.clone()
            } else {
                format!("{}; {}", old.fact, next_proof.fact)
            },
        });
    }
    match (&old.effect, &mut next.effect) {
        (n::NativeEffect::CaptureHttpResponse(old), n::NativeEffect::CaptureHttpResponse(next)) => {
            if let (
                n::CaptureResponseContract::Urls { pointers: old },
                n::CaptureResponseContract::Urls { pointers: next },
            ) = (&old.contract, &mut next.contract)
            {
                for item in next {
                    if let Some(previous) = old
                        .iter()
                        .find(|previous| previous.contract == item.contract)
                    {
                        item.proof = previous.proof.clone();
                    }
                }
            }
        }
        (n::NativeEffect::ProcessOwned(old), n::NativeEffect::ProcessOwned(next)) => {
            if let (Some(old), Some(next)) = (&old.origin, &mut next.origin) {
                for (key, capture) in &mut next.contract.capture {
                    if let Some(previous) = old
                        .contract
                        .capture
                        .get(key)
                        .filter(|previous| previous.contract == capture.contract)
                    {
                        capture.proof = previous.proof.clone();
                    }
                }
                if old.contract == next.contract {
                    next.proof = old.proof.clone();
                }
            }
            match (&old.selector, &mut next.selector) {
                (
                    n::ProcessSelector::Mysql {
                        transaction_members: old,
                        ..
                    },
                    n::ProcessSelector::Mysql {
                        transaction_members: next,
                        ..
                    },
                ) => {
                    for member in next {
                        if let Some(previous) = old
                            .iter()
                            .find(|previous| previous.contract == member.contract)
                        {
                            member.proof = previous.proof.clone();
                        }
                    }
                }
                (
                    n::ProcessSelector::Redis {
                        script: Some(old), ..
                    },
                    n::ProcessSelector::Redis {
                        script: Some(next), ..
                    },
                ) if old.contract == next.contract => next.proof = old.proof.clone(),
                _ => (),
            }
        }
        _ => (),
    }
    Ok(())
}
