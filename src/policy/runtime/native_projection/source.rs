//! Finite sharing proof remains owned by the existing protocol correlation owner.
use super::*;
use anyhow::{Context, Result, ensure};
use std::path::Path;

pub(crate) fn validate_finite_sharing(
    case_source: &Path,
    replay_report: &Path,
    compiled: &CompiledNativeRule,
) -> Result<usize> {
    ensure!(
        matches!(compiled.rule.effect, n::NativeEffect::FiniteSharing(_)),
        "finite-sharing proof received another effect"
    );
    let projected = dependency::project(&compiled.rule)?;
    let resource = compiled.rule.selector.resource.as_ref();
    let evidence = match &compiled.rule.effect {
        n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Http) => {
            let selected = projected
                .http
                .context("HTTP sharing projection is missing")?;
            crate::protocols::replay::http::cross_case::verify_candidate(
                case_source,
                replay_report,
                &crate::HttpCrossCaseSelector {
                    host: resource
                        .map(|resource| resource.endpoint.host.clone())
                        .or_else(|| compiled.rule.selector.http_host.clone()),
                    port: resource.map(|resource| resource.endpoint.port),
                    method: selected.method,
                    path: selected.path,
                },
            )?
        }
        n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Redis { .. }) => {
            anyhow::bail!("finite Redis sharing requires an installed native sharing capability")
        }
        _ => unreachable!("validated finite-sharing effect"),
    };
    Ok(evidence["matching_exchanges"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or_else(|| {
            evidence["candidates"]
                .as_array()
                .map_or(1, |items| items.len().max(1))
        }))
}
