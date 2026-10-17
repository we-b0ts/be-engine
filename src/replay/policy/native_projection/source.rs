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
    let resource = compiled
        .rule
        .selector
        .resource
        .as_ref()
        .context("sharing resource is missing")?;
    let evidence = match &compiled.rule.effect {
        n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Http) => {
            let selected = projected
                .http
                .context("HTTP sharing projection is missing")?;
            crate::replay::http::cross_case::verify_candidate(
                case_source,
                replay_report,
                &crate::replay::HttpCrossCaseSelector {
                    host: resource.endpoint.host.clone(),
                    port: resource.endpoint.port,
                    method: selected.method,
                    path: selected.path,
                },
            )?
        }
        n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Redis { .. }) => {
            let super::super::redis_value::RedisSelector::TimeShift(read) = projected
                .redis
                .context("Redis sharing projection is missing")?
            else {
                anyhow::bail!("Redis sharing owner is not a time-shift read");
            };
            crate::replay::redis::cross_case::verify_candidate(
                case_source,
                replay_report,
                &crate::replay::RedisTimeShiftSelector {
                    host: resource.endpoint.host.clone(),
                    port: resource.endpoint.port,
                    read,
                },
            )?
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
