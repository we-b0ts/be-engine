//! Global header values join the same staged identity graph as request bodies.
use super::*;
use crate::replay::policy::request_contract::{Decision, RequestContracts};

pub(in crate::replay::http) fn preview(
    owner: &RequestContracts,
    case: Option<&str>,
    source: &HeaderSnapshot,
    target: &HeaderSnapshot,
    source_started: Option<chrono::DateTime<Utc>>,
    target_started: chrono::DateTime<Utc>,
) -> Option<Result<(Decision, HeaderSnapshot)>> {
    let plan = owner.compiled_rules()?.http.as_ref()?;
    Some((|| {
        let source_normalized = normalized(source);
        let target_normalized = normalized(target);
        for name in plan.headers.keys() {
            if source_normalized
                .get(name)
                .is_some_and(|values| values.iter().any(|value| value == "<redacted>"))
            {
                anyhow::ensure!(
                    source_normalized.get(name) == target_normalized.get(name),
                    "global HTTP header Source value is unavailable"
                );
            }
        }
        let clocks = owner.contract_clocks(case, source_started, Some(target_started), None, None);
        let comparison =
            crate::value_contract::http_headers::compare(source, target, plan, clocks)?;
        anyhow::ensure!(
            comparison.passed(),
            "global HTTP header format failed: {:?}",
            comparison.differences
        );
        let identity = if let Some(case) = case {
            Some(owner.identity_decision(case, &comparison)?)
        } else {
            anyhow::ensure!(
                comparison.identity_pairs().is_empty(),
                "HTTP header identity requires an active case"
            );
            None
        };
        let masked = crate::value_contract::http_headers::mask(source, target, plan)?;
        let mut decision = Decision::from_value_comparison(comparison);
        decision.identity = identity;
        Ok((decision, masked))
    })())
}

/// Matching already authenticated the original pair. Audit only the unowned
/// remainder; declared values are accounted by the atomic request decision.
pub(super) fn audit_projection(
    state: &ReplayState,
    exchange: &ReplayHttpExchange,
    actual: &HeaderSnapshot,
    started: chrono::DateTime<Utc>,
) -> Option<HeaderSnapshot> {
    let owner = &state.replay_policy.as_ref()?.request_contracts;
    let plan = owner.compiled_rules()?.http.as_ref()?;
    let clocks = owner.contract_clocks(
        state.active_case_id.as_deref(),
        time_reference::source(&exchange.record),
        Some(started),
        None,
        None,
    );
    let checked = crate::value_contract::http_headers::compare(
        &exchange.record.native.request_headers,
        actual,
        plan,
        clocks,
    )
    .ok()?;
    if !checked.passed() {
        return None;
    }
    crate::value_contract::http_headers::mask(&exchange.record.native.request_headers, actual, plan)
        .ok()
}
