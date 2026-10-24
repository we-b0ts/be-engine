//! Offline payload checks do not prove one accepted case-wide identity graph.
use super::*;

pub(super) fn require_replay(
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) {
    // Protected witnesses include rejected speculative candidates. Combining
    // every locally valid pair would invent accepted edges and can reject a
    // legitimate policy. Keep per-payload validation and require genuine Replay
    // to establish the shared domain, input anchors and successful admission.
    result.stateful_target_obligations.extend(
        policy
            .rules
            .iter()
            .filter(|rule| selected.contains(&rule.rule.id))
            .filter(|rule| {
                rule.rule.contract.values().any(|field| {
                    matches!(
                        field.unconditional(),
                        crate::policy::FieldContract::Identity { .. }
                    )
                })
            })
            .map(|rule| rule.rule.id.clone()),
    );
}
