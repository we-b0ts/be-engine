//! Ownership questions select analyst work; already owned failures do not.
use super::model::ClaimStatus;
use crate::model::{RewriteAction, RewriteInputRequiredReason, RewriteState};
use std::{collections::BTreeMap, path::Path};

pub(super) use traffic_rewrite_attribution::admission::{refresh_inventory, review_inventory};

pub(crate) fn required_action(root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    // A batch switch can retain claims for the selected recording before its
    // Source is adopted. Context and apply need that Source to resolve them.
    state.case_source.as_ref()?;
    let unowned = match review_inventory(root, state) {
        Ok((_, occurrences)) => occurrences.len(),
        Err(error) => {
            return Some(RewriteAction::InputRequired {
                reason: RewriteInputRequiredReason::RecordingEvidenceRequired,
                summary: format!("cannot establish Source dependency ownership: {error:#}"),
                required: vec!["provide the current sealed dependency inventory".into()],
                recording_input_diagnosis: None,
            });
        }
    };
    let disputed = state
        .dependency_review
        .claims
        .values()
        .filter(|claim| {
            claim.recording_run_id == state.recording_run_id
                && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
        })
        .count();
    (unowned > 0 || disputed > 0).then(|| RewriteAction::DependencyAttributionRequired {
        summary: format!(
            "resolve {unowned} ownerless Source dependencies and {disputed} ownership returns through the repository analyst before formal Replay; apply supported owner rules or reject mistaken returns"
        ),
        assignment_id: super::assignment_id(state).expect("serializable attribution assignment"),
        dispatch_generation: state.dependency_review.revision,
        claim_kinds: BTreeMap::from([
            ("unattributed_source".into(), unowned),
            ("foreign_unused".into(), disputed),
        ]),
        context: crate::action::command(root, vec!["dependency-attribution".into(), "context".into()], vec![]),
        apply: crate::action::command(root, vec!["dependency-attribution".into(), "apply".into(), "--file".into(), "<attribution.json>".into()], vec![]),
    })
}

#[cfg(test)]
mod tests {
    use super::super::model::ForeignUnusedClaim;
    use super::*;
    use std::collections::BTreeSet;
    use uuid::Uuid;

    #[test]
    fn retained_claim_waits_for_the_selected_recording_to_be_adopted() {
        let mut state = crate::test_state();
        state.phase = crate::model::RewritePhase::RecordingRequired;
        state.case_source = None;
        let id = "retained-claim".to_owned();
        state.dependency_review.claims.insert(
            id.clone(),
            ForeignUnusedClaim {
                id,
                api: "/api".into(),
                method_api: "GET /api".into(),
                recording_run_id: state.recording_run_id.clone(),
                source_revision: "old-revision".into(),
                source_inventory_id: "old-inventory".into(),
                attempt: 27,
                execution_identity: "old-execution".into(),
                report_sha256: "old-report".into(),
                source_exchange_ids: BTreeSet::from([Uuid::new_v4()]),
                exclusion: None,
                reason: "still needs ownership review".into(),
                status: ClaimStatus::Pending,
                rejection: None,
            },
        );

        assert!(required_action(Path::new("."), &state).is_none());
    }
}
