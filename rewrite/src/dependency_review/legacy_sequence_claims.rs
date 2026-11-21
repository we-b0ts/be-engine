//! Retire unreviewed ownership claims generated solely from a Replay timeout.
use super::{model::ClaimStatus, source};
use crate::model::RewriteState;
use anyhow::{Context, Result};

pub(crate) fn retire_pending(state: &mut RewriteState) -> Result<()> {
    let mut retired = Vec::new();
    for (id, claim) in &state.dependency_review.claims {
        if claim.status != ClaimStatus::Pending || claim.exclusion.is_some() {
            continue;
        }
        let mut ids = claim.source_exchange_ids.iter();
        let (Some(exchange), None) = (ids.next(), ids.next()) else {
            continue;
        };
        // The old automatic path used a different identity from explicit
        // submissions. A matching reason alone cannot retire an explicit claim.
        let automatic = source::digest(&serde_json::to_vec(&(
            "missing-sequence-ownership/v1",
            &state.workflow_id,
            &claim.method_api,
            &claim.recording_run_id,
            &claim.source_inventory_id,
            &claim.source_revision,
            exchange,
        ))?);
        if *id == automatic {
            retired.push(id.clone());
        }
    }
    if !retired.is_empty() {
        state.dependency_review.revision = state
            .dependency_review
            .revision
            .checked_add(1)
            .context("attribution revision exhausted")?;
        for id in retired {
            state.dependency_review.claims.remove(&id);
        }
        state.bump();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency_review::model::ForeignUnusedClaim;
    use std::collections::BTreeSet;
    use uuid::Uuid;

    #[test]
    fn retires_automatic_pending_claims_without_losing_explicit_or_reviewed_claims() {
        let mut state = crate::test_state();
        let original_revision = state.dependency_review.revision;
        let make_claim = |exchange| {
            let method_api = "GET /api";
            let source_inventory_id = "sealed-inventory";
            let source_revision = "source-revision";
            let id = source::digest(
                &serde_json::to_vec(&(
                    "missing-sequence-ownership/v1",
                    &state.workflow_id,
                    method_api,
                    &state.recording_run_id,
                    source_inventory_id,
                    source_revision,
                    exchange,
                ))
                .unwrap(),
            );
            ForeignUnusedClaim {
                id,
                api: "/api".into(),
                method_api: method_api.into(),
                recording_run_id: state.recording_run_id.clone(),
                source_revision: source_revision.into(),
                source_inventory_id: source_inventory_id.into(),
                attempt: 1,
                execution_identity: "execution".into(),
                report_sha256: "report".into(),
                source_exchange_ids: BTreeSet::from([exchange]),
                exclusion: None,
                reason: "The expected request was missing".into(),
                status: ClaimStatus::Pending,
                rejection: None,
            }
        };
        let automatic = make_claim(Uuid::new_v4());
        let mut explicit = automatic.clone();
        explicit.id = "explicit-claim".into();
        let mut reviewed = make_claim(Uuid::new_v4());
        reviewed.status = ClaimStatus::Unresolved;
        let retired = automatic.id.clone();
        state.dependency_review.claims = [automatic, explicit.clone(), reviewed.clone()]
            .into_iter()
            .map(|claim| (claim.id.clone(), claim))
            .collect();

        retire_pending(&mut state).unwrap();
        assert!(!state.dependency_review.claims.contains_key(&retired));
        assert_eq!(
            state.dependency_review.claims[&explicit.id].status,
            ClaimStatus::Pending
        );
        assert_eq!(
            state.dependency_review.claims[&reviewed.id].status,
            ClaimStatus::Unresolved
        );
        assert_eq!(state.dependency_review.revision, original_revision + 1);
        retire_pending(&mut state).unwrap();
        assert_eq!(state.dependency_review.revision, original_revision + 1);
    }
}
