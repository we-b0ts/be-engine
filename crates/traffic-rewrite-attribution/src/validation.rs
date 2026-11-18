//! Source-backed ownership proposal validation and assignment identity.
use super::source;
use anyhow::{Context, Result, ensure};
use traffic_engine::dependency::attribution::DependencyOwner;
use traffic_rewrite_model::rewrite::dependency_review::model::ProposedAttribution;
use traffic_rewrite_model::rewrite::model::RewriteState;
use traffic_rewrite_model::rewrite::verification_obligations::{self, VerificationScope};

pub fn validate_proposal(
    state: &RewriteState,
    source: &source::SourceSnapshot,
    proposal: &ProposedAttribution,
) -> Result<()> {
    ensure!(
        !proposal.source_task.trim().is_empty() && proposal.source_task.len() <= 128,
        "attribution requires an actual bounded Source task/entrypoint"
    );
    proposal.proof.validate(
        state
            .source_revision
            .as_deref()
            .context("Source revision absent")?,
    )?;
    proposal.owner.validate()?;
    ensure!(
        !matches!(proposal.owner, DependencyOwner::Unattributed { .. }),
        "unresolved ownership is not a proven decision"
    );
    ensure!(
        !proposal.source_exchange_ids.is_empty(),
        "attribution proof requires original Source occurrences"
    );
    for id in &proposal.source_exchange_ids {
        let event = source
            .exchanges
            .get(id)
            .context("attribution occurrence is absent from original Source inventory")?;
        ensure!(
            event.complete,
            "attribution cannot exempt incomplete original capture"
        );
        ensure!(
            proposal
                .claim_ids
                .iter()
                .all(|claim| state.dependency_review.claims.contains_key(claim)),
            "unknown attribution claim"
        );
    }
    for claim_id in &proposal.claim_ids {
        let claim = &state.dependency_review.claims[claim_id];
        ensure!(
            claim.recording_run_id == state.recording_run_id
                && claim.source_inventory_id == source.identity,
            "attribution claim belongs to changed Source inventory"
        );
        ensure!(
            !claim
                .source_exchange_ids
                .is_disjoint(&proposal.source_exchange_ids),
            "attribution proof does not cover the claimed occurrences"
        );
    }
    let scope_valid = match (&proposal.owner, &proposal.obligation_scope) {
        (DependencyOwner::Case { origin_case_id, .. }, scope @ VerificationScope::Api { .. }) => {
            source
                .apis
                .get(origin_case_id)
                .is_some_and(|api| verification_obligations::scope_matches_api(scope, api))
        }
        (
            DependencyOwner::Process {
                process_epoch,
                source_task,
                ..
            },
            VerificationScope::Process {
                process_epoch: epoch,
                source_task: task,
            },
        ) => process_epoch == epoch && source_task == task && source.epochs.contains(epoch),
        (
            DependencyOwner::Startup {
                process_epoch,
                initialization_unit,
            },
            VerificationScope::Startup {
                process_epoch: epoch,
                initialization_unit: unit,
            },
        ) => process_epoch == epoch && initialization_unit == unit && source.epochs.contains(epoch),
        _ => false,
    };
    ensure!(
        scope_valid,
        "verification obligation must belong to the actual proven origin scope"
    );
    if proposal.impact == verification_obligations::VerificationImpact::MissingCapture {
        ensure!(
            proposal
                .missing_evidence
                .as_ref()
                .is_some_and(|reason| !reason.trim().is_empty()),
            "capture obligation requires concrete missing evidence"
        );
    }
    Ok(())
}
pub use traffic_rewrite_model::rewrite::dependency_review::assignment_id;
