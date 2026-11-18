//! Canonical ownership identity hashes shared proofs and all finite UUID members.
use super::*;

impl DecisionSet {
    pub fn snapshot(
        &self,
        recording_run_id: &str,
        source_revision: Option<&str>,
        source_inventory_id: &str,
        mut eligible: impl FnMut(&DecisionTemplate) -> bool,
    ) -> Result<String> {
        let mut groups = self
            .groups
            .iter()
            .filter(|group| eligible(&group.template))
            .map(Arc::as_ref)
            .collect::<Vec<_>>();
        groups.sort_unstable_by(|left, right| {
            left.template
                .proof_id
                .cmp(&right.template.proof_id)
                .then_with(|| {
                    left.template
                        .proof_revision
                        .cmp(&right.template.proof_revision)
                })
                .then_with(|| left.exchange_ids.cmp(&right.exchange_ids))
        });
        traffic_recording_store::attribution::snapshot_identity(
            recording_run_id,
            source_revision,
            source_inventory_id,
            &groups,
        )
    }
}
