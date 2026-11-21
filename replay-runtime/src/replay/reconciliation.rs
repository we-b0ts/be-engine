//! Dependency closure for one actual session, separate from focused API gates.
use super::*;
use crate::dependency::observation::{RecordingManifest, SemanticInventory};

#[derive(Debug, Clone)]
pub(super) struct BatchScope {
    source_inventory_id: String,
    recording_run_id: String,
    recording_run_epoch: Uuid,
    process_epochs: Vec<Uuid>,
    required_cases: BTreeSet<String>,
    selected_cases: BTreeSet<String>,
    source_capture_complete: bool,
    pub unlocated_inventory_gap: bool,
    pub inventory: SemanticInventory,
}

pub use traffic_engine_replay::replay::reconciliation::BatchReconciliation;

impl BatchScope {
    pub(super) fn new(
        root: &Path,
        manifest: &RecordingManifest,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<Self> {
        let source_inventory_id = crate::policy_evidence::digest(&std::fs::read(
            root.join(crate::dependency::observation::MANIFEST_FILE),
        )?);
        Ok(Self {
            source_inventory_id,
            recording_run_id: manifest.run_id.clone(),
            recording_run_epoch: manifest.run_epoch,
            process_epochs: manifest.process_epochs.clone(),
            required_cases: manifest
                .inputs
                .iter()
                .map(|input| input.case_id.to_string())
                .collect(),
            selected_cases: cases.keys().cloned().collect(),
            source_capture_complete: manifest.capture_complete,
            unlocated_inventory_gap: manifest.coverage.inventory_gaps,
            inventory: manifest.semantic_inventory.clone(),
        })
    }

    pub(super) fn exclude_optional_unattributed(&mut self, count: u64) -> Result<()> {
        let by_owner = self
            .inventory
            .by_owner_kind
            .entry("unattributed".into())
            .or_default();
        ensure!(
            count <= *by_owner
                && count <= self.inventory.unattributed_dependencies
                && count <= self.inventory.total_mandatory,
            "proven optional controls exceed the sealed unattributed inventory"
        );
        *by_owner -= count;
        self.inventory.unattributed_dependencies -= count;
        self.inventory.total_mandatory -= count;
        Ok(())
    }

    pub(super) fn report<S: traffic_replay::report::SessionSnapshot>(
        &self,
        report: &ReplayReport<S>,
    ) -> BatchReconciliation {
        let mut unused_run_dependencies = report.native.unused_run_dependencies();
        for (protocol, native) in &report.dependency_protocols {
            *unused_run_dependencies.entry(protocol.clone()).or_default() +=
                native.unused_global_count;
        }
        // Teardown is retained outside executable primary inputs. Until a real
        // teardown driver delivers these facts, WholeSource cannot certify them.
        let shutdown = self
            .inventory
            .by_owner_kind
            .get("shutdown")
            .copied()
            .unwrap_or(0);
        if shutdown > 0 {
            unused_run_dependencies
                .insert("shutdown".into(), shutdown.try_into().unwrap_or(usize::MAX));
        }
        // Actual requests outside a primary Case remain independent obligations.
        let actual_unmatched_or_unsafe = report.native.unmatched_or_unsafe()
            + report.unrecorded_targets.len()
            + report
                .dependency_protocols
                .values()
                .map(|native| native.unmatched_count)
                .sum::<usize>();
        let complete_source_scope =
            self.required_cases == self.selected_cases && !self.required_cases.is_empty();
        let execution_complete = report.is_complete() && report.finalized;
        let startup_phase_complete = !report.startup_phase.is_dirty();
        let provisional_hypotheses_used = !report.dependency_pre_matches.is_empty()
            || report.dependency_hypothesis_coverage_error.is_some();
        let dependency_inventory_verified = complete_source_scope
            && self.source_capture_complete
            && execution_complete
            && self.inventory.unattributed_dependencies == 0
            && self
                .inventory
                .unsupported_by_scope
                .values()
                .all(|protocols| protocols.values().all(|count| *count == 0))
            && unused_run_dependencies.values().all(|count| *count == 0)
            && actual_unmatched_or_unsafe == 0
            && !provisional_hypotheses_used
            && startup_phase_complete
            && !report.is_dirty();
        BatchReconciliation {
            schema: "dependency-reconciliation/v3".into(),
            session_id: report.session_id.clone(),
            source_inventory_id: self.source_inventory_id.clone(),
            recording_run_id: self.recording_run_id.clone(),
            recording_run_epoch: self.recording_run_epoch,
            process_epochs: self.process_epochs.clone(),
            dependency_attribution_snapshot: report.dependency_attribution_snapshot.clone(),
            complete_source_scope,
            source_capture_complete: self.source_capture_complete,
            execution_complete,
            required_cases: self.required_cases.clone(),
            selected_cases: self.selected_cases.clone(),
            source_inventory: self.inventory.clone(),
            unused_run_dependencies,
            actual_unmatched_or_unsafe,
            provisional_hypotheses_used,
            startup_phase_complete,
            dependency_inventory_verified,
        }
    }
}
