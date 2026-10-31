//! Dependency closure for one actual session, separate from focused API gates.
use super::*;
use crate::dependency::observation::{RecordingManifest, SemanticInventory};
use serde::{Deserialize, Serialize};

mod validation;
pub(crate) use validation::validate_completed_receipt;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchReconciliation {
    pub schema: String,
    pub session_id: String,
    pub source_inventory_id: String,
    pub recording_run_id: String,
    pub recording_run_epoch: Uuid,
    pub process_epochs: Vec<Uuid>,
    pub dependency_attribution_snapshot: Option<String>,
    pub complete_source_scope: bool,
    pub source_capture_complete: bool,
    pub execution_complete: bool,
    pub required_cases: BTreeSet<String>,
    pub selected_cases: BTreeSet<String>,
    pub source_inventory: SemanticInventory,
    pub unused_run_dependencies: BTreeMap<String, usize>,
    pub actual_unmatched_or_unsafe: usize,
    pub provisional_hypotheses_used: bool,
    pub startup_phase_complete: bool,
    pub dependency_inventory_verified: bool,
}

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

    pub(super) fn report(&self, report: &ReplayReport) -> BatchReconciliation {
        let unused_run_dependencies = BTreeMap::from([
            ("mysql".into(), report.unused_global_exchange_count),
            ("http".into(), report.unused_global_http_exchange_count),
            (
                "redis".into(),
                report
                    .protocols
                    .redis
                    .unused_global_count
                    .unwrap_or(report.protocols.redis.unused_global.len()),
            ),
            (
                "memcached".into(),
                report
                    .protocols
                    .memcached
                    .unused_global_count
                    .unwrap_or(report.protocols.memcached.unused_global.len()),
            ),
            (
                "motan".into(),
                report
                    .protocols
                    .motan
                    .unused_global_count
                    .unwrap_or(report.protocols.motan.unused_global.len()),
            ),
            (
                "kafka".into(),
                report
                    .protocols
                    .kafka
                    .unused_global_count
                    .unwrap_or(report.protocols.kafka.unused_global.len()),
            ),
        ]);
        // Actual requests outside a primary Case remain independent obligations.
        let actual_unmatched_or_unsafe = report.unmatched_queries.len()
            + report.unsupported_commands.len()
            + report.unmatched_http_requests.len()
            + report.unsupported_http_exchanges.len()
            + report.http_request_header_mismatches.len()
            + report.protocols.redis.unmatched.len()
            + report.protocols.redis.unsupported.len()
            + report.protocols.redis.unsafe_events.len()
            + report.protocols.memcached.unmatched.len()
            + report.protocols.memcached.unsupported.len()
            + report.protocols.memcached.unsafe_events.len()
            + report.protocols.motan.unmatched.len()
            + report.protocols.motan.unsupported.len()
            + report.protocols.motan.unsafe_events.len()
            + report.protocols.kafka.unmatched.len()
            + report.protocols.kafka.unsupported.len()
            + report.protocols.kafka.unsafe_events.len()
            + report.unrecorded_targets.len();
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
