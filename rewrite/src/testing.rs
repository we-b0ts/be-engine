//! Fixtures and fault injection for cross-library coordinator regression tests.
pub use crate::unified_rule::UnifiedRulePlanRecordMethods;
use crate::{RewriteAction, RewriteEvidenceReport, RewriteWorkScope, model::RewriteState};
use anyhow::Result;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

pub struct RewriteStore(crate::store::RewriteStore);
impl RewriteStore {
    pub fn new(root: &Path) -> Result<Self> {
        crate::store::RewriteStore::new(root).map(Self)
    }
    pub fn load(&self) -> Result<Option<RewriteState>> {
        self.0.load()
    }
    pub fn save(&self, state: &RewriteState) -> Result<()> {
        self.0.save(state)
    }
    pub fn lock(&self) -> Result<traffic_rewrite_core::WorkflowLock> {
        self.0.lock()
    }
}

pub fn configured_target() -> tempfile::TempDir {
    crate::workflow_test_support::configured_target()
}
pub fn implementation_state_with_inventory(include_pending: bool) -> RewriteState {
    crate::workflow_test_support::implementation_state_with_inventory(include_pending)
}
pub fn query_issue_evidence(
    root: &Path,
    state: &RewriteState,
    id: &str,
) -> Result<RewriteEvidenceReport> {
    crate::evidence::query(root, state, id)
}
pub fn batch_information(root: &Path, state: &RewriteState) -> Result<Value> {
    crate::unified_rule::batch::information(root, state)
}
pub fn idle_rule_plan_action(root: &Path, state: &RewriteState) -> Result<Option<RewriteAction>> {
    crate::rule_plans::idle_action(root, state)
}
pub fn attribution_required_action(root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    crate::dependency_review::required_action(root, state)
}
pub fn request_capture(
    state: &mut RewriteState,
    scopes: &BTreeMap<String, String>,
    proof_id: &str,
) -> Result<()> {
    crate::verification_obligations::request_capture(state, scopes, proof_id)
}
pub fn replay_admitted(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    crate::replay_admission::admitted(state, scope)
}
pub fn worker_acceptance_ready(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    crate::worker::runtime::acceptance_ready(state, scope)
}
pub fn batch_execution_identity(root: &Path) -> Result<String> {
    crate::batch_execution_identity(root)
}
pub fn dependency_attribution_snapshot(root: &Path, run: &str) -> Result<String> {
    crate::dependency_attribution_snapshot(root, run)
}

pub fn ownership_evidence_api(root: &Path, state: &RewriteState, id: &str) -> Result<String> {
    crate::inventory::api_for_ownership_evidence_id(root, state, id)
}

// Cross-library delivery regression fixtures and coordinator observations.
pub fn legacy_review(options: crate::RewriteReviewOptions) -> Result<crate::RewriteReviewReport> {
    crate::review::inspect_legacy(options)
}
pub fn worker_scopes(state: &RewriteState) -> Vec<RewriteWorkScope> {
    crate::worker::runtime::scopes(state)
}
pub fn worker_observation<'a>(
    state: &'a RewriteState,
    scope: &RewriteWorkScope,
) -> Option<&'a crate::worker::model::RewriteWorkerObservation> {
    crate::worker::runtime::observation(state, scope)
}
pub fn worker_coverage(
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> crate::worker::model::RewriteWorkerCoverageState {
    crate::worker::runtime::coverage(state, scope)
}
pub fn worker_inventory(
    root: &Path,
    state: &RewriteState,
) -> Vec<crate::worker::model::RewriteWorkerInventoryItem> {
    crate::worker::scheduler::inventory(root, state)
}
pub fn delivery_context(
    root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> crate::review::DeliveryContext {
    crate::review::context(root, state, scope)
}
pub fn activate_api(state: &mut RewriteState, api: Option<&crate::RecordingApi>) -> Result<bool> {
    crate::inventory::activate_requested(state, api)
}
pub fn defer_completed_apis(state: &mut RewriteState, fingerprint: &str) -> Result<bool> {
    crate::inventory::defer_completed_for_target_change(state, fingerprint)
}
pub fn api_is_skipped(state: &RewriteState, api: &str) -> bool {
    crate::regression_scope::is_skipped(state, api)
}
pub fn engine_retry_pending(state: &RewriteState, slice: &crate::model::RewriteSliceState) -> bool {
    crate::engine_retry::pending(state, slice)
}
pub fn reserve_engine_retry(state: &mut RewriteState) -> bool {
    crate::engine_retry::reserve(state, None)
}
pub fn reserve_current_route_engine_retry(state: &mut RewriteState) -> bool {
    let mut route = crate::api_batch::PreparedRoute {
        apis: vec![state.api.clone()],
        slices: std::iter::once((state.api.clone(), state.active_slice.clone())).collect(),
    };
    crate::engine_retry::reserve(state, Some(&mut route))
}

pub use crate::review::testing as review;

pub fn workflow_state() -> RewriteState {
    crate::workflow_test_support::test_state()
}

pub fn integrate_current_worker(state: &mut RewriteState) {
    crate::worker::integrate_current_for_test(state)
}
pub fn worker_scoped(state: &RewriteState, scope: &RewriteWorkScope) -> Result<RewriteState> {
    crate::worker::runtime::scoped(state, scope)
}
pub fn worker_dispatch(
    state: &RewriteState,
    scope: RewriteWorkScope,
    requested: Option<RewriteWorkScope>,
) -> traffic_rewrite_model::rewrite::worker::model::RewriteWorkerDispatchView {
    crate::worker::dispatch_view(state, scope, requested)
}
pub fn scoped_status(root: &Path, state: &RewriteState) -> Result<crate::RewriteActionEnvelope> {
    crate::action::for_scoped_status(root, state)
}

pub fn workflow_issue(id: &str, attempt: u64, fingerprint: &str) -> crate::model::RewriteIssue {
    crate::workflow_test_support::issue(id, attempt, fingerprint)
}
pub fn install_api_inventory(state: &mut RewriteState, apis: Vec<String>) -> Result<bool> {
    crate::inventory::install(state, apis)
}
pub fn resume_api_index(state: &mut RewriteState, index: usize) -> Result<()> {
    crate::inventory::resume_at(state, index)
}
pub fn api_in_revalidation_round(state: &RewriteState, api: &str) -> bool {
    crate::inventory::revalidation_round::contains(state, api)
}
pub fn apply_regression_scope(root: &Path, state: &mut RewriteState) -> Result<bool> {
    crate::regression_scope::apply(root, state)
}
pub fn complete_replay_if_ready(root: &Path, state: &mut RewriteState) -> Result<bool> {
    crate::transition::complete_replay_if_ready(root, state)
}

pub fn workflow_status(root: &Path, state: &RewriteState) -> Result<crate::RewriteActionEnvelope> {
    crate::action::for_status(root, state)
}

pub fn complete_current_api(state: &mut RewriteState) -> Result<bool> {
    crate::inventory::complete_current_and_advance(state)
}
pub fn repair_api(state: &RewriteState, id: &str) -> Option<String> {
    crate::inventory::api_for_repair(state, id)
}
pub fn finish_revalidation_api(state: &mut RewriteState, api: &str) {
    crate::inventory::revalidation_round::finish(state, api)
}

pub use crate::expert::model::RewriteExpertInventoryItem;
pub fn expert_inventory(root: &Path, state: &RewriteState) -> Vec<RewriteExpertInventoryItem> {
    crate::expert::inventory(root, state)
}
pub fn expert_required_action(
    root: &Path,
    state: &RewriteState,
    api: Option<&str>,
) -> Option<RewriteAction> {
    crate::expert::required_action(root, state, api)
}
pub fn expert_counts(state: &RewriteState) -> (usize, usize, usize) {
    crate::expert::counts(state)
}
pub fn confirm_current_worker(state: &mut RewriteState) {
    crate::worker::confirm_current_for_test(state);
}
pub fn implementer_dispatch(
    root: &Path,
    state: &RewriteState,
    group: &str,
) -> Result<Option<crate::ImplementerDispatch>> {
    crate::implementer::dispatch(root, state, group)
}
pub fn implementer_pool(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<crate::ImplementerPoolView>> {
    crate::implementer::view(root, state)
}

pub fn expert_api_verified(state: &RewriteState, api: &str) -> bool {
    crate::expert::verified(state, api)
}
