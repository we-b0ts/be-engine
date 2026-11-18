//! Coordinator observations used by cross-library delivery regression suites.
use super::*;
pub fn candidate_current_handoff_scope(
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> Result<RewriteWorkScope> {
    super::candidate::current_handoff_scope(state, scope)
}

pub fn candidate_batch_handoffs(
    state: &RewriteState,
    selections: &[IntegrationHandoffSelection],
) -> Result<Vec<IntegrationHandoffReview>> {
    super::candidate::batch_handoffs(state, selections)
}

pub fn candidate_accept_locked(
    root: &Path,
    state: &mut RewriteState,
    path: &Path,
    expected_scope: Option<&RewriteWorkScope>,
    expected_handoff: Option<&str>,
) -> Result<Option<String>> {
    super::candidate::accept_locked(root, state, path, expected_scope, expected_handoff)
}

pub fn integrated_current(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteReviewReport>> {
    super::integrated::current(root, state)
}

pub fn integrated_terminal_current(root: &Path, state: &RewriteState) -> bool {
    super::integrated::terminal_current(root, state)
}

pub fn integrated_admission_current(root: &Path, state: &RewriteState) -> bool {
    super::integrated::admission_current(root, state)
}

pub fn integrated_required_action(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    super::integrated::required_action(root, state)
}

pub fn integrated_gate(
    root: &Path,
    state: &RewriteState,
    _pr_base: &str,
) -> Result<Option<RewriteAction>> {
    super::integrated::gate(root, state, _pr_base)
}

pub fn pre_revalidation_current(root: &Path, state: &RewriteState) -> bool {
    super::pre_revalidation::current(root, state)
}

pub fn pre_revalidation_required_action(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    super::pre_revalidation::required_action(root, state)
}

pub fn integrated_path(root: &Path) -> PathBuf {
    super::integrated_path(root)
}

pub fn is_rework_wait(action: &RewriteAction) -> bool {
    super::integrated::is_rework_wait(action)
}

pub fn pre_revalidation_ready(state: &RewriteState) -> bool {
    super::pre_revalidation::ready(state)
}

pub fn pre_revalidation_completion_current(root: &Path, state: &RewriteState) -> bool {
    super::pre_revalidation::completion_current(root, state)
}

pub fn pre_revalidation_reconcile(root: &Path, state: &mut RewriteState) -> Result<bool> {
    super::pre_revalidation::reconcile(root, state)
}

pub fn pre_revalidation_admit(
    root: &Path,
    state: &mut RewriteState,
    report: &RewriteReviewReport,
) -> Result<()> {
    super::pre_revalidation::admit(root, state, report)
}

pub fn pre_revalidation_checked_path(root: &Path) -> PathBuf {
    super::pre_revalidation::checked_path(root)
}

pub fn pre_revalidation_accepted_path(root: &Path) -> PathBuf {
    super::pre_revalidation::accepted_path(root)
}
