use super::*;
use crate::rewrite::RewriteActionEnvelope;
use crate::rewrite::model::{
    RewriteApiStatus, RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase,
};

/// Coordinator-owned routing. Quality findings do not become fake Replay failures.
pub fn rework(
    target_root: PathBuf,
    finding_id: &str,
    scope: RewriteWorkScope,
) -> Result<RewriteActionEnvelope> {
    rework_with_report(target_root, finding_id, scope, None)
}

/// Route a source finding from an unpublished integration candidate or the
/// current canonical report. A failing candidate is never published or admitted.
pub fn rework_with_report(
    target_root: PathBuf,
    finding_id: &str,
    scope: RewriteWorkScope,
    report_path: Option<PathBuf>,
) -> Result<RewriteActionEnvelope> {
    let (root, project) = crate::e2e_run::resolve_project(&target_root)?;
    let store = RewriteStore::new(&root)?;
    let _lock = store.lock()?;
    ensure!(
        matches!(
            crate::rewrite::traffic_operation::state(&root)?,
            crate::rewrite::traffic_operation::TrafficOperationState::Absent
        ),
        "quality rework must wait for traffic verification"
    );
    let mut state = store.load()?.context("rewrite workflow is absent")?;
    let scope = crate::rewrite::api_selector::canonical_scope(&state, &scope);
    let report = if let Some(path) = report_path.as_deref() {
        candidate_report(&root, &state, &project, path)?
    } else {
        show(root.clone())?
    };
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == finding_id)
        .context("review finding is absent")?;
    ensure!(
        report.status != ReviewStatus::Passed,
        "passed source review does not require rework"
    );
    if state
        .source_review_rework
        .get(&scope.binding_key())
        .is_some_and(|route| route.target_fingerprint == report.target_fingerprint)
        && worker::runtime::scopes(&state).contains(&scope)
        && !worker::runtime::acceptance_ready(&state, &scope)
    {
        // Additional findings for the same repair must not supersede a live turn.
        if let std::collections::btree_map::Entry::Vacant(entry) = state
            .source_review_rework
            .get_mut(&scope.binding_key())
            .unwrap()
            .findings
            .entry(finding_id.to_string())
        {
            entry.insert(finding.clone());
            state.bump();
            store.save(&state)?;
        }
        drop(_lock);
        return worker::runtime::current_envelope(&root);
    }
    let evidence_instruction = if let Some(path) = report_path {
        format!(
            "Read context.review.rework.findings and the original integration candidate report {} for source evidence; this candidate was not published.",
            path.display()
        )
    } else {
        "Read backend-rewrite review show for the current finding and evidence contract.".into()
    };
    let issue = RewriteIssue {
        id: format!("quality-{finding_id}"),
        kind: RewriteIssueKind::TargetQuality,
        owner: RewriteIssueOwner::TargetCode,
        summary: format!(
            "Source quality review: {}:{}: {}. {}",
            finding.file.display(),
            finding.line,
            finding.message,
            evidence_instruction,
        ),
        pointer_pattern: None,
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: vec![finding.message.clone()],
        observed_target_fingerprint: report.target_fingerprint.clone(),
        attempt: 0,
    };
    match &scope {
        RewriteWorkScope::Api { api } => {
            let mut scoped = crate::rewrite::api_selector::scoped(&state, api)?;
            let selected_api = scoped.api.clone();
            ensure!(
                scoped.rule_plan.is_none()
                    && scoped.dependency_rule_plan.is_none()
                    && scoped.recorder_capture_plan.is_none(),
                "finish the work item's pending rule plan before routing quality rework"
            );
            ensure!(
                matches!(
                    scoped.phase,
                    RewritePhase::ImplementationRequired
                        | RewritePhase::SliceComplete
                        | RewritePhase::ApiPending
                ),
                "finish the work item's current rule/recording/repair transition before routing quality rework"
            );
            scoped.phase = RewritePhase::ImplementationRequired;
            // Preserve an existing behavioral issue; its worker also receives review context.
            if scoped.active_issue.is_none() {
                scoped.active_issue = Some(issue);
            }
            if state.api == selected_api {
                state.active_slice = scoped.active_slice;
            } else {
                state
                    .parked_slices
                    .insert(selected_api.clone(), scoped.active_slice);
            }
            if let Some(item) = state
                .api_inventory
                .iter_mut()
                .find(|item| item.api == selected_api)
            {
                item.status = RewriteApiStatus::ImplementationRequired;
            }
        }
    }
    if let Some(binding) = state.worker_bindings.get_mut(&scope.binding_key()) {
        binding.rework_generation = binding
            .rework_generation
            .checked_add(1)
            .context("rework generation overflow")?;
        binding.observation = None;
        // Newer feedback must not overwrite the coordinator's rework generation.
        let _feedback = worker::events::lock(&root)?;
        worker::events::publish(&root, &state, &scope)?;
    }
    state.source_review_rework.insert(
        scope.binding_key(),
        ReviewRework {
            target_fingerprint: report.target_fingerprint,
            findings: std::collections::BTreeMap::from([(finding_id.to_string(), finding.clone())]),
        },
    );
    state.bump();
    store.save(&state)?;
    drop(_lock);
    worker::runtime::current_envelope(&root)
}

fn candidate_report(
    root: &Path,
    state: &RewriteState,
    project: &crate::e2e_run::ResolvedProjectConfig,
    path: &Path,
) -> Result<RewriteReviewReport> {
    let report: RewriteReviewReport = read_json(path)?;
    let integration = report
        .integration
        .as_ref()
        .context("--report requires an integration candidate review")?;
    let worktree = fs::canonicalize(&report.worktree)?;
    candidate::same_repository(root, &worktree)?;
    candidate::fresh(root, &worktree, state, &report, project)?;
    ensure!(
        report.head_revision == candidate::head(&worktree)?,
        "candidate commit changed after review; rerun review check before routing rework"
    );
    ensure!(
        integration.canonical_base_revision == candidate::head(root)?
            && integration.canonical_base_fingerprint == fingerprint::repository_fingerprint(root)?,
        "canonical integration base changed; refresh the candidate review before routing rework"
    );
    Ok(report)
}

#[cfg(test)]
mod tests;
