//! Export selected accepted deliveries and validate their immutable batch identity.
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct RewriteIntegrationBatchOptions {
    pub target_root: PathBuf,
    pub worktree: PathBuf,
    pub apis: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RewriteIntegrationBatchReport {
    pub schema_version: u32,
    pub workflow_id: String,
    pub recording_run_id: String,
    pub canonical_base_revision: String,
    pub batch_path: PathBuf,
    pub handoffs: Vec<RewriteIntegrationBatchDelivery>,
    pub check: super::super::RewriteCommandSpec,
}

#[derive(Debug, Serialize)]
pub struct RewriteIntegrationBatchDelivery {
    #[serde(flatten)]
    pub identity: IntegrationHandoffReview,
    pub agent_handle: Option<String>,
    pub worker_worktree: PathBuf,
    pub worker_base_revision: String,
    pub delivery_commit: String,
    pub worker_review_report: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchDocument {
    schema_version: u32,
    workflow_id: String,
    recording_run_id: String,
    handoffs: Vec<IntegrationHandoffReview>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BatchInput {
    Exported(BatchDocument),
    Selections(Vec<IntegrationHandoffSelection>),
}

pub fn export(options: RewriteIntegrationBatchOptions) -> Result<RewriteIntegrationBatchReport> {
    ensure!(
        !options.apis.is_empty(),
        "batch export requires at least one API"
    );
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow is not initialized")?;
    let worktree = source_diff::project_root_in_worktree(&target_root, &options.worktree)?;
    candidate::same_repository(&target_root, &worktree)?;
    let selections = options
        .apis
        .iter()
        .map(|api| {
            let scope = candidate::current_handoff_scope(
                &state,
                &RewriteWorkScope::Api { api: api.clone() },
            )?;
            let handoff_id = worker::runtime::observation(&state, &scope)
                .and_then(|observation| observation.handoff_id.clone())
                .with_context(|| format!(
                    "batch export requires a current accepted handoff for {}; refresh inventory and select a ready delivery",
                    scope.label()
                ))?;
            Ok(IntegrationHandoffSelection { scope, handoff_id })
        })
        .collect::<Result<Vec<_>>>()?;
    // Export and full review share admission. Export never reserves or consumes a handoff.
    let identities = candidate::batch_handoffs(&state, &selections)?;
    let handoffs = identities
        .iter()
        .map(|identity| {
            let binding = state.worker_bindings.get(&identity.scope.binding_key())
                .context("accepted handoff has no worker binding")?;
            let review = binding.review_report.as_ref().with_context(|| format!(
                "batch export for {} requires its accepted worker review; refresh inventory",
                identity.scope.label()
            ))?;
            ensure!(
                review.dispatch_id.as_deref() == Some(identity.dispatch_id.as_str()),
                "accepted worker review is stale for {}; refresh inventory and reconcile the handoff",
                identity.scope.label()
            );
            Ok(RewriteIntegrationBatchDelivery {
                identity: identity.clone(),
                agent_handle: binding.agent_handle.clone(),
                worker_worktree: review.worktree.clone(),
                worker_base_revision: review.base_revision.clone(),
                delivery_commit: review.head_revision.clone(),
                worker_review_report: review.report_path.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let canonical_base_revision = candidate::head(&target_root)?;
    let batch_path = crate::internal_runtime::root(&target_root)
        .join("review-batches")
        .join(format!("{}.json", uuid::Uuid::new_v4().simple()));
    write_batch(
        &batch_path,
        &BatchDocument {
            schema_version: 1,
            workflow_id: state.workflow_id.clone(),
            recording_run_id: state.recording_run_id.clone(),
            handoffs: identities,
        },
    )?;
    let check = action::command(
        &target_root,
        vec![
            "review".into(),
            "check".into(),
            "--integration".into(),
            "--worktree".into(),
            worktree.to_string_lossy().into_owned(),
            "--batch-handoffs".into(),
            batch_path.to_string_lossy().into_owned(),
        ],
        Vec::new(),
    );
    Ok(RewriteIntegrationBatchReport {
        schema_version: 1,
        workflow_id: state.workflow_id,
        recording_run_id: state.recording_run_id,
        canonical_base_revision,
        batch_path,
        handoffs,
        check,
    })
}

pub fn check_file(options: RewriteReviewOptions, path: &Path) -> Result<RewriteReviewReport> {
    match read_json::<BatchInput>(path)? {
        BatchInput::Selections(handoffs) => super::check_batch(options, handoffs),
        BatchInput::Exported(document) => {
            ensure!(
                options.integration
                    && options.worktree.is_some()
                    && options.scope.is_none()
                    && options.handoff_id.is_none(),
                "batch review requires --integration without a single work-item selector"
            );
            ensure!(
                !document.handoffs.is_empty(),
                "batch review requires at least one handoff"
            );
            ensure!(
                document.schema_version == 1,
                "unsupported integration batch schema {}",
                document.schema_version
            );
            let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
            let state = RewriteStore::new(&target_root)?
                .load()?
                .context("rewrite workflow is not initialized")?;
            ensure!(
                document.workflow_id == state.workflow_id
                    && document.recording_run_id == state.recording_run_id,
                "integration batch belongs to another workflow or recording; export the selected batch again"
            );
            let selections = document
                .handoffs
                .iter()
                .map(|handoff| IntegrationHandoffSelection {
                    scope: handoff.scope.clone(),
                    handoff_id: handoff.handoff_id.clone(),
                })
                .collect::<Vec<_>>();
            let current = candidate::batch_handoffs(&state, &selections)?;
            for (expected, actual) in document.handoffs.iter().zip(&current) {
                ensure!(
                    expected.dispatch_id == actual.dispatch_id,
                    "integration batch dispatch is stale for {}; exported_dispatch_id={:?}, current_dispatch_id={:?}; refresh inventory and export the selected batch again",
                    actual.scope.label(),
                    expected.dispatch_id,
                    actual.dispatch_id
                );
            }
            // Use the same state snapshot for identity checks and the complete review.
            super::check_candidate(
                &target_root,
                &project,
                &state,
                options,
                Some(&selections),
                false,
            )
        }
    }
}

fn write_batch(path: &Path, document: &BatchDocument) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(document)?;
    let parent = path.parent().context("integration batch has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
