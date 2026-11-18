pub mod investigations;
pub use investigations::*;
pub mod model;
pub use model::*;
pub mod decisions;
pub use decisions::*;

pub mod rules;

pub fn assignment_id(state: &crate::rewrite::model::RewriteState) -> anyhow::Result<String> {
    Ok(traffic_engine::policy_evidence::digest(
        &serde_json::to_vec(&(
            &state.workflow_id,
            &state.recording_run_id,
            &state.source_revision,
            state.dependency_review.revision,
        ))?,
    ))
}
