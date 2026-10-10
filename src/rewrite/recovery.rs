use anyhow::Result;

use super::model::RewriteRecoveryReport;
use super::store::RewriteStore;
use super::{RewriteContext, action, traffic_operation};
use crate::E2eRunContext;

pub(super) async fn recover(context: RewriteContext) -> Result<RewriteRecoveryReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    super::execution::recover(&target_root)?;
    let store = RewriteStore::new(&target_root)?;
    if let traffic_operation::TrafficOperationState::Live(marker) =
        traffic_operation::state(&target_root)?
    {
        anyhow::bail!(
            "traffic {:?} process {} is still active; inspect `backend-rewrite status`",
            marker.kind,
            marker.pid
        );
    }
    let recovered_stale_traffic_operation = traffic_operation::clear_stale(&target_root)?;
    let recovered_stale_lock = store.recover_lock()?;
    let _lock = store.lock()?;
    let state = store.load()?;
    let recovered_focused_attempt = match state {
        Some(state) => match (state.case_source.clone(), state.group_id.clone()) {
            (Some(case_source), Some(group_id)) => {
                crate::e2e_run::recover_focused_e2e_api(
                    E2eRunContext {
                        target_root: target_root.clone(),
                        case_source,
                        run_key: None,
                    },
                    &group_id,
                )
                .await?
            }
            _ => false,
        },
        None => false,
    };
    Ok(RewriteRecoveryReport {
        recovered_stale_lock,
        recovered_stale_traffic_operation,
        recovered_focused_attempt,
        next: action::next_command(&target_root),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recovery_does_not_finalize_or_replace_external_recordings() {
        let target = crate::rewrite::worker::tests::configured_target();
        let state = crate::rewrite::test_state();
        let store = RewriteStore::new(target.path()).unwrap();
        store.save(&state).unwrap();
        let manifest =
            crate::rewrite::artifacts::recording_manifest(target.path(), &state.recording_run_id);
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        let running = br#"{"status":"running","recording_apis":["GET /api"],"published_cases":1}"#;
        std::fs::write(&manifest, running).unwrap();
        recover(RewriteContext {
            target_root: target.path().to_owned(),
        })
        .await
        .unwrap();
        assert_eq!(std::fs::read(&manifest).unwrap(), running);
        let saved = store.load().unwrap().unwrap();
        assert_eq!(saved.recording_run_id, state.recording_run_id);
        assert_eq!(saved.phase, state.phase);
        assert_eq!(saved.revision, state.revision);
    }
}
