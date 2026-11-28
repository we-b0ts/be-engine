use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::model::{RewriteState, STATE_VERSION};

mod decision_history;
mod replacement;

pub use decision_history::{compact_rewrite_decision_history, verify_rewrite_decision_history};

pub(super) use traffic_rewrite_core::{
    WorkflowLock as RewriteLock, WorkflowLockState as RewriteLockState,
};

pub(super) struct RewriteStore {
    snapshots: traffic_rewrite_core::SnapshotStore,
    target_root: PathBuf,
}

impl RewriteStore {
    pub(super) fn new(target_root: &Path) -> Result<Self> {
        crate::initialize();
        let target_root = fs::canonicalize(target_root)
            .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
        let root = crate::internal_runtime::root(&target_root).join("rewrite");
        Ok(Self {
            snapshots: traffic_rewrite_core::SnapshotStore::new(root),
            target_root,
        })
    }

    pub(super) fn exists(&self) -> bool {
        self.snapshots.exists()
    }

    pub(super) fn load(&self) -> Result<Option<RewriteState>> {
        let mut state = self.load_snapshot()?;
        if let Some(state) = state.as_mut() {
            super::regression_scope::apply(&self.target_root, state)?;
            super::repository_analysis::refresh(&self.target_root, state)?;
            super::group_replay::refresh(state);
            super::implementer::refresh(state)?;
            super::dependency_review::refresh_receipts(&self.target_root, state)?;
        }
        Ok(state)
    }

    /// Load identity and feedback without adopting a possibly obsolete recording policy.
    pub(super) fn load_snapshot(&self) -> Result<Option<RewriteState>> {
        let Some(bytes) = self.snapshot_bytes()? else {
            return Ok(None);
        };
        let mut state: RewriteState = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "invalid rewrite state {}",
                self.snapshots.state_path().display()
            )
        })?;
        ensure!(
            state.version == STATE_VERSION,
            "unsupported rewrite state version {}",
            state.version
        );
        super::dependency_review::legacy_sequence_claims::retire_pending(&mut state)?;
        // Snapshot-based capture plans no longer have an apply path.
        for slice in
            std::iter::once(&mut state.active_slice).chain(state.parked_slices.values_mut())
        {
            if slice
                .recorder_capture_plan
                .as_ref()
                .is_some_and(|plan| plan.http_response.is_none())
            {
                slice.recorder_capture_plan = None;
            }
        }
        super::worker::events::overlay(&self.target_root, &mut state)?;
        super::rule_plans::events::overlay(&self.target_root, &mut state)?;
        super::repository_analysis::refresh(&self.target_root, &mut state)?;
        super::group_replay::refresh(&mut state);
        super::implementer::refresh(&mut state)?;
        Ok(Some(state))
    }

    pub(super) fn save(&self, state: &RewriteState) -> Result<()> {
        let _feedback = super::worker::events::lock(&self.target_root)?;
        let mut state = state.clone();
        super::worker::events::overlay(&self.target_root, &mut state)?;
        self.save_snapshot(&state, &_feedback)
    }

    /// Caller holds the feedback lock for an atomic workflow replacement.
    pub(super) fn save_snapshot(&self, state: &RewriteState, _feedback: &File) -> Result<()> {
        let _plans = super::rule_plans::events::lock(&self.target_root)?;
        let mut state = state.clone();
        super::rule_plans::events::overlay(&self.target_root, &mut state)?;
        state.dependency_review.decision_history.persist(
            &self.snapshots.root().join("decision-history"),
            &state.workflow_id,
        )?;
        let mut payload = serde_json::to_vec_pretty(&state)?;
        payload.push(b'\n');
        self.write_snapshot(&payload, state.revision)?;
        // Publication has committed. Failed cleanup must not roll it back.
        if let Err(error) = super::rule_plans::events::compact(&self.target_root, &state) {
            tracing::warn!(%error, "could not compact incorporated rule plans");
        }
        Ok(())
    }

    fn snapshot_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.snapshots.snapshot_bytes()
    }

    fn write_snapshot(&self, payload: &[u8], revision: u64) -> Result<()> {
        self.snapshots.write_snapshot(payload, revision)
    }

    pub(super) fn try_lock(&self) -> Result<Option<RewriteLock>> {
        if super::execution::owned_by_other_process(&self.target_root)? {
            return Ok(None);
        }
        self.snapshots.try_lock()
    }

    pub(super) fn lock(&self) -> Result<RewriteLock> {
        self.try_lock()?.context(
            "rewrite workflow is already being advanced; inspect `backend-rewrite status` and wait when it returns `wait_required`",
        )
    }

    pub(super) fn lock_state(&self) -> Result<RewriteLockState> {
        self.snapshots.lock_state()
    }

    pub(super) fn owns_lock(&self) -> Result<bool> {
        self.snapshots.owns_lock()
    }

    pub(super) fn recover_lock(&self) -> Result<bool> {
        self.snapshots.recover_lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    const INCOMPLETE_LOCK_GRACE: Duration = Duration::from_secs(2);
    use crate::test_state;

    #[test]
    fn state_is_atomically_replaced_and_lock_is_exclusive() {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::internal_runtime::root(target.path())).unwrap();
        let store = RewriteStore::new(target.path()).unwrap();
        let mut state = test_state();
        store.save(&state).unwrap();
        state.bump();
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().unwrap().revision, 2);

        let lock = store.lock().unwrap();
        assert_eq!(store.lock_state().unwrap(), RewriteLockState::Live);
        assert!(store.try_lock().unwrap().is_none());
        assert!(store.lock().is_err());
        drop(lock);
        assert_eq!(store.lock_state().unwrap(), RewriteLockState::Absent);
        assert!(store.try_lock().unwrap().is_some());
    }

    #[test]
    fn loading_discards_retired_capture_plans_from_active_and_parked_apis() {
        let target = tempfile::tempdir().unwrap();
        let store = RewriteStore::new(target.path()).unwrap();
        let mut state = test_state();
        state.recorder_capture_plan = Some(crate::model::RewriteRecorderCapturePlanRecord {
            http_response: None,
            id: "capture-plan".into(),
            issue_id: "issue-1".into(),
            evidence_id: "evidence-1".into(),
            endpoint: "cache.example.test".into(),
            source_evidence: "CacheClient.java:42".into(),
            source_revision: "source-1".into(),
            project_config_revision: "config-1".into(),
            resource_identity: "cache".into(),
            target_fingerprint: "target-1".into(),
        });
        state
            .parked_slices
            .insert("GET /parked".into(), state.active_slice.clone());
        store.save(&state).unwrap();

        let loaded = store.load_snapshot().unwrap().unwrap();
        assert!(loaded.recorder_capture_plan.is_none());
        assert!(
            loaded.parked_slices["GET /parked"]
                .recorder_capture_plan
                .is_none()
        );
    }

    #[test]
    fn recover_removes_an_incomplete_lock_without_exposing_it_to_callers() {
        let target = tempfile::tempdir().unwrap();
        let store = RewriteStore::new(target.path()).unwrap();
        fs::create_dir_all(store.snapshots.root()).unwrap();
        fs::write(store.snapshots.root().join("lock"), []).unwrap();

        assert!(store.recover_lock().is_err());
        let lock_file = File::options()
            .write(true)
            .open(store.snapshots.root().join("lock"))
            .unwrap();
        lock_file
            .set_times(
                std::fs::FileTimes::new().set_modified(
                    SystemTime::now() - INCOMPLETE_LOCK_GRACE - Duration::from_secs(1),
                ),
            )
            .unwrap();

        assert_eq!(store.lock_state().unwrap(), RewriteLockState::Stale);
        assert!(store.recover_lock().unwrap());
        assert!(store.try_lock().unwrap().is_some());
    }
}
