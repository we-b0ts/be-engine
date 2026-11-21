use super::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone)]
struct Data;

impl WorkflowData for Data {
    type AttemptSummary = Summary;
    type Issue = String;
    type RulePlan = String;
    type DependencyRulePlan = String;
    type RecorderCapturePlan = String;
    type Route = String;
    type ReviewLedger = ();
    type Regression = ();
    type RevalidationRound = ();
    type AcceptedReview = ();
    type WorkerBinding = ();
    type ImplementerPool = ();
    type RepositoryAnalysis = ();
    type GroupReplayRound = ();
    type GroupReplaySummary = ();
    type ReviewRework = ();
    type CasePatternAnalysis = ();
    type RecordingSettings = ();
    type RecordingReason = ();
    type RecordingInputDiagnosis = ();
    type RecordingRefresh = ();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Summary {
    sequence: u64,
    selected: usize,
    passed: usize,
}

impl Attempt for Summary {
    fn attempt(&self) -> u64 {
        self.sequence
    }
    fn counts(&self) -> AttemptCounts {
        AttemptCounts {
            selected: self.selected,
            response_passed: self.passed,
            response_nonpassing: self.selected - self.passed,
        }
    }
}

fn state() -> RewriteState<Data> {
    serde_json::from_value(json!({
        "version":2, "revision":1, "workflow_id":"workflow",
        "dependency_review":null, "recording_run_id":"recording",
        "phase":"api_pending", "api":"GET /api", "source_route":"/api",
        "attempts":[], "e2e_current":false,
    }))
    .unwrap()
}

fn update(sequence: u64, passed: usize) -> ExecutionUpdate<Data> {
    ExecutionUpdate {
        summary: Summary {
            sequence,
            selected: 2,
            passed,
        },
        passed: passed == 2,
        target_fingerprint: "target".into(),
        replay_identity: "inputs".into(),
        issue: (passed != 2).then(|| "failed response".into()),
    }
}

#[test]
fn transitions_reset_consumed_plans_and_compare_actual_attempts() {
    let mut state = state();
    state
        .begin_execution(1)
        .unwrap()
        .apply(update(1, 0))
        .unwrap();
    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
    assert!(state.active_issue.is_some());
    state.rule_plan = Some("pending".into());
    state.dependency_rule_plan = Some("pending".into());
    state.recorder_capture_plan = Some("pending".into());
    state.route = Some("pending".into());
    state.engine_retry_running = true;
    state.rule_replay_pending = true;
    state.system_repair_accepted = true;
    state
        .begin_execution(2)
        .unwrap()
        .apply(update(2, 2))
        .unwrap();
    assert_eq!(state.phase, RewritePhase::SliceComplete);
    assert!(state.e2e_current);
    assert!(state.active_issue.is_none());
    assert!(state.rule_plan.is_none());
    assert!(state.dependency_rule_plan.is_none());
    assert!(state.recorder_capture_plan.is_none());
    assert!(state.route.is_none());
    assert!(!state.engine_retry_running);
    assert!(!state.rule_replay_pending);
    assert!(!state.system_repair_accepted);
    let delta = state.attempt_delta.as_ref().unwrap();
    assert!(delta.improved);
    assert!(!delta.regressed);
    assert_eq!(delta.response_passed_delta, 2);
    assert_eq!(delta.response_nonpassing_delta, -2);
    assert_eq!(state.revision, 1);
}

#[test]
fn rejected_transitions_leave_the_snapshot_unchanged() {
    let mut state = state();
    state
        .begin_execution(4)
        .unwrap()
        .apply(update(4, 0))
        .unwrap();
    let original = serde_json::to_vec(&state).unwrap();
    assert!(state.begin_execution(4).is_err());
    assert!(state.begin_execution(3).is_err());
    assert!(
        state
            .begin_execution(5)
            .unwrap()
            .apply(update(6, 2))
            .is_err()
    );
    let mut inconsistent = update(5, 2);
    inconsistent.issue = Some("contradicts result".into());
    assert!(
        state
            .begin_execution(5)
            .unwrap()
            .apply(inconsistent)
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), original);
}

#[test]
fn atomic_storage_retains_previous_bytes_when_reservation_fails() {
    let directory = tempfile::tempdir().unwrap();
    let store = SnapshotStore::new(directory.path().to_path_buf());
    assert!(!store.exists());
    assert!(store.snapshot_bytes().unwrap().is_none());
    store.write_snapshot(b"original\n", 1).unwrap();
    let temporary = store
        .root()
        .join(format!(".state.json.tmp.{}.2", std::process::id()));
    std::fs::write(&temporary, b"another writer").unwrap();
    assert!(store.write_snapshot(b"replacement", 2).is_err());
    assert_eq!(store.snapshot_bytes().unwrap().unwrap(), b"original\n");
    std::fs::remove_file(temporary).unwrap();
    store.write_snapshot(b"replacement", 2).unwrap();
    assert_eq!(store.snapshot_bytes().unwrap().unwrap(), b"replacement");
}

#[test]
fn workflow_lock_excludes_a_second_owner_and_recovers_dead_processes() {
    let directory = tempfile::tempdir().unwrap();
    let store = SnapshotStore::new(directory.path().to_path_buf());
    assert_eq!(store.lock_state().unwrap(), WorkflowLockState::Absent);
    let lock = store.lock().unwrap();
    assert!(store.owns_lock().unwrap());
    assert_eq!(store.lock_state().unwrap(), WorkflowLockState::Live);
    assert!(store.try_lock().unwrap().is_none());
    assert!(store.recover_lock().is_err());
    drop(lock);
    assert_eq!(store.lock_state().unwrap(), WorkflowLockState::Absent);
    std::fs::write(store.root().join("lock"), u32::MAX.to_string()).unwrap();
    assert_eq!(store.lock_state().unwrap(), WorkflowLockState::Stale);
    assert!(store.recover_lock().unwrap());
    assert!(store.try_lock().unwrap().is_some());
}
