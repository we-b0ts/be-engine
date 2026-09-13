use tempfile::tempdir;

use super::*;

fn observation(key: &str, apis: &[(&str, u64, u64)]) -> ProgressObservation {
    ProgressObservation {
        key: key.to_string(),
        evidence_fingerprint: format!("fingerprint-{key}"),
        finished_at: format!("2026-07-31T00:00:0{}Z", key.len()),
        finalized: true,
        passed: None,
        success_streak: None,
        apis: apis
            .iter()
            .map(|(api, executed, passed)| {
                (
                    (*api).to_string(),
                    ApiObservation {
                        cases: LatestCounts {
                            executed: *executed,
                            passed: *passed,
                        },
                        finalized: true,
                        passed: executed == passed,
                        success_streak: None,
                    },
                )
            })
            .collect(),
    }
}

#[test]
fn authoritative_ledger_rebuilds_a_reset_public_snapshot() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("replay-progress.yaml");
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation("1", &[("GET /users", 10, 10)]))
        .unwrap();
    write(&path, &report).unwrap();
    let reset_snapshot = fs::read(&path).unwrap();

    report
        .apply(observation("2", &[("GET /users", 10, 9)]))
        .unwrap();
    write(&path, &report).unwrap();
    write_payload(&path, &reset_snapshot).unwrap();

    let rebuilt = load(&path, VerificationStage::Replay).unwrap().unwrap();
    assert_eq!(rebuilt.totals.runs.executed, 2);
    assert_eq!(rebuilt.totals.cases.executed, 20);
    assert_eq!(rebuilt.latest_run.as_ref().unwrap().key, "2");
    assert!(rebuilt.requires_persistence());
    assert!(synchronize(&path, VerificationStage::Replay).unwrap());
    assert!(
        !load(&path, VerificationStage::Replay)
            .unwrap()
            .unwrap()
            .requires_persistence()
    );
}

#[test]
fn public_snapshot_initializes_a_missing_local_ledger_baseline() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("comparison-progress.yaml");
    let mut report = ProgressReport::new(VerificationStage::Comparison);
    report
        .apply(observation("1", &[("POST /orders", 8, 8)]))
        .unwrap();
    write(&path, &report).unwrap();
    fs::remove_file(ledger::path(&path, VerificationStage::Comparison).unwrap()).unwrap();

    let imported = load(&path, VerificationStage::Comparison).unwrap().unwrap();
    let baseline = imported.observation_baseline.as_ref().unwrap();
    assert_eq!(baseline.number, 1);
    assert_eq!(baseline.totals.runs.executed, 1);
    assert_eq!(baseline.totals.runs.passed, 1);
    assert_eq!(baseline.totals.cases.executed, 8);
    assert_eq!(baseline.success_streak.runs, 1);
    assert!(
        baseline
            .latest_run
            .as_ref()
            .unwrap()
            .key
            .starts_with("public-v3:")
    );
    assert_eq!(baseline.apis["POST /orders"].totals.runs.executed, 1);
    assert_eq!(baseline.apis["POST /orders"].success_streak.cases, 8);
    assert!(imported.requires_persistence());
    assert!(synchronize(&path, VerificationStage::Comparison).unwrap());
    assert!(
        ledger::path(&path, VerificationStage::Comparison)
            .unwrap()
            .is_file()
    );
}

#[test]
fn local_ledger_recreates_a_missing_public_snapshot() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("replay-progress.yaml");
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation("1", &[("GET /users", 4, 4)]))
        .unwrap();
    report
        .apply(observation("2", &[("GET /users", 4, 4)]))
        .unwrap();
    write(&path, &report).unwrap();
    fs::remove_file(&path).unwrap();

    let rebuilt = load(&path, VerificationStage::Replay).unwrap().unwrap();
    assert_eq!(rebuilt.totals.runs.executed, 2);
    assert_eq!(rebuilt.success_streak.runs, 2);
    assert!(rebuilt.requires_persistence());
    assert!(synchronize(&path, VerificationStage::Replay).unwrap());
    assert!(path.is_file());
}

#[test]
fn tracks_totals_and_resets_global_and_api_streaks_on_failure() {
    let mut report = ProgressReport::new(VerificationStage::Comparison);
    report
        .apply(observation("1", &[("GET /users", 100, 100)]))
        .unwrap();
    report
        .apply(observation("2", &[("GET /users", 100, 100)]))
        .unwrap();

    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.runs.passed, 2);
    assert_eq!(report.success_streak.runs, 2);
    assert_eq!(report.success_streak.cases, 200);
    assert_eq!(report.apis["GET /users"].success_streak.runs, 2);

    report
        .apply(observation("3", &[("GET /users", 100, 99)]))
        .unwrap();

    assert_eq!(report.totals.runs.executed, 3);
    assert_eq!(report.totals.cases.passed, 299);
    assert_eq!(report.success_streak.runs, 0);
    assert_eq!(report.success_streak.cases, 0);
    assert_eq!(report.apis["GET /users"].success_streak.runs, 0);
}

#[test]
fn one_failed_api_resets_global_streak_without_resetting_other_api() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation(
            "1",
            &[("GET /users", 50, 50), ("GET /friends", 50, 50)],
        ))
        .unwrap();
    report
        .apply(observation(
            "2",
            &[("GET /users", 50, 50), ("GET /friends", 50, 49)],
        ))
        .unwrap();

    assert_eq!(report.success_streak.runs, 0);
    assert_eq!(report.apis["GET /users"].success_streak.runs, 2);
    assert_eq!(report.apis["GET /friends"].success_streak.runs, 0);
}

#[test]
fn changed_global_scope_preserves_the_business_success_streak() {
    let mut report = ProgressReport::new(VerificationStage::Comparison);
    report
        .apply(observation("1", &[("GET /users", 100, 100)]))
        .unwrap();
    report
        .apply(observation(
            "2",
            &[("GET /users", 100, 100), ("GET /friends", 100, 100)],
        ))
        .unwrap();

    assert_eq!(report.success_streak.runs, 2);
    assert_eq!(report.success_streak.cases, 300);
    assert_eq!(report.apis["GET /users"].success_streak.runs, 2);
}

#[test]
fn retrying_one_logical_run_revises_coverage_without_extending_the_streak() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation("previous", &[("GET /users", 1_000, 1_000)]))
        .unwrap();
    report
        .upsert_logical_run(
            observation("current", &[("GET /users", 10, 9)]),
            Some("current|"),
        )
        .unwrap();

    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.cases.executed, 1_010);
    assert_eq!(report.success_streak, SuccessStreak::default());

    let mut passing = observation("current", &[("GET /users", 10, 10)]);
    passing.evidence_fingerprint = "current-passing".to_string();
    report
        .upsert_logical_run(passing, Some("current|"))
        .unwrap();

    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.runs.passed, 2);
    assert_eq!(report.totals.cases.executed, 1_010);
    assert_eq!(report.totals.cases.passed, 1_010);
    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 10);

    let mut repeated = observation("current", &[("GET /users", 10, 10)]);
    repeated.evidence_fingerprint = "current-passing-again".to_string();
    report
        .upsert_logical_run(repeated, Some("current|"))
        .unwrap();

    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.cases.executed, 1_010);
    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 10);
}

#[test]
fn unfinished_logical_run_adds_new_api_coverage_without_changing_existing_cases() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    let mut first = observation("current", &[("GET /apps", 4, 4)]);
    first.finalized = false;
    report.upsert_logical_run(first, None).unwrap();

    let mut second = observation("current", &[("GET /attachments/*", 1, 1)]);
    second.evidence_fingerprint = "current-attachments".to_string();
    second.finalized = false;
    report.upsert_logical_run(second, None).unwrap();

    let current = &report.counted_observations["current"].observation;
    assert!(!current.finalized);
    assert_eq!(current.apis.len(), 2);
    assert_eq!(current.apis["GET /apps"].cases.executed, 4);
    assert_eq!(current.apis["GET /attachments/*"].cases.executed, 1);
}

#[test]
fn unfinished_logical_run_rejects_changed_case_count_for_existing_api() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    let mut first = observation("current", &[("GET /apps", 4, 4)]);
    first.finalized = false;
    report.upsert_logical_run(first, None).unwrap();

    let mut changed = observation("current", &[("GET /apps", 5, 5)]);
    changed.evidence_fingerprint = "current-changed".to_string();
    changed.finalized = false;
    assert!(report.upsert_logical_run(changed, None).is_err());

    let current = &report.counted_observations["current"].observation;
    assert_eq!(current.apis.len(), 1);
    assert_eq!(current.apis["GET /apps"].cases.executed, 4);
}

#[test]
fn recording_completion_counts_coverage_and_holds_streaks_until_the_result_is_final() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("progress.yaml");
    let mut report = ProgressReport::new(VerificationStage::Progress);
    report
        .apply(observation(
            "previous",
            &[("GET /users", 1_000, 1_000), ("GET /orders", 2, 2)],
        ))
        .unwrap();
    write(&path, &report).unwrap();

    record_completed_batch(
        &path,
        "current",
        "2026-08-15T00:00:00Z".to_string(),
        BTreeMap::from([("GET /users".to_string(), 10)]),
    )
    .unwrap();
    let pending = load(&path, VerificationStage::Progress).unwrap().unwrap();
    assert_eq!(pending.totals.runs.executed, 2);
    assert_eq!(pending.totals.runs.passed, 1);
    assert_eq!(pending.totals.cases.executed, 1_012);
    assert_eq!(pending.totals.cases.passed, 1_002);
    assert_eq!(pending.success_streak, SuccessStreak::default());
    assert_eq!(pending.apis["GET /users"].success_streak.runs, 0);
    assert_eq!(pending.apis["GET /orders"].success_streak.runs, 1);
    assert!(!pending.latest_run.as_ref().unwrap().finalized);
    let public: serde_yaml::Value = serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(public["latest_run"]["passed"].is_null());
    assert_eq!(public["totals"]["runs"]["executed"], 2);
    assert_eq!(public["totals"]["runs"]["passed"], 1);
    assert_eq!(public["totals"]["runs"]["success_streak"], 0);

    let mut failed = observation("current", &[("GET /users", 10, 9)]);
    failed.evidence_fingerprint = "current-failed".to_string();
    let mut report = pending;
    report.upsert_logical_run(failed, Some("current|")).unwrap();
    write(&path, &report).unwrap();

    let mut passing = observation("current", &[("GET /users", 10, 10)]);
    passing.evidence_fingerprint = "current-passing".to_string();
    report
        .upsert_logical_run(passing, Some("current|"))
        .unwrap();
    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.runs.passed, 2);
    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 10);
    assert_eq!(report.apis["GET /users"].success_streak.runs, 1);
    assert_eq!(report.apis["GET /orders"].success_streak.runs, 1);
}

#[test]
fn duplicate_evidence_is_idempotent_and_conflicting_evidence_is_rejected() {
    let mut report = ProgressReport::new(VerificationStage::Comparison);
    let first = observation("1", &[("GET /users", 100, 100)]);
    assert!(report.apply(first.clone()).unwrap());
    assert!(
        report
            .apply(observation("2", &[("GET /users", 100, 100)]))
            .unwrap()
    );
    assert!(!report.apply(first).unwrap());

    let mut conflicting = observation("1", &[("GET /users", 100, 100)]);
    conflicting.evidence_fingerprint = "other".to_string();
    assert!(report.apply(conflicting).is_err());
    assert_eq!(report.totals.runs.executed, 2);
}

#[test]
fn revises_latest_focused_observation_without_counting_a_new_run() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation("1", &[("GET /users", 100, 100)]))
        .unwrap();
    let previous = observation("2", &[("GET /users", 100, 98)]);
    report.apply(previous.clone()).unwrap();
    let mut revised = observation("2", &[("GET /users", 100, 100)]);
    revised.evidence_fingerprint = "reclassified-fingerprint-2".to_string();

    assert!(report.revise(previous, revised).unwrap());

    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.runs.passed, 2);
    assert_eq!(report.totals.cases.executed, 200);
    assert_eq!(report.totals.cases.passed, 200);
    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 100);
    assert_eq!(report.apis["GET /users"].totals.runs.executed, 2);
    assert_eq!(report.apis["GET /users"].totals.runs.passed, 2);
    assert_eq!(
        report.latest_run.as_ref().unwrap().evidence_fingerprint,
        "reclassified-fingerprint-2"
    );
}

#[test]
fn revises_a_non_latest_progress_run_and_rebuilds_aggregates() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    let previous = observation("1", &[("GET /users", 1, 0)]);
    report.apply(previous.clone()).unwrap();
    report
        .apply(observation("2", &[("GET /friends", 1, 1)]))
        .unwrap();
    let mut revised = observation("1", &[("GET /users", 1, 1)]);
    revised.evidence_fingerprint = "reclassified-fingerprint-1".to_string();

    assert!(report.revise(previous, revised).unwrap());
    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.runs.passed, 2);
    assert_eq!(report.apis["GET /users"].totals.runs.passed, 1);
    assert_eq!(report.apis["GET /users"].success_streak.runs, 1);
    assert_eq!(report.latest_run.as_ref().unwrap().key, "2");
}

#[test]
fn revises_a_journaled_run_after_a_legacy_progress_baseline() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation("legacy-1", &[("GET /users", 1, 1)]))
        .unwrap();
    report.counted_observations.clear();

    let previous = observation("new-1", &[("GET /users", 1, 0)]);
    report.apply(previous.clone()).unwrap();
    report
        .apply(observation("new-2", &[("GET /friends", 1, 1)]))
        .unwrap();
    let mut revised = observation("new-1", &[("GET /users", 1, 1)]);
    revised.evidence_fingerprint = "reclassified-new-1".to_string();

    assert!(report.revise(previous, revised).unwrap());
    assert_eq!(report.totals.runs.executed, 3);
    assert_eq!(report.totals.runs.passed, 3);
    assert_eq!(report.latest_run.as_ref().unwrap().key, "new-2");
}

#[test]
fn rejects_an_unjournaled_historical_revision_before_mutating_progress() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation("legacy-1", &[("GET /users", 1, 0)]))
        .unwrap();
    report
        .apply(observation("legacy-2", &[("GET /friends", 1, 1)]))
        .unwrap();
    report.counted_observations.clear();
    let before = report.counted_runs.clone();

    let error = report.ensure_revisable("legacy-1").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("observation ledger is incomplete")
    );
    assert_eq!(report.counted_runs, before);
}

#[test]
fn rejects_new_runs_when_the_idempotency_ledger_is_full() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report.counted_runs = (0..MAX_COUNTED_RUNS)
        .map(|index| (format!("run-{index}"), format!("evidence-{index}")))
        .collect();

    let error = report
        .apply(observation("new", &[("GET /users", 1, 1)]))
        .unwrap_err();

    assert!(error.to_string().contains("counted-run limit"));
    assert_eq!(report.totals.runs.executed, 0);
}

#[test]
fn round_trips_the_unified_public_schema_and_local_ledger() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("progress.yaml");
    let mut report = ProgressReport::new(VerificationStage::Progress);
    report
        .apply(observation("1", &[("GET /users", 100, 100)]))
        .unwrap();
    write(&path, &report).unwrap();

    let public_payload = std::fs::read_to_string(&path).unwrap();
    let public: serde_yaml::Value = serde_yaml::from_str(&public_payload).unwrap();
    assert!(public_payload.contains("success_streak: 1"));
    assert!(public_payload.contains("covered: 1"));
    assert!(!public_payload.contains("stage:"));
    assert!(!public_payload.contains("counted_runs:"));
    assert_eq!(public["totals"]["runs"]["success_streak"], 1);
    assert_eq!(public["totals"]["cases"]["success_streak"], 100);
    assert_eq!(public["totals"]["apis"]["covered"], 1);
    assert_eq!(public["latest_run"]["passed"], true);
    assert_eq!(public["apis"]["GET /users"]["runs"]["executed"], 1);
    let ledger_path = ledger::path(&path, VerificationStage::Progress).unwrap();
    let ledger_payload = std::fs::read_to_string(ledger_path).unwrap();
    assert!(ledger_payload.contains("counted_runs:"));
    assert!(ledger_payload.contains("fingerprint-1"));
    let loaded = load(&path, VerificationStage::Progress).unwrap().unwrap();
    assert_eq!(loaded.stage, VerificationStage::Progress);
    assert_eq!(loaded.success_streak.cases, 100);
    assert!(!loaded.requires_persistence());
    assert_eq!(
        loaded.counted_runs.get("1").map(String::as_str),
        Some("fingerprint-1")
    );
    assert_eq!(loaded.counted_observations.len(), 1);
}

#[test]
fn migrates_only_recording_coverage_from_the_split_replay_ledger() {
    let directory = tempdir().unwrap();
    let replay_path = directory.path().join("replay-progress.yaml");
    let comparison_path = directory.path().join("comparison-progress.yaml");
    let progress_path = directory.path().join("progress.yaml");
    let mut replay = ProgressReport::new(VerificationStage::Replay);
    replay
        .apply(observation("replay", &[("GET /users", 10, 10)]))
        .unwrap();
    write(&replay_path, &replay).unwrap();
    let mut comparison = ProgressReport::new(VerificationStage::Comparison);
    comparison
        .apply(observation("comparison", &[("GET /users", 5, 4)]))
        .unwrap();
    write(&comparison_path, &comparison).unwrap();

    let migrated = load(&progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    assert!(migrated.requires_persistence());
    assert_eq!(migrated.totals.runs.executed, 1);
    assert_eq!(migrated.totals.runs.passed, 1);
    assert_eq!(migrated.totals.cases.executed, 10);
    assert_eq!(migrated.totals.cases.passed, 10);
    write(&progress_path, &migrated).unwrap();

    assert!(progress_path.is_file());
    assert!(!replay_path.exists());
    assert!(!comparison_path.exists());
    assert!(
        ledger::path(&progress_path, VerificationStage::Progress)
            .unwrap()
            .is_file()
    );
}

#[test]
fn loading_an_older_report_seeds_the_latest_run_in_the_ledger() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("replay-progress.yaml");
    let mut report = ProgressReport::new(VerificationStage::Replay);
    let first = observation("1", &[("GET /users", 100, 100)]);
    report.apply(first.clone()).unwrap();
    let payload = serde_yaml::to_string(&report).unwrap();
    std::fs::write(&path, payload).unwrap();

    let mut loaded = load(&path, VerificationStage::Replay).unwrap().unwrap();

    assert!(loaded.requires_persistence());
    assert!(!loaded.apply(first).unwrap());
    assert_eq!(loaded.totals.runs.executed, 1);
    write(&path, &loaded).unwrap();
    assert!(
        ledger::path(&path, VerificationStage::Replay)
            .unwrap()
            .is_file()
    );
}

#[test]
fn migrates_embedded_counted_runs_to_the_artifact_ledger() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("comparison-progress.yaml");
    let mut report = ProgressReport::new(VerificationStage::Comparison);
    let first = observation("1", &[("GET /users", 100, 100)]);
    report.apply(first.clone()).unwrap();
    let mut legacy_payload =
        serde_yaml::to_string(&report)
            .unwrap()
            .replacen("version: 2", "version: 1", 1);
    legacy_payload.push_str("counted_runs:\n  '1': fingerprint-1\n");
    std::fs::write(&path, legacy_payload).unwrap();

    let mut loaded = load(&path, VerificationStage::Comparison).unwrap().unwrap();

    assert!(loaded.requires_persistence());
    assert!(!loaded.apply(first).unwrap());
    write(&path, &loaded).unwrap();
    let public_payload = std::fs::read_to_string(&path).unwrap();
    assert!(public_payload.starts_with("version: 3\n"));
    assert!(!public_payload.contains("counted_runs:"));
    let ledger_path = ledger::path(&path, VerificationStage::Comparison).unwrap();
    assert!(
        std::fs::read_to_string(ledger_path)
            .unwrap()
            .contains("fingerprint-1")
    );
}

#[test]
fn persists_a_legacy_baseline_and_revises_a_later_historical_run_after_reload() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("replay-progress.yaml");
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation("legacy", &[("GET /legacy", 1, 1)]))
        .unwrap();
    report.counted_observations.clear();
    let previous = observation("new-1", &[("GET /users", 1, 0)]);
    report.apply(previous.clone()).unwrap();
    report
        .apply(observation("new-2", &[("GET /friends", 1, 1)]))
        .unwrap();
    write(&path, &report).unwrap();

    let mut loaded = load(&path, VerificationStage::Replay).unwrap().unwrap();
    let mut revised = observation("new-1", &[("GET /users", 1, 1)]);
    revised.evidence_fingerprint = "reclassified-new-1".to_string();

    assert!(loaded.revise(previous, revised).unwrap());
    assert_eq!(loaded.totals.runs.executed, 3);
    assert_eq!(loaded.totals.runs.passed, 3);
    assert_eq!(loaded.latest_run.as_ref().unwrap().key, "new-2");
}
