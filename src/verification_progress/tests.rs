use tempfile::tempdir;

use super::*;

fn observation(key: &str, apis: &[(&str, u64, u64)]) -> ProgressObservation {
    ProgressObservation {
        key: key.to_string(),
        evidence_fingerprint: format!("fingerprint-{key}"),
        finished_at: format!("2026-07-31T00:00:0{}Z", key.len()),
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
    assert_eq!(baseline.latest_run.as_ref().unwrap().key, "1");
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
fn changed_global_scope_starts_a_new_streak() {
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

    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 200);
    assert_eq!(report.apis["GET /users"].success_streak.runs, 2);
}

#[test]
fn retrying_one_logical_run_revises_coverage_without_extending_the_streak() {
    let mut report = ProgressReport::new(VerificationStage::Replay);
    report
        .apply(observation("previous", &[("GET /users", 1_000, 1_000)]))
        .unwrap();
    report
        .upsert_logical_run(observation("current", &[("GET /users", 10, 9)]), "current|")
        .unwrap();

    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.cases.executed, 1_010);
    assert_eq!(report.success_streak, SuccessStreak::default());

    let mut passing = observation("current", &[("GET /users", 10, 10)]);
    passing.evidence_fingerprint = "current-passing".to_string();
    report.upsert_logical_run(passing, "current|").unwrap();

    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.runs.passed, 2);
    assert_eq!(report.totals.cases.executed, 1_010);
    assert_eq!(report.totals.cases.passed, 1_010);
    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 10);

    let mut repeated = observation("current", &[("GET /users", 10, 10)]);
    repeated.evidence_fingerprint = "current-passing-again".to_string();
    report.upsert_logical_run(repeated, "current|").unwrap();

    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.cases.executed, 1_010);
    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 10);
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
    assert_eq!(report.success_streak.runs, 2);
    assert_eq!(report.success_streak.cases, 200);
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
fn round_trips_the_same_schema_for_both_stages() {
    let directory = tempdir().unwrap();
    for (name, stage) in [
        ("replay-progress.yaml", VerificationStage::Replay),
        ("comparison-progress.yaml", VerificationStage::Comparison),
    ] {
        let path = directory.path().join(name);
        let mut report = ProgressReport::new(stage);
        report
            .apply(observation("1", &[("GET /users", 100, 100)]))
            .unwrap();
        write(&path, &report).unwrap();
        let public_payload = std::fs::read_to_string(&path).unwrap();
        assert!(!public_payload.contains("counted_runs:"));
        let ledger_path = ledger::path(&path, stage).unwrap();
        let ledger_payload = std::fs::read_to_string(ledger_path).unwrap();
        assert!(ledger_payload.contains("counted_runs:"));
        assert!(ledger_payload.contains("fingerprint-1"));
        let loaded = load(&path, stage).unwrap().unwrap();
        assert_eq!(loaded.stage, stage);
        assert_eq!(loaded.success_streak.cases, 100);
        assert!(!loaded.requires_persistence());
        assert_eq!(
            loaded.counted_runs.get("1").map(String::as_str),
            Some("fingerprint-1")
        );
        assert_eq!(loaded.counted_observations.len(), 1);
    }
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
    assert!(public_payload.starts_with("version: 2\n"));
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
