use super::*;
use crate::E2eEventSessionProgress;

#[test]
fn status_tracks_the_registered_attempt_and_selects_history() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let target = temp.path().canonicalize()?;
    let recording = target.join("recording");
    let other_recording = target.join("another-recording");
    fs::create_dir(&recording)?;
    fs::create_dir(&other_recording)?;
    let runtime = crate::internal_runtime::root(&target);
    let run_key = "custom";
    let attempts = attempts_root(&runtime.join(run_key), &recording);
    let status = |id| status_e2e_event_session(&target, &recording, Some(run_key), id);
    assert_eq!(status(None)?.state, E2eEventSessionState::NotStarted);
    assert_eq!(status(None)?.previous_events, None);
    assert!(!runtime.exists());

    let first = Uuid::new_v4();
    let first_dir = attempts.join(first.simple().to_string());
    fs::create_dir_all(&first_dir)?;
    let mut result = E2eEventSessionResult {
        target_commit: None,
        target_inputs: None,
        engine_revision: None,
        target_image_id: None,
        run_key: run_key.into(),
        attempt_id: first.simple().to_string(),
        recording_root: recording.clone(),
        passed: false,
        events: Default::default(),
        phase: E2eEventSessionPhase::PreparingReplay,
        apis: Default::default(),
        cases: Default::default(),
        error: None,
        progress: first_dir.join(PROGRESS),
        report: first_dir.join(".active/reports/replay.json"),
    };
    let running = begin(&attempts, first, &result)?;
    let progress = status(None)?.progress.unwrap();
    assert_eq!(progress.phase, E2eEventSessionPhase::PreparingReplay);
    assert_eq!(progress.events.total, None);
    assert_eq!(progress.apis.total, None);
    assert_eq!(progress.cases.total, None);

    result.events = E2eEventSessionProgress {
        matched: 2,
        total: Some(3),
        last_sequence: Some(5),
        ..Default::default()
    };
    result.phase = E2eEventSessionPhase::Replaying;
    result.apis = E2eEventSessionApiProgress {
        verified: 1,
        total: Some(2),
    };
    result.cases = E2eEventSessionCaseProgress {
        completed: 3,
        total: Some(10),
    };
    publish_progress(&result)?;
    let current = status(None)?;
    assert_eq!(current.state, E2eEventSessionState::Running);
    let progress = current.progress.unwrap();
    assert_eq!(progress.phase, E2eEventSessionPhase::Replaying);
    assert_eq!(
        progress.events,
        E2eEventSessionCounts {
            matched: 2,
            total: Some(3)
        }
    );
    assert_eq!(progress.apis, result.apis);
    assert_eq!(progress.cases, result.cases);
    assert_eq!(current.attempt.unwrap().events.last_sequence, Some(5));
    assert_eq!(
        status_e2e_event_session(&target, &other_recording, Some(run_key), None)?.state,
        E2eEventSessionState::NotStarted
    );

    result.error = Some("Target request differed".into());
    finish(&first_dir, &result)?;
    assert_eq!(status(None)?.state, E2eEventSessionState::Failed);
    drop(running);
    assert_eq!(status(None)?.attempt.unwrap().engine_revision, None);
    store::write_yaml(
        &first_dir.join(".active/state.yaml"),
        &serde_json::json!({
            "engine_fingerprint": "engine-revision-v1:legacy",
            "run_key": run_key,
            "case_source": &recording,
        }),
    )?;
    assert_eq!(
        status(None)?.attempt.unwrap().engine_revision.as_deref(),
        Some("engine-revision-v1:legacy")
    );

    // A pre-upgrade attempt can still supply the next attempt's baseline.
    store::write_json(&attempts.join(LATEST_ATTEMPT), &first)?;
    assert_eq!(status(None)?.previous_events, None);

    let first_report = result.report.clone();
    fs::create_dir_all(first_report.parent().unwrap())?;
    fs::write(&first_report, b"{}")?;

    let second = Uuid::new_v4();
    let second_dir = attempts.join(second.simple().to_string());
    fs::create_dir(&second_dir)?;
    result.attempt_id = second.simple().to_string();
    result.progress = second_dir.join(PROGRESS);
    result.report = second_dir.join(".active/reports/replay.json");
    result.error = None;
    result.events = Default::default();
    result.phase = E2eEventSessionPhase::PreparingReplay;
    result.apis = Default::default();
    result.cases = Default::default();
    let running = begin(&attempts, second, &result)?;
    let current = status(None)?;
    assert_eq!(current.state, E2eEventSessionState::Running);
    assert_eq!(current.attempt.unwrap().events.last_sequence, None);
    assert_eq!(
        current.previous_events,
        Some(E2eEventSessionSequenceProgress {
            last_sequence: Some(5),
            complete: false,
        })
    );
    assert_eq!(status(Some(first))?.state, E2eEventSessionState::Failed);
    assert_eq!(status(Some(first))?.previous_events, None);
    let first_evidence = || event_session_report(&target, &recording, run_key, first);
    assert_eq!(first_evidence()?, first_report);
    assert!(event_session_report(&target, &other_recording, run_key, first).is_err());
    assert!(event_session_report(&target, &recording, run_key, second).is_err());
    let outside = target.join("other-report.json");
    fs::write(&outside, b"{}")?;
    fs::remove_file(&first_report)?;
    std::os::unix::fs::symlink(outside, &first_report)?;
    assert!(first_evidence().is_err());

    result.events.last_sequence = Some(7);
    publish_progress(&result)?;
    let inherited = running.0.try_clone()?;
    drop(running);
    assert_eq!(status(None)?.state, E2eEventSessionState::Interrupted);
    drop(inherited);

    let third = Uuid::new_v4();
    let third_dir = attempts.join(third.simple().to_string());
    fs::create_dir(&third_dir)?;
    result.attempt_id = third.simple().to_string();
    result.progress = third_dir.join(PROGRESS);
    result.report = third_dir.join(".active/reports/replay.json");
    result.events = Default::default();
    let running = begin(&attempts, third, &result)?;
    assert_eq!(
        status(None)?.previous_events,
        Some(E2eEventSessionSequenceProgress {
            last_sequence: Some(7),
            complete: false,
        })
    );
    result.events = E2eEventSessionProgress {
        matched: 3,
        total: Some(3),
        last_sequence: Some(8),
        complete: true,
        ..Default::default()
    };
    result.passed = true;
    result.phase = E2eEventSessionPhase::Complete;
    finish(&third_dir, &result)?;
    drop(running);
    assert_eq!(status(None)?.state, E2eEventSessionState::Passed);
    assert_eq!(
        status(None)?.progress.unwrap().phase,
        E2eEventSessionPhase::Complete
    );
    assert_eq!(
        status(None)?
            .previous_events
            .and_then(|events| events.last_sequence),
        Some(7)
    );
    assert_eq!(
        status(Some(second))?.state,
        E2eEventSessionState::Interrupted
    );
    Ok(())
}
