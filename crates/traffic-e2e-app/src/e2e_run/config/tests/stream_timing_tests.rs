use super::*;
use crate::e2e_run::{
    case_selection::{self, ReplayIteration},
    execute::timing_guard,
    model::{ActiveRunState, RunLayout},
    test_session,
};
use crate::replay::ReplayStreamTiming::{Fast, Recorded};

#[test]
fn managed_replay_resolves_local_regression_timing_separately_from_project_defaults() {
    let target = target();
    initialize(options(target.path())).unwrap();
    let (_, config) = resolve_project(target.path()).unwrap();
    assert_eq!(config.replay_stream_timing, None);
    assert_eq!(config.replay_stream_interval_cap_ms, 5);
    for (mode, value) in [(Fast, "fast"), (Recorded, "recorded")] {
        fs::write(
            target.path().join(crate::config::regression::PATH),
            format!("replay_timing: {value}\nreplay_interval_cap_ms: 0\n"),
        )
        .unwrap();
        let (_, config) = resolve_project(target.path()).unwrap();
        assert_eq!(config.replay_stream_timing, Some(mode));
        assert_eq!(config.replay_stream_interval_cap_ms, 0);
    }
}

struct TimingAttempt {
    target: tempfile::TempDir,
    config: ResolvedProjectConfig,
    layout: RunLayout,
    state: ActiveRunState,
}

fn timing_attempt(settings: &str) -> TimingAttempt {
    let target = target();
    initialize(options(target.path())).unwrap();
    fs::write(
        target.path().join(crate::config::regression::PATH),
        settings,
    )
    .unwrap();
    let (_, config) = resolve_project(target.path()).unwrap();
    let (layout, mut inventory, mut state) = test_session::session(target.path());
    state.case_selection = case_selection::prepare(
        &layout,
        &mut inventory,
        Some(&ReplayIteration {
            workflow_id: "timing-snapshot".into(),
            final_round: false,
        }),
    )
    .unwrap();
    TimingAttempt {
        target,
        config,
        layout,
        state,
    }
}

#[test]
fn timing_edits_after_resolution_cannot_be_frozen_as_the_old_runtime() {
    for (before, after) in [
        ("", "replay_timing: fast\n"),
        (
            "replay_timing: fast\nreplay_interval_cap_ms: 5\n",
            "replay_timing: fast\nreplay_interval_cap_ms: 0\n",
        ),
    ] {
        let mut attempt = timing_attempt(before);
        // Full-round runs also need this guard without a focused selection.
        attempt.state.case_selection = None;
        fs::write(
            attempt.target.path().join(crate::config::regression::PATH),
            after,
        )
        .unwrap();
        let error = timing_guard::freeze(
            &attempt.config,
            &attempt.layout.target_root,
            &mut attempt.state,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed after runtime resolution")
        );
        assert!(attempt.state.executed_replay_identity.is_none());
    }
}

#[test]
fn selected_cases_cannot_use_timing_from_a_newer_runtime_snapshot() {
    for after in [
        "replay_timing: recorded\n",
        "replay_timing: fast\nreplay_interval_cap_ms: 0\n",
    ] {
        let mut attempt = timing_attempt("replay_timing: fast\n");
        fs::write(
            attempt.target.path().join(crate::config::regression::PATH),
            after,
        )
        .unwrap();
        // The file and newly resolved runtime agree, but the selected inputs
        // were prepared under the previous timing policy.
        let (_, newer_config) = resolve_project(attempt.target.path()).unwrap();
        let error = timing_guard::freeze(
            &newer_config,
            &attempt.layout.target_root,
            &mut attempt.state,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Case selection stream timing differs")
        );
        assert!(attempt.state.executed_replay_identity.is_none());
    }
}

#[test]
fn preparation_cannot_replace_the_frozen_mode_or_cap_before_spawn() {
    for after in [
        "replay_timing: recorded\n",
        "replay_timing: fast\nreplay_interval_cap_ms: 0\n",
    ] {
        let mut attempt = timing_attempt("replay_timing: fast\n");
        timing_guard::freeze(
            &attempt.config,
            &attempt.layout.target_root,
            &mut attempt.state,
        )
        .unwrap();
        let frozen = attempt.state.executed_replay_identity.clone();
        timing_guard::before_spawn(&attempt.config, &attempt.layout.target_root, &attempt.state)
            .unwrap();
        fs::write(
            attempt.target.path().join(crate::config::regression::PATH),
            after,
        )
        .unwrap();
        assert!(
            timing_guard::before_spawn(
                &attempt.config,
                &attempt.layout.target_root,
                &attempt.state,
            )
            .is_err()
        );
        assert_eq!(attempt.state.executed_replay_identity, frozen);
    }
}

#[test]
fn preparation_must_keep_the_original_code_identity_before_spawn() {
    let mut attempt = timing_attempt("replay_timing: fast\n");
    timing_guard::freeze(
        &attempt.config,
        &attempt.layout.target_root,
        &mut attempt.state,
    )
    .unwrap();
    let frozen = attempt.state.executed_replay_identity.clone();
    fs::write(
        attempt.target.path().join("business.rs"),
        "changed target inputs\n",
    )
    .unwrap();
    let error =
        timing_guard::before_spawn(&attempt.config, &attempt.layout.target_root, &attempt.state)
            .unwrap_err();
    assert!(format!("{error:#}").contains("changed before launch"));
    assert_eq!(attempt.state.executed_replay_identity, frozen);
    assert!(
        timing_guard::freeze(
            &attempt.config,
            &attempt.layout.target_root,
            &mut attempt.state,
        )
        .is_err(),
        "a changed identity cannot be refreshed inside an existing attempt"
    );
    assert_eq!(attempt.state.executed_replay_identity, frozen);
}

#[test]
fn an_inactive_interval_cap_does_not_invalidate_recorded_execution() {
    for mode in ["", "replay_timing: recorded\n"] {
        let mut attempt = timing_attempt(mode);
        timing_guard::freeze(
            &attempt.config,
            &attempt.layout.target_root,
            &mut attempt.state,
        )
        .unwrap();
        fs::write(
            attempt.target.path().join(crate::config::regression::PATH),
            format!("{mode}replay_interval_cap_ms: 0\n"),
        )
        .unwrap();
        timing_guard::before_spawn(&attempt.config, &attempt.layout.target_root, &attempt.state)
            .unwrap();
    }
}
