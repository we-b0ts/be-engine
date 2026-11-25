use super::*;
use crate::{
    case_selection::{self, ReplayIteration},
    execute::timing_guard,
    model::{ActiveRunState, RunLayout},
    test_session,
};

#[test]
fn standalone_replay_uses_default_stream_timing() {
    let target = target();
    initialize(options(target.path())).unwrap();
    let (_, config) = resolve_project(target.path()).unwrap();
    assert_eq!(config.replay_stream_timing, None);
    assert_eq!(config.replay_stream_interval_cap_ms, 5);
}

struct TimingAttempt {
    target: tempfile::TempDir,
    config: ResolvedProjectConfig,
    layout: RunLayout,
    state: ActiveRunState,
}

fn timing_attempt() -> TimingAttempt {
    let target = target();
    initialize(options(target.path())).unwrap();
    let (_, config) = resolve_project(target.path()).unwrap();
    let (layout, inventory, mut state) = test_session::session(target.path());
    state.case_selection = case_selection::prepare(
        &layout,
        &inventory,
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
fn preparation_must_keep_the_original_code_identity_before_spawn() {
    let mut attempt = timing_attempt();
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
