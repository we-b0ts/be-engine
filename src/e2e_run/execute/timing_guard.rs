//! Bind selected inputs and the launched timing policy to one execution identity.
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::super::{
    batch_evidence,
    model::{ActiveRunState, ResolvedProjectConfig},
};

fn validate_timing(
    config: &ResolvedProjectConfig,
    root: &Path,
    state: &ActiveRunState,
) -> Result<()> {
    if let Some(selection) = &state.case_selection {
        selection.validate_stream_timing(config)?;
    }
    let current = crate::config::regression::RegressionScope::load(root)?;
    ensure!(
        current.replay_timing == config.replay_stream_timing
            && (current.replay_timing != Some(crate::replay::ReplayStreamTiming::Fast)
                || current.replay_interval_cap_ms == config.replay_stream_interval_cap_ms),
        "Replay stream timing changed after runtime resolution; start a fresh attempt"
    );
    Ok(())
}

pub(in crate::e2e_run) fn freeze(
    config: &ResolvedProjectConfig,
    root: &Path,
    state: &mut ActiveRunState,
) -> Result<()> {
    ensure!(
        state.executed_replay_identity.is_none(),
        "Replay already has a frozen execution identity; start a fresh attempt"
    );
    validate_timing(config, root, state)?;
    let identity = crate::rewrite::batch_execution_identity(root)?;
    // Fingerprinting reads Source and runtime metadata synchronously. A local
    // timing edit during that work must not certify different launch arguments.
    validate_timing(config, root, state)?;
    state.executed_replay_identity = Some(identity);
    Ok(())
}

pub(in crate::e2e_run) fn before_spawn(
    config: &ResolvedProjectConfig,
    root: &Path,
    state: &ActiveRunState,
) -> Result<()> {
    validate_timing(config, root, state)?;
    // Index preparation and the Target image build can await for a long time.
    // Validate against the original identity rather than replacing it with a
    // new fingerprint of inputs that this attempt never resolved or selected.
    batch_evidence::validate_executed_identity(root, state)
        .context("Replay inputs changed before launch; start a fresh attempt")
}
