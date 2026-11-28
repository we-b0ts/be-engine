//! Bind selected inputs and the launched timing policy to one execution identity.
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::super::{
    batch_evidence,
    model::{ActiveRunState, ResolvedProjectConfig},
};

fn validate_timing(config: &ResolvedProjectConfig, state: &ActiveRunState) -> Result<()> {
    if let Some(selection) = &state.case_selection {
        selection.validate_stream_timing(config)?;
    }
    Ok(())
}

pub(crate) fn freeze(
    config: &ResolvedProjectConfig,
    root: &Path,
    state: &mut ActiveRunState,
) -> Result<()> {
    ensure!(
        state.executed_replay_identity.is_none(),
        "Replay already has a frozen execution identity; start a fresh attempt"
    );
    validate_timing(config, state)?;
    state.executed_replay_identity = Some(crate::execution_identity::fresh_replay_identity(root)?);
    Ok(())
}

pub(crate) fn before_spawn(
    config: &ResolvedProjectConfig,
    root: &Path,
    state: &ActiveRunState,
) -> Result<()> {
    validate_timing(config, state)?;
    // Index preparation and the Target image build can await for a long time.
    // Validate against the original identity rather than replacing it with a
    // new fingerprint of inputs that this attempt never resolved or selected.
    batch_evidence::validate_executed_identity(root, state)
        .context("Replay inputs changed before launch; start a fresh attempt")
}
