//! Resolve protected Target evidence for an exact registered Replay attempt.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use traffic_e2e::{e2e_run::event_session_report, session};
use uuid::Uuid;

use crate::round::Repository;

use super::workflow;

pub(super) fn observation(
    root: &Path,
    recording_id: Option<&str>,
    attempt: Option<Uuid>,
    report: Option<PathBuf>,
    observation_id: Uuid,
) -> Result<Value> {
    let (recording, report) = if let Some(id) = attempt {
        let repo = Repository::load(root)?;
        let round = workflow::require_round(&repo)?;
        let recording = workflow::round_recording(&repo, &round, recording_id)?;
        let report = event_session_report(&repo.root, &recording.root, &round.run_key, id)?;
        (recording, report)
    } else {
        let recording = workflow::evidence_recording(root, recording_id)?;
        (recording, report.context("specify --attempt or --report")?)
    };
    session::target_observation(&recording.root, &report, observation_id)
}
