//! Round mutations for Replay, reviewed findings and delivery receipts.
use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde_json::json;
use traffic_e2e::{
    E2eEventSessionOptions, E2eEventSessionResult, E2eEventSessionState, E2eEventSessionStatus,
    event_work, execution_identity, run_e2e_event_session_with_apis, session,
    status_e2e_event_session,
};
use uuid::Uuid;

use crate::{
    handoff::{AssignmentDetail, Receipt},
    print_json,
    round::{Recording, Repository, Round},
};

use super::status::{attempt_action, configuration_action, mismatch_sequence, round_status};

pub(super) async fn replay(
    root: &Path,
    id: Option<&str>,
    user_confirm: bool,
    run_key: Option<String>,
    pretty: bool,
) -> Result<()> {
    require_committed_configuration(root)?;
    let mut repo = Repository::load(root)?;
    ensure!(
        !repo.on_base() || user_confirm,
        "starting a regression on pr_base requires user approval and `run --user-confirm`"
    );
    let lock = repo.lock()?;
    require_committed_configuration(&repo.root)?;
    let mut round = if let Some(id) = id {
        let recording = Recording::load(&repo.root, id)?;
        repo.select_round(&lock, recording, user_confirm, run_key)?
    } else {
        ensure!(
            !user_confirm,
            "select a sealed recording with --recording-run-id; inspect be-replay status"
        );
        let round = repo.read_round()?.context(
            "select a sealed recording with --recording-run-id; inspect be-replay status",
        )?;
        round.validate_run_key(run_key.as_deref())?;
        round
    };
    let recording = round_recording(&repo, &round, id)?;
    let current = current_attempt(&repo, &round, &recording)?;
    if let Some(last) = current.attempt.as_ref() {
        let engine_retry = current.state == E2eEventSessionState::Failed
            && mismatch_sequence(last).is_some()
            && round.engine_retry_available(&repo, last)?;
        if !engine_retry {
            ensure!(
                current.state != E2eEventSessionState::Failed
                    || last.target_commit.as_deref() != Some(&repo.head)
                    || mismatch_sequence(last).is_none()
                    || round.workflow.next(last, &repo.head).is_some(),
                "submit reviewed findings for the first Replay mismatch; inspect be-replay status"
            );
            round.workflow.require_replay_candidate(last, &repo.head)?;
        }
    }
    repo.check_checkout(&lock)?;
    if round.note_engine_attempt(current.attempt.as_ref()) {
        round = repo.save_round(&lock, round)?;
    }
    let (result, apis) = run_e2e_event_session_with_apis(E2eEventSessionOptions {
        target_root: repo.root.clone(),
        recording_root: recording.root.clone(),
        run_key: Some(round.run_key.clone()),
        expected_target_commit: Some(repo.head.clone()),
    })
    .await?;
    if result.passed && round.workflow.has_pending_api_work() {
        let limit = round.workflow.max_implementers();
        round.workflow.queue_api_repairs(&result, limit)?;
        repo.reserve_worktrees(&lock, &mut round)?;
        round = repo.save_round(&lock, round)?;
    }
    publish_result(&repo, &round, &recording, result, apis, pretty)
}

pub(super) fn switch_recording(root: &Path, id: &str, pretty: bool) -> Result<()> {
    let mut repo = Repository::load(root)?;
    ensure!(
        !repo.on_base(),
        "start a regression from pr_base with run --user-confirm --recording-run-id {id}"
    );
    let lock = repo.lock()?;
    let recording = Recording::load(&repo.root, id)?;
    let round = repo.select_round(&lock, recording, false, None)?;
    round_status(&repo, round, false, AssignmentDetail::Full, pretty)
}

pub(super) fn plan(
    root: &Path,
    id: Option<&str>,
    findings: &Path,
    max_implementers: usize,
    attempt_id: Uuid,
    pretty: bool,
) -> Result<()> {
    require_committed_configuration(root)?;
    let repo = Repository::load(root)?;
    let lock = repo.lock()?;
    require_committed_configuration(&repo.root)?;
    let mut round = require_round(&repo)?;
    let recording = round_recording(&repo, &round, id)?;
    let current = current_attempt(&repo, &round, &recording)?;
    ensure!(
        matches!(
            current.state,
            E2eEventSessionState::Failed | E2eEventSessionState::Passed
        ),
        "expected a finished Replay attempt; inspect status"
    );
    let last = current.attempt.context("Replay attempt is missing")?;
    ensure!(
        last.target_commit.as_deref() == Some(repo.head.as_str()),
        "the attempt belongs to a different Target revision"
    );
    ensure!(
        last.attempt_id.parse::<Uuid>()? == attempt_id,
        "findings refer to a stale attempt"
    );
    let mut findings: event_work::Findings =
        serde_json::from_slice(&fs::read(findings)?).context("parse event findings")?;
    if let Some(apis) = findings.apis.take() {
        round
            .workflow
            .confirm_apis(&repo.root, &recording.root, apis, &findings)?;
    }
    if current.state == E2eEventSessionState::Passed {
        ensure!(
            findings.first_unmatched.is_none() && findings.others.is_empty(),
            "submit only API confirmations after a passing Replay"
        );
        ensure!(
            round.workflow.apis_reviewed(),
            "confirm every recorded API in findings.apis"
        );
        round.workflow.queue_api_repairs(&last, max_implementers)?;
    } else {
        let failed_seq = mismatch_sequence(&last)
            .context("the failed attempt has no event mismatch to plan; inspect status")?;
        round
            .workflow
            .set_plan(&last, failed_seq, findings, max_implementers)?;
    }
    repo.reserve_worktrees(&lock, &mut round)?;
    let mut output = match round.workflow.current_plan(&last) {
        Some(plan) => serde_json::to_value(plan)?,
        None => json!({}),
    };
    output["action"] = attempt_action(
        &repo,
        &round,
        current.state,
        Some(&last),
        AssignmentDetail::Full,
    )?
    .1;
    repo.save_round(&lock, round)?;
    print_json(&output, pretty)
}

pub(super) fn report(root: &Path, id: Option<&str>, path: &Path, pretty: bool) -> Result<()> {
    let receipt: Receipt =
        serde_json::from_slice(&fs::read(path)?).context("parse delivery receipt")?;
    let repo = Repository::load(root)?;
    let lock = repo.lock()?;
    let mut round = require_round(&repo)?;
    let recording = round_recording(&repo, &round, id)?;
    let latest = current_attempt(&repo, &round, &recording)?;
    if matches!(&receipt, Receipt::Candidate { .. }) {
        require_committed_configuration(&repo.root)?;
        ensure!(
            matches!(
                latest.state,
                E2eEventSessionState::Failed | E2eEventSessionState::Passed
            ),
            "publish an integration candidate for the current finished attempt; inspect status"
        );
    }
    let last = latest
        .attempt
        .as_ref()
        .context("round has no Replay attempt")?;
    round
        .workflow
        .report(&repo.root, &repo.head, last, receipt)?;
    repo.reserve_worktrees(&lock, &mut round)?;
    let action = match configuration_action(&repo.root)? {
        Some(action) => action,
        None => {
            attempt_action(
                &repo,
                &round,
                latest.state,
                Some(last),
                AssignmentDetail::Full,
            )?
            .1
        }
    };
    repo.save_round(&lock, round)?;
    print_json(
        &json!({
            "recording_id":recording.id, "attempt_id":last.attempt_id,
            "action":action
        }),
        pretty,
    )
}

pub(super) fn evidence_recording(root: &Path, id: Option<&str>) -> Result<Recording> {
    if let Some(id) = id {
        return Recording::load(root, id);
    }
    let repo = Repository::load(root)?;
    let round = require_round(&repo)?;
    round_recording(&repo, &round, None)
}

pub(super) fn require_round(repo: &Repository) -> Result<Round> {
    repo.read_round()?
        .context("start or resume a regression work branch; inspect be-replay status")
}

fn require_committed_configuration(root: &Path) -> Result<()> {
    let changes = execution_identity::configuration_changes(root)?;
    ensure!(
        changes.is_empty(),
        "commit the managed configuration before continuing: {}",
        changes
            .iter()
            .map(|change| change.path.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

pub(super) fn round_recording(
    repo: &Repository,
    round: &Round,
    id: Option<&str>,
) -> Result<Recording> {
    ensure!(
        id.is_none_or(|id| id == round.recording_id),
        "round uses recording {}; select the requested recording with switch-recording-id",
        round.recording_id,
    );
    let recording = Recording::load(&repo.root, &round.recording_id)?;
    round.validate_recording(&recording)?;
    Ok(recording)
}

pub(super) fn current_attempt(
    repo: &Repository,
    round: &Round,
    recording: &Recording,
) -> Result<E2eEventSessionStatus> {
    status_e2e_event_session(&repo.root, &recording.root, Some(&round.run_key), None)
}

fn publish_result(
    repo: &Repository,
    round: &Round,
    recording: &Recording,
    result: E2eEventSessionResult,
    apis: BTreeMap<String, session::SessionApiCounts>,
    pretty: bool,
) -> Result<()> {
    let progress = if result.passed {
        session::publish_passed_progress(&repo.root, &recording.root, &apis)
    } else {
        Ok(false)
    };
    let state = if result.passed {
        E2eEventSessionState::Passed
    } else {
        E2eEventSessionState::Failed
    };
    let (_, action) = attempt_action(repo, round, state, Some(&result), AssignmentDetail::Full)?;
    let mut report = json!({
        "recording_id":recording.id, "branch":round.branch, "session":result, "apis":apis,
        "progress_published":progress.as_ref().copied().unwrap_or(false), "action":action
    });
    if let Err(error) = &progress {
        report["progress_publication_error"] = json!(format!("{error:#}"));
    }
    print_json(&report, pretty)?;
    ensure!(result.passed, "Source session Replay failed");
    progress?;
    Ok(())
}
