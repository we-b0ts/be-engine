//! Round mutations for Replay, reviewed findings and delivery receipts.
use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde_json::json;
use traffic_e2e::{
    E2eEventSessionOptions, E2eEventSessionResult, E2eEventSessionState, E2eEventSessionStatus,
    execution_identity, run_e2e_event_session_with_apis, session, status_e2e_event_session,
};

use crate::{
    handoff::{AssignmentDetail, Plan, Receipt},
    print_json,
    round::{Recording, Repository, Round, RoundLock},
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
    let _run = repo.lock_replay()?;
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
    round = sync_round(&repo, &lock, round, &recording, &current)?;
    let (_, action) = attempt_action(
        &repo,
        &round,
        &recording,
        current.state,
        current.attempt.as_ref(),
        AssignmentDetail::Summary,
    )?;
    if action["kind"] == "api_review_required" {
        drop(lock);
        return round_status(&repo, round, false, AssignmentDetail::Summary, pretty);
    }
    ensure!(
        current.state != E2eEventSessionState::Running,
        "a Replay is already running; inspect status"
    );
    if let Some(candidate) = current
        .attempt
        .as_ref()
        .and_then(|attempt| round.workflow.candidate_commit(attempt))
    {
        ensure!(
            candidate == repo.head,
            "restore the registered Target candidate {candidate}"
        );
    }
    if current.state == E2eEventSessionState::Failed
        && current
            .attempt
            .as_ref()
            .and_then(mismatch_sequence)
            .is_some()
    {
        ensure!(
            action["kind"] == "advance_required",
            "complete the current handoff before Replay; inspect status"
        );
    }
    repo.check_checkout(&lock)?;
    if round.note_engine_attempt(current.attempt.as_ref()) {
        round = repo.save_round(&lock, round)?;
    }
    let options = E2eEventSessionOptions {
        target_root: repo.root.clone(),
        recording_root: recording.root.clone(),
        run_key: Some(round.run_key.clone()),
        expected_target_commit: Some(repo.head.clone()),
    };
    drop(lock);

    let (result, apis) = run_e2e_event_session_with_apis(options).await?;
    let lock = repo.lock_round_for_update()?;
    let round = require_round(&repo)?;
    let current = current_attempt(&repo, &round, &recording)?;
    let round = sync_round(&repo, &lock, round, &recording, &current)?;
    publish_result(&repo, &round, &recording, result, apis, pretty)
}

pub(super) fn switch_recording(root: &Path, id: &str, pretty: bool) -> Result<()> {
    let mut repo = Repository::load(root)?;
    ensure!(
        !repo.on_base(),
        "start a regression from pr_base with run --user-confirm --recording-run-id {id}"
    );
    let _run = repo.lock_replay()?;
    let lock = repo.lock()?;
    let recording = Recording::load(&repo.root, id)?;
    let round = repo.select_round(&lock, recording, false, None)?;
    drop(lock);
    round_status(&repo, round, false, AssignmentDetail::Full, pretty)
}

pub(super) fn plan(
    root: &Path,
    id: Option<&str>,
    path: &Path,
    max_implementers: Option<usize>,
    pretty: bool,
) -> Result<()> {
    let plan: Plan = serde_json::from_slice(&fs::read(path)?).context("parse Replay plan")?;
    let repo = Repository::load(root)?;
    let lock = repo.lock_round_for_update()?;
    require_committed_configuration(&repo.root)?;
    let mut round = require_round(&repo)?;
    let recording = round_recording(&repo, &round, id)?;
    let current = current_attempt(&repo, &round, &recording)?;
    if let Some(max_implementers) = max_implementers {
        round.workflow.set_max_implementers(max_implementers)?;
    }
    if let Some(apis) = plan.apis {
        round
            .workflow
            .confirm_apis(&repo.root, &recording.root, apis)?;
    } else {
        ensure!(
            plan.ownership.is_some(),
            "supply API confirmations or event ownership"
        );
    }
    update_round(&repo, &mut round, &recording, &current)?;
    if let Some(owner) = plan.ownership {
        ensure!(
            failed_sequence(&current) == Some(owner.seq),
            "ownership must refer to the current failed sequence"
        );
        round.workflow.set_owner(owner, &repo.head)?;
    }
    repo.reserve_worktrees(&lock, &mut round)?;
    let round = repo.save_round(&lock, round)?;
    print_action(&repo, &round, &recording, &current, pretty)
}

pub(super) fn report(root: &Path, id: Option<&str>, path: &Path, pretty: bool) -> Result<()> {
    let receipt: Receipt =
        serde_json::from_slice(&fs::read(path)?).context("parse delivery receipt")?;
    let repo = Repository::load(root)?;
    let _run = receipt
        .is_candidate()
        .then(|| repo.lock_replay())
        .transpose()?;
    let lock = repo.lock_round_for_update()?;
    let mut round = require_round(&repo)?;
    let recording = round_recording(&repo, &round, id)?;
    let current = current_attempt(&repo, &round, &recording)?;
    if receipt.is_candidate() {
        require_committed_configuration(&repo.root)?;
        ensure!(
            matches!(
                current.state,
                E2eEventSessionState::Failed | E2eEventSessionState::Passed
            ),
            "publish an integration candidate for the current finished attempt; inspect status"
        );
    }
    update_round(&repo, &mut round, &recording, &current)?;
    round.workflow.report(
        &repo.root,
        &repo.head,
        current.attempt.as_ref(),
        failed_sequence(&current),
        receipt,
    )?;
    repo.reserve_worktrees(&lock, &mut round)?;
    let round = repo.save_round(&lock, round)?;
    print_action(&repo, &round, &recording, &current, pretty)
}

pub(super) fn needs_round_sync(round: &Round, current: &E2eEventSessionStatus) -> bool {
    round.workflow.needs_api_work_queue()
        || (current.state == E2eEventSessionState::Passed && round.workflow.has_lookahead_work())
        || failed_sequence(current).is_some_and(|seq| {
            current
                .attempt
                .as_ref()
                .is_some_and(|attempt| !round.workflow.failure_observed(attempt, seq))
        })
}

pub(super) fn sync_round(
    repo: &Repository,
    lock: &RoundLock,
    mut round: Round,
    recording: &Recording,
    current: &E2eEventSessionStatus,
) -> Result<Round> {
    if update_round(repo, &mut round, recording, current)? {
        repo.reserve_worktrees(lock, &mut round)?;
        return repo.save_round(lock, round);
    }
    Ok(round)
}

fn update_round(
    repo: &Repository,
    round: &mut Round,
    recording: &Recording,
    current: &E2eEventSessionStatus,
) -> Result<bool> {
    if !needs_round_sync(round, current)
        || round
            .workflow
            .needs_api_review(&repo.root, &recording.root)?
    {
        return Ok(false);
    }
    round.workflow.queue_api_work(&repo.head);
    if current.state == E2eEventSessionState::Passed {
        round.workflow.retire_lookahead_work();
    }
    if let Some(seq) = failed_sequence(current) {
        let attempt = current
            .attempt
            .as_ref()
            .context("a failure has no Replay attempt")?;
        round
            .workflow
            .observe_failure(&repo.root, &recording.root, &repo.head, attempt, seq)?;
    }
    Ok(true)
}

fn failed_sequence(current: &E2eEventSessionStatus) -> Option<u64> {
    if current.state == E2eEventSessionState::Failed {
        current.attempt.as_ref().and_then(mismatch_sequence)
    } else {
        None
    }
}

fn print_action(
    repo: &Repository,
    round: &Round,
    recording: &Recording,
    current: &E2eEventSessionStatus,
    pretty: bool,
) -> Result<()> {
    let action = match configuration_action(&repo.root)? {
        Some(action) => round
            .workflow
            .with_assignments(action, AssignmentDetail::Full),
        None => {
            attempt_action(
                repo,
                round,
                recording,
                current.state,
                current.attempt.as_ref(),
                AssignmentDetail::Full,
            )?
            .1
        }
    };
    print_json(
        &json!({"recording_id":recording.id, "action":action}),
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
    let (_, action) = attempt_action(
        repo,
        round,
        recording,
        state,
        Some(&result),
        AssignmentDetail::Full,
    )?;
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
