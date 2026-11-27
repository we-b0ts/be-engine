//! Round mutations for Replay, reviewed findings and delivery receipts.
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde_json::json;
use traffic_e2e::{
    E2eEventSessionOptions, E2eEventSessionResult, E2eEventSessionState, E2eEventSessionStatus,
    execution_identity, run_e2e_event_session_with_apis, session, status_e2e_event_session,
};
use uuid::Uuid;

use crate::{
    handoff::{AssignmentDetail, CatalogUpdate, Plan, Receipt, Registration, read_receipt},
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
    let action = current_action(&repo, &round, &current)?;
    let kind = action.output["kind"].as_str();
    if action.task.as_ref().is_some_and(|task| task.is_grouping())
        || matches!(kind, Some("dispatch_required" | "worker_status_required"))
        || (current.state == E2eEventSessionState::NotStarted && kind != Some("advance_required"))
    {
        drop(lock);
        return round_status(&repo, round, false, AssignmentDetail::Summary, pretty);
    }
    ensure!(
        current.state != E2eEventSessionState::Running,
        "a Replay is already running; inspect status"
    );
    ensure!(
        action.task.is_none(),
        "complete the current delegated task before Replay; inspect status"
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
            kind == Some("advance_required"),
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
    round_status(&repo, round, false, AssignmentDetail::Summary, pretty)
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
    update_round(&repo, &mut round, &recording, &current)?;
    let task = if plan.lookahead.is_some() {
        current.attempt.as_ref().and_then(|attempt| {
            round
                .workflow
                .lookahead_delivery_task(&round.run_key, &attempt.attempt_id)
        })
    } else {
        current_action(&repo, &round, &current)?.task
    }
    .context("no delegated plan is currently required; inspect status")?;
    let binding = Registration {
        task_id: plan.task_id,
        agent_handle: plan.agent_handle,
    };
    round.workflow.require_task_delivery(&task, &binding)?;
    if let Some(max_implementers) = max_implementers {
        round.workflow.set_max_implementers(max_implementers)?;
    }
    let catalog = match (plan.apis, plan.ownership, plan.lookahead) {
        (Some(apis), None, None) => {
            ensure!(
                task.is_grouping(),
                "the current delegated task does not request API groupings"
            );
            let inventory = session::recorded_apis(&repo.root, &recording.root)?;
            let catalog = CatalogUpdate::prepare(&repo.root, &inventory, &apis)?;
            round.api_backlog.register_groupings(&apis);
            Some(catalog)
        }
        (None, Some(mut owner), None) => {
            ensure!(
                failed_sequence(&current) == Some(owner.seq),
                "ownership must refer to the current failed sequence"
            );
            ensure!(
                task.is_ownership(),
                "the current delegated task does not request event ownership"
            );
            owner.resolve_api(&repo.root)?;
            round.workflow.set_owner(owner, &repo.head)?;
            repo.reserve_worktrees(&lock, &mut round)?;
            None
        }
        (None, None, Some(findings)) => {
            ensure!(
                task.is_lookahead(),
                "the current task does not request lookahead ownership"
            );
            round.workflow.apply_lookahead_findings(
                &repo.root,
                &repo.head,
                path.parent().unwrap_or_else(|| Path::new("")),
                findings,
            )?;
            repo.reserve_worktrees(&lock, &mut round)?;
            None
        }
        _ => anyhow::bail!("supply API groupings, current event ownership, or lookahead findings"),
    };
    // Keep the implementation obligations even if publication is interrupted.
    let round = repo.save_round(&lock, round)?;
    if let Some(catalog) = catalog {
        repo.check_checkout(&lock)?;
        catalog.publish(&repo.root)?;
    }
    print_action(&repo, &round, &recording, &current, pretty)
}

pub(super) fn report(root: &Path, id: Option<&str>, path: &Path, pretty: bool) -> Result<()> {
    let receipt = read_receipt(path)?;
    let repo = Repository::load(root)?;
    let _run = receipt
        .is_candidate()
        .then(|| repo.lock_replay())
        .transpose()?;
    let lock = repo.lock_round_for_update()?;
    let mut round = require_round(&repo)?;
    let recording = round_recording(&repo, &round, id)?;
    let current = current_attempt(&repo, &round, &recording)?;
    let dispatch = match &receipt {
        Receipt::TaskDispatch { task_id, .. } => Some(task_id.as_str()),
        _ => None,
    };
    if dispatch.is_some() || receipt.is_candidate() {
        require_committed_configuration(&repo.root)?;
    }
    if receipt.is_candidate() {
        ensure!(
            matches!(
                current.state,
                E2eEventSessionState::Failed | E2eEventSessionState::Passed
            ),
            "publish an integration candidate for the current finished attempt; inspect status"
        );
    }
    if configuration_action(&repo.root)?.is_none() {
        update_round(&repo, &mut round, &recording, &current)?;
    }
    if let Receipt::Confirmed(confirmation) = &receipt
        && failed_sequence(&current).is_some_and(|seq| confirmation.sequences.contains(&seq))
    {
        let attempt = current.attempt.as_ref().context("missing failed attempt")?;
        ensure!(
            round.engine_retry_available(&repo, attempt)?,
            "the current failed sequence requires a repair or an updated engine"
        );
    }
    if receipt.is_candidate() {
        ensure!(
            round.ungrouped_apis() == 0,
            "group the new APIs before publishing a candidate; inspect status"
        );
    }
    let current_task = if let Some(id) = dispatch {
        let lookahead = current
            .attempt
            .as_ref()
            .and_then(|attempt| {
                round
                    .workflow
                    .lookahead_task(&round.run_key, &attempt.attempt_id)
            })
            .filter(|task| task.id() == id);
        match lookahead {
            Some(task) => Some(task),
            None => current_action(&repo, &round, &current)?.task,
        }
    } else {
        None
    };
    let completed = round.workflow.report(
        &repo.root,
        &repo.head,
        current.attempt.as_ref(),
        failed_sequence(&current),
        current_task.as_ref(),
        receipt,
    )?;
    round.api_backlog.complete(completed);
    repo.reserve_worktrees(&lock, &mut round)?;
    let round = repo.save_round(&lock, round)?;
    print_action(&repo, &round, &recording, &current, pretty)
}

pub(super) fn sequences(
    root: &Path,
    id: Option<&str>,
    assignment_id: Option<Uuid>,
    task_id: Option<&str>,
    scope: Option<&str>,
    after_seq: u64,
    limit: Option<usize>,
) -> Result<()> {
    let repo = Repository::load(root)?;
    let round = require_round(&repo)?;
    ensure!(
        id.is_none_or(|id| id == round.recording_id),
        "select the active recording to query assignments"
    );
    let seqs = if let Some(id) = assignment_id {
        round.workflow.assignment_sequences(id, scope)?
    } else {
        round.workflow.lookahead_task_sequences(
            &round.run_key,
            task_id.context("supply a task or assignment ID")?,
        )?
    };
    let mut out = io::stdout().lock();
    for seq in seqs
        .range((
            std::ops::Bound::Excluded(after_seq),
            std::ops::Bound::Unbounded,
        ))
        .take(limit.unwrap_or(usize::MAX))
    {
        writeln!(out, "{seq}")?;
    }
    Ok(())
}

pub(super) fn needs_round_sync(round: &Round, current: &E2eEventSessionStatus, head: &str) -> bool {
    if current.state == E2eEventSessionState::Running {
        return false;
    }
    round.needs_api_inventory(head)
        || (round.ungrouped_apis() == 0
            && ((current.state == E2eEventSessionState::Passed
                && round.workflow.has_lookahead_work())
                || failed_sequence(current).is_some_and(|seq| {
                    current
                        .attempt
                        .as_ref()
                        .is_some_and(|attempt| !round.workflow.failure_observed(attempt, seq))
                })))
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
    let inventory_changed =
        current.state != E2eEventSessionState::Running && round.needs_api_inventory(&repo.head);
    if inventory_changed {
        let inventory = session::recorded_apis(&repo.root, &recording.root)?;
        round.refresh_api_inventory(&inventory, &repo.head);
    }
    if round.ungrouped_apis() > 0 {
        return Ok(inventory_changed);
    }
    let retired =
        current.state == E2eEventSessionState::Passed && round.workflow.has_lookahead_work();
    if retired {
        round.workflow.retire_lookahead_work();
    }
    if let Some(seq) = failed_sequence(current) {
        let attempt = current
            .attempt
            .as_ref()
            .context("a failure has no Replay attempt")?;
        if !round.workflow.failure_observed(attempt, seq) {
            round.workflow.observe_failure(
                &repo.root,
                &recording.root,
                &repo.head,
                attempt,
                seq,
            )?;
            return Ok(true);
        }
    }
    Ok(inventory_changed || retired)
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
        Some(action) => action,
        None => current_action(repo, round, current)?.output,
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

fn current_action(
    repo: &Repository,
    round: &Round,
    current: &E2eEventSessionStatus,
) -> Result<super::status::AttemptAction> {
    attempt_action(
        repo,
        round,
        current.state,
        current.attempt.as_ref(),
        AssignmentDetail::Summary,
    )
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
    let action = attempt_action(repo, round, state, Some(&result), AssignmentDetail::Summary)?;
    let mut report = json!({
        "recording_id":recording.id, "branch":round.branch, "session":result, "apis":apis,
        "progress_published":progress.as_ref().copied().unwrap_or(false), "action":action.output
    });
    if let Err(error) = &progress {
        report["progress_publication_error"] = json!(format!("{error:#}"));
    }
    print_json(&report, pretty)?;
    ensure!(result.passed, "Source session Replay failed");
    progress?;
    Ok(())
}
