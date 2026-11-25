//! Project the coordinator's next action from the current round and attempt.
use std::{fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde_json::json;
use traffic_e2e::{
    E2eEventSessionOptions, E2eEventSessionResult, E2eEventSessionState, E2eEventSessionStatus,
    event_work, execution_identity, run_e2e_event_session, session, status_e2e_event_session,
};
use uuid::Uuid;

use crate::{
    handoff::Receipt,
    print_json,
    round::{self, Recording, Repository, Round},
};

use super::failure_action;

pub(super) async fn replay(
    root: &Path,
    id: Option<&str>,
    user_confirm: bool,
    run_key: Option<String>,
    pretty: bool,
) -> Result<()> {
    let mut repo = Repository::load(root)?;
    ensure!(
        !repo.on_base() || user_confirm,
        "starting a regression on pr_base requires user approval and `run --user-confirm`"
    );
    let lock = repo.lock()?;
    let round = if let Some(round) = repo.read_round()? {
        ensure!(
            !user_confirm,
            "this branch already has a regression; run without --user-confirm"
        );
        ensure!(
            run_key.as_ref().is_none_or(|key| key == &round.run_key),
            "the work branch already uses run key {}",
            round.run_key
        );
        round
    } else {
        let id = id.context(
            "select a sealed recording with --recording-run-id; inspect be-replay status",
        )?;
        let recording = Recording::load(&repo.root, id)?;
        repo.start_round(&lock, recording, user_confirm, run_key)?
    };
    let recording = round_recording(&repo, &round, id)?;
    if let Some(last) = current_attempt(&repo, &round, &recording)?.attempt {
        round.workflow.require_replay_candidate(&last, &repo.head)?;
    }
    repo.check_checkout(&lock)?;
    let result = run_e2e_event_session(E2eEventSessionOptions {
        target_root: repo.root.clone(),
        recording_root: recording.root.clone(),
        run_key: Some(round.run_key.clone()),
        expected_target_commit: Some(repo.head.clone()),
    })
    .await?;
    publish_result(&repo, &round, &recording, result, pretty)
}

pub(super) fn status(
    root: &Path,
    id: Option<&str>,
    run_key: Option<&str>,
    attempt_id: Option<Uuid>,
    pretty: bool,
) -> Result<()> {
    if run_key.is_some() || attempt_id.is_some() {
        return historical_status(root, id, run_key, attempt_id, pretty);
    }
    let repo = Repository::load(root)?;
    let Some(round) = repo.read_round()? else {
        return entry_status(&repo, id, pretty);
    };
    let recording = round_recording(&repo, &round, id)?;
    let status = current_attempt(&repo, &round, &recording)?;
    let mut state = json!(status.state);
    let next = match (&status.state, status.attempt.as_ref()) {
        (E2eEventSessionState::NotStarted, _) => {
            Some(json!({"action":"run_regression", "run":["run"]}))
        }
        (E2eEventSessionState::Running, Some(_)) => {
            Some(json!({"action":"wait_for_session", "status":["status"]}))
        }
        (E2eEventSessionState::Interrupted, Some(_)) => {
            Some(json!({"action":"rerun_interrupted_session", "run":["run"]}))
        }
        (E2eEventSessionState::Failed, Some(last)) => {
            round.workflow.next(last, &repo.head).or_else(|| {
                if last.target_commit.as_deref() == Some(repo.head.as_str()) {
                    Some(failure_action(&recording.id, last))
                } else {
                    state = json!("candidate_changed");
                    Some(json!({"action":"run_regression", "run":["run"]}))
                }
            })
        }
        (E2eEventSessionState::Passed, Some(last)) => {
            if last.target_commit.as_deref() == Some(repo.head.as_str())
                && last.target_inputs.as_deref().is_some_and(|inputs| {
                    execution_identity::repository_fingerprint(&repo.root)
                        .is_ok_and(|current| current == inputs)
                })
            {
                None
            } else {
                state = json!("candidate_changed");
                Some(json!({"action":"run_regression", "run":["run"]}))
            }
        }
        _ => unreachable!("only not_started has no attempt"),
    };
    print_json(
        &json!({
            "recording_id": recording.id, "branch": round.branch, "pr_base": round.pr_base,
            "base_commit": round.base_commit, "target_commit": repo.head, "run_key": round.run_key,
            "state": state, "session": status.attempt, "next": next
        }),
        pretty,
    )
}

fn entry_status(repo: &Repository, id: Option<&str>, pretty: bool) -> Result<()> {
    let id = id
        .map(|id| Recording::load(&repo.root, id))
        .transpose()?
        .map(|recording| recording.id);
    let next = match id.as_deref() {
        _ if repo.branch.is_none() => {
            json!({"action":"checkout_target_branch", "pr_base":repo.pr_base})
        }
        None => json!({
            "action":"select_recording", "recording_ids":round::recordings(&repo.root)?,
            "status":["status", "--recording-run-id", "<ID>"]
        }),
        Some(id) if repo.on_base() => json!({
            "action":"confirm_regression", "requires_user_confirmation":true,
            "run":["run", "--user-confirm", "--recording-run-id", id]
        }),
        Some(id) => json!({"action":"run_regression", "run":["run", "--recording-run-id", id]}),
    };
    print_json(
        &json!({
            "recording_id":id, "branch":repo.branch, "pr_base":repo.pr_base, "target_commit":repo.head,
            "state":"not_started", "session":null, "next":next
        }),
        pretty,
    )
}

fn historical_status(
    root: &Path,
    id: Option<&str>,
    run_key: Option<&str>,
    attempt_id: Option<Uuid>,
    pretty: bool,
) -> Result<()> {
    let repo = Repository::load(root)?;
    let current = repo.read_round()?;
    let id = id
        .or(current.as_ref().map(|round| round.recording_id.as_str()))
        .context("specify --recording-run-id for historical status")?;
    let key = run_key.or(current
        .as_ref()
        .filter(|round| round.recording_id == id)
        .map(|round| round.run_key.as_str()));
    let recording = Recording::load(&repo.root, id)?;
    let status = status_e2e_event_session(&repo.root, &recording.root, key, attempt_id)?;
    print_json(
        &json!({
            "recording_id":id, "state":status.state, "session":status.attempt, "next":null
        }),
        pretty,
    )
}

pub(super) fn plan(
    root: &Path,
    id: Option<&str>,
    findings: &Path,
    max_implementers: usize,
    attempt_id: Option<Uuid>,
    pretty: bool,
) -> Result<()> {
    let repo = Repository::load(root)?;
    let lock = repo.lock()?;
    let mut round = require_round(&repo)?;
    let recording = round_recording(&repo, &round, id)?;
    let last = failed_attempt(&repo, &round, &recording)?;
    ensure!(
        last.events.failure.is_some() && !last.events.complete,
        "the failed attempt has no event mismatch to plan; inspect status"
    );
    ensure!(
        last.target_commit.as_deref() == Some(repo.head.as_str()),
        "the failed attempt belongs to a different Target revision"
    );
    if let Some(attempt_id) = attempt_id {
        ensure!(
            last.attempt_id.parse::<Uuid>()? == attempt_id,
            "findings refer to a stale attempt"
        );
    }
    let findings = serde_json::from_slice(&fs::read(findings)?).context("parse event findings")?;
    let dispatch = event_work::plan(findings, max_implementers)?;
    let mut output = serde_json::to_value(round.workflow.set_plan(&last, dispatch)?)?;
    repo.save_round(&lock, &round)?;
    let next = round
        .workflow
        .next(&last, &repo.head)
        .expect("just recorded an attempt plan");
    output["next"] = next;
    print_json(&output, pretty)
}

pub(super) fn report(root: &Path, id: Option<&str>, path: &Path, pretty: bool) -> Result<()> {
    let receipt: Receipt =
        serde_json::from_slice(&fs::read(path)?).context("parse delivery receipt")?;
    let repo = Repository::load(root)?;
    let lock = repo.lock()?;
    let mut round = require_round(&repo)?;
    let recording = round_recording(&repo, &round, id)?;
    let last = failed_attempt(&repo, &round, &recording)?;
    round
        .workflow
        .report(&repo.root, &repo.head, &last, receipt)?;
    repo.save_round(&lock, &round)?;
    print_json(
        &json!({
            "recording_id":recording.id, "attempt_id":last.attempt_id,
            "next":round.workflow.next(&last, &repo.head)
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

fn require_round(repo: &Repository) -> Result<Round> {
    repo.read_round()?
        .context("start or resume a regression work branch; inspect be-replay status")
}

fn round_recording(repo: &Repository, round: &Round, id: Option<&str>) -> Result<Recording> {
    ensure!(
        id.is_none_or(|id| id == round.recording_id),
        "round uses recording {}; select a different recording from pr_base",
        round.recording_id
    );
    let recording = Recording::load(&repo.root, &round.recording_id)?;
    round.validate_recording(&recording)?;
    Ok(recording)
}

fn current_attempt(
    repo: &Repository,
    round: &Round,
    recording: &Recording,
) -> Result<E2eEventSessionStatus> {
    status_e2e_event_session(&repo.root, &recording.root, Some(&round.run_key), None)
}

fn failed_attempt(
    repo: &Repository,
    round: &Round,
    recording: &Recording,
) -> Result<E2eEventSessionResult> {
    let status = current_attempt(repo, round, recording)?;
    ensure!(
        status.state == E2eEventSessionState::Failed,
        "expected a current failed attempt; inspect be-replay status"
    );
    status.attempt.context("failed attempt is missing")
}

fn publish_result(
    repo: &Repository,
    round: &Round,
    recording: &Recording,
    result: E2eEventSessionResult,
    pretty: bool,
) -> Result<()> {
    let apis = session::api_counts(&repo.root, &recording.root, result.events.last_sequence);
    let progress = match &apis {
        Ok(apis) if result.passed => {
            session::publish_passed_progress(&repo.root, &recording.root, apis)
        }
        _ => Ok(false),
    };
    let next = (!result.passed).then(|| failure_action(&recording.id, &result));
    let mut report = json!({
        "recording_id":recording.id, "branch":round.branch, "session":result, "apis":apis.as_ref().ok(),
        "progress_published":progress.as_ref().copied().unwrap_or(false), "next":next
    });
    if let Err(error) = &apis {
        report["api_counts_error"] = json!(format!("{error:#}"));
    }
    if let Err(error) = &progress {
        report["progress_publication_error"] = json!(format!("{error:#}"));
    }
    print_json(&report, pretty)?;
    ensure!(result.passed, "Source session Replay failed");
    apis?;
    progress?;
    Ok(())
}
