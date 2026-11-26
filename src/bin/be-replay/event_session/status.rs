//! Compact Replay state and the coordinator's current action.

use std::{fmt::Display, path::Path};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};
use traffic_e2e::{
    E2eEventSessionPhase, E2eEventSessionResult, E2eEventSessionState, E2eEventSessionStatus,
    execution_identity, session, status_e2e_event_session,
};
use uuid::Uuid;

use crate::{
    handoff::AssignmentDetail,
    print_json,
    round::{self, Recording, Repository, Round},
};

use super::workflow::{
    current_attempt, needs_round_sync, require_round, round_recording, sync_round,
};

pub(super) fn show(
    root: &Path,
    id: Option<&str>,
    run_key: Option<&str>,
    attempt_id: Option<Uuid>,
    with_assignments: bool,
    pretty: bool,
) -> Result<()> {
    let repo = match Repository::load(root) {
        Ok(repo) => repo,
        Err(error) => {
            if run_key.is_none()
                && attempt_id.is_none()
                && let Some(action) = configuration_action(root)?
            {
                return print_json(
                    &json!({"recording_id":id, "state":null, "phase":null, "progress":null, "session":null, "action":action}),
                    pretty,
                );
            }
            return Err(error);
        }
    };
    let (round, needs_switch) = repo.inspect_round(id)?;
    if run_key.is_some() || attempt_id.is_some() {
        return historical_status(&repo, round.as_ref(), id, run_key, attempt_id, pretty);
    }
    let detail = if with_assignments {
        AssignmentDetail::Full
    } else {
        AssignmentDetail::Summary
    };
    match round {
        Some(round) => round_status(&repo, round, needs_switch, detail, pretty),
        None => entry_status(&repo, id, needs_switch, pretty),
    }
}

pub(super) fn round_status(
    repo: &Repository,
    round: Round,
    needs_switch: bool,
    detail: AssignmentDetail,
    pretty: bool,
) -> Result<()> {
    let mut round = round;
    let recording = round_recording(repo, &round, None)?;
    let mut status = current_attempt(repo, &round, &recording)?;
    let configuration = if status.state == E2eEventSessionState::Running {
        None
    } else {
        configuration_action(&repo.root)?
    };
    if !needs_switch
        && configuration.is_none()
        && needs_round_sync(&round, &status)
        && !round
            .workflow
            .needs_api_review(&repo.root, &recording.root)?
    {
        let lock = repo.lock_round_for_update()?;
        round = require_round(repo)?;
        round_recording(repo, &round, Some(&recording.id))?;
        status = current_attempt(repo, &round, &recording)?;
        round = sync_round(repo, &lock, round, &recording, &status)?;
    }
    let (state, action) = if let Some(action) = configuration {
        (
            json!(status.state),
            round.workflow.with_assignments(action, detail),
        )
    } else if needs_switch {
        (json!(status.state), switch_action(&recording.id))
    } else {
        attempt_action(
            repo,
            &round,
            &recording,
            status.state,
            status.attempt.as_ref(),
            detail,
        )?
    };
    let mut output = attempt_fields(&status, &recording.root);
    output["recording_id"] = json!(recording.id);
    output["branch"] = json!(round.branch);
    output["state"] = state;
    output["action"] = action;
    print_json(&output, pretty)
}

pub(super) fn attempt_action(
    repo: &Repository,
    round: &Round,
    recording: &Recording,
    state: E2eEventSessionState,
    attempt: Option<&E2eEventSessionResult>,
    detail: AssignmentDetail,
) -> Result<(Value, Value)> {
    use E2eEventSessionState::{Failed, Interrupted, NotStarted, Passed, Running};

    let mut state_label = json!(state);
    let action = if state != Running
        && round
            .workflow
            .needs_api_review(&repo.root, &recording.root)?
    {
        json!({
            "kind":"api_review_required",
            "summary":"Confirm implementation and grouping for every recorded API.",
            "details":{"role":"issue-analyst"},
            "command":["plan", "--findings", "<apis.json>"]
        })
    } else {
        match (state, attempt) {
            (NotStarted, _) => run_action("Run the selected Source recording."),
            (Running, Some(_)) => json!({
                "kind":"wait_required", "summary":"Wait for Replay to finish.",
                "command":["status"]
            }),
            (Interrupted, Some(_)) => run_action("Restart the interrupted Replay."),
            (Failed, Some(last)) => {
                if let Some(commit) = round.workflow.candidate_commit(last) {
                    candidate_action(commit, &repo.head)
                } else if let Some(seq) = mismatch_sequence(last) {
                    if round.engine_retry_available(repo, last)? {
                        json!({
                            "kind":"advance_required",
                            "summary":"Replay once with the updated engine.",
                            "details":{"reason":"engine_changed"},
                            "command":["run"]
                        })
                    } else {
                        round.workflow.failed_action(seq)
                    }
                } else {
                    json!({
                        "kind":"setup_required",
                        "summary":"Resolve the Replay execution error, then retry.",
                        "command":["run"]
                    })
                }
            }
            (Passed, Some(last)) => {
                if let Some(commit) = round.workflow.candidate_commit(last) {
                    candidate_action(commit, &repo.head)
                } else if let Some(action) = round.workflow.integration_action(None) {
                    action
                } else if last.target_commit.as_deref() != Some(&repo.head)
                    || !last.target_inputs.as_deref().is_some_and(|inputs| {
                        execution_identity::repository_fingerprint(&repo.root)
                            .is_ok_and(|current| current == inputs)
                    })
                {
                    state_label = json!("candidate_changed");
                    run_action("Verify the current Target revision and inputs.")
                } else if round.workflow.pending_api_work() {
                    round.workflow.implementation_action()
                } else {
                    json!({"kind":"complete", "summary":"The current Target passed full Replay and API review."})
                }
            }
            _ => unreachable!("only not_started has no attempt"),
        }
    };
    let action = if action["kind"] == "complete" {
        action
    } else {
        round.workflow.with_assignments(action, detail)
    };
    Ok((state_label, action))
}

fn candidate_action(commit: &str, head: &str) -> Value {
    if commit == head {
        json!({
            "kind":"advance_required", "summary":"Verify the registered Target candidate.",
            "details":{"candidate_commit":commit}, "command":["run"]
        })
    } else {
        json!({
            "kind":"setup_required", "summary":"Restore the registered Target candidate, then retry.",
            "details":{"candidate_commit":commit, "head":head}, "command":["run"]
        })
    }
}

fn entry_status(
    repo: &Repository,
    id: Option<&str>,
    needs_switch: bool,
    pretty: bool,
) -> Result<()> {
    if let Some(id) = id {
        Recording::load(&repo.root, id)?;
    }
    let action = if let Some(action) = configuration_action(&repo.root)? {
        action
    } else {
        match id {
            _ if repo.branch.is_none() => json!({
                "kind":"checkout_target_branch", "summary":"Check out a named Target branch."
            }),
            None => json!({
                "kind":"select_recording", "summary":"Select a sealed Source recording.",
                "details":{"recording_ids":round::recordings(&repo.root)?},
                "command":["status", "--recording-run-id", "<ID>"]
            }),
            Some(id) if repo.on_base() => json!({
                "kind":"confirm_regression", "summary":"Ask the user to approve a regression round.",
                "command":["run", "--user-confirm", "--recording-run-id", id]
            }),
            Some(id) if needs_switch => switch_action(id),
            Some(id) => json!({
                "kind":"advance_required", "summary":"Run the selected Source recording.",
                "command":["run", "--recording-run-id", id]
            }),
        }
    };
    print_json(
        &json!({
            "recording_id":id, "branch":repo.branch, "state":"not_started",
            "phase":null, "progress":null, "session":null, "action":action
        }),
        pretty,
    )
}

pub(super) fn configuration_action(root: &Path) -> Result<Option<Value>> {
    let changes = execution_identity::configuration_changes(root)?;
    Ok((!changes.is_empty()).then(|| json!({
        "kind":"configuration_commit_required",
        "summary":"Review and commit the managed configuration, then check status.",
        "details":{"files":changes.iter().map(|change| change.path.as_str()).collect::<Vec<_>>()},
        "command":["status"]
    })))
}

fn run_action(summary: &str) -> Value {
    json!({"kind":"advance_required", "summary":summary, "command":["run"]})
}

fn switch_action(id: &str) -> Value {
    json!({
        "kind":"switch_recording", "summary":"Switch the active Source recording.",
        "command":["switch-recording-id", id]
    })
}

fn historical_status(
    repo: &Repository,
    round: Option<&Round>,
    id: Option<&str>,
    run_key: Option<&str>,
    attempt_id: Option<Uuid>,
    pretty: bool,
) -> Result<()> {
    let id = id
        .or(round.map(|round| round.recording_id.as_str()))
        .context("specify --recording-run-id for historical status")?;
    let key = run_key.or(round
        .filter(|round| round.recording_id == id)
        .map(|round| round.run_key.as_str()));
    let recording = Recording::load(&repo.root, id)?;
    let status = status_e2e_event_session(&repo.root, &recording.root, key, attempt_id)?;
    let attempt = status.attempt.as_ref();
    let mut output = attempt_fields(&status, &recording.root);
    output["recording_id"] = json!(id);
    output["run_key"] = json!(attempt.map(|attempt| attempt.run_key.as_str()).or(key));
    output["state"] = json!(status.state);
    output["action"] = Value::Null;
    print_json(&output, pretty)
}

fn attempt_fields(status: &E2eEventSessionStatus, root: &Path) -> Value {
    let attempt = status.attempt.as_ref();
    let mut fields = json!({
        "phase": attempt.map(|attempt| attempt.phase),
        "progress": attempt.map(|attempt| status_progress(attempt, status, root)),
        "session": attempt.map(|attempt| {
            let mut identity = json!({"attempt_id":attempt.attempt_id});
            if let Some(commit) = &attempt.target_commit {
                identity["target_commit"] = json!(commit);
            }
            identity
        })
    });
    if let Some(failure) = attempt.and_then(failure_view) {
        fields["failure"] = json!(failure);
    }
    fields
}

#[derive(Serialize)]
struct StatusProgress {
    apis: String,
    cases: String,
    events: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_events: Option<String>,
}

fn status_progress(
    attempt: &E2eEventSessionResult,
    status: &E2eEventSessionStatus,
    recording: &Path,
) -> StatusProgress {
    // A historical or damaged recording may have no readable end sequence.
    let end = session::recording_end_sequence(recording).ok().flatten();
    let cases = match attempt.cases.total {
        Some(total) => ratio(attempt.cases.completed, Some(total)),
        None => match session::recording_case_total(recording) {
            Ok(total) => format!("?/{total}"),
            Err(_) => "?/?".to_owned(),
        },
    };
    StatusProgress {
        apis: ratio(attempt.apis.verified, attempt.apis.total),
        cases,
        events: event_ratio(attempt.events.last_sequence, attempt.events.complete, end),
        previous_events: status
            .previous_events
            .map(|previous| event_ratio(previous.last_sequence, previous.complete, end)),
    }
}

fn event_ratio(last_sequence: Option<u64>, complete: bool, end: Option<u64>) -> String {
    ratio(
        end.filter(|_| complete)
            .or(last_sequence)
            .unwrap_or_default(),
        end,
    )
}

fn ratio<T: Display>(current: T, total: Option<T>) -> String {
    match total {
        Some(total) => format!("{current}/{total}"),
        None => format!("{current}/?"),
    }
}

#[derive(Serialize)]
struct Failure<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<Expected<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_observation_id: Option<&'a str>,
}

#[derive(Serialize)]
struct Expected<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependency_sequence: Option<u64>,
}

pub(super) fn mismatch_sequence(attempt: &E2eEventSessionResult) -> Option<u64> {
    mismatch(attempt).map(|(_, seq)| seq)
}

fn mismatch(attempt: &E2eEventSessionResult) -> Option<(&Value, u64)> {
    if attempt.events.complete
        || !matches!(
            attempt.phase,
            E2eEventSessionPhase::StartingTarget | E2eEventSessionPhase::Replaying
        )
    {
        return None;
    }
    let failure = attempt.events.failure.as_ref()?;
    let expected = failure
        .get("expected")
        .or(attempt.events.expected.as_ref())?;
    let seq = expected["sequence"].as_u64().filter(|seq| *seq > 0)?;
    let reason = failure["reason"].as_str().unwrap_or_default();
    // The streaming reader can report an artifact failure while a cursor exists.
    let source_read_failed = reason.starts_with("prepare Source Session event:");
    let starting_target_failed = attempt.phase == E2eEventSessionPhase::StartingTarget
        && failure["reported_sequence"]
            .as_u64()
            .is_some_and(|reported| {
                Some(reported) == attempt.events.last_sequence && reported < seq
            });
    (!source_read_failed && !starting_target_failed).then_some((expected, seq))
}

fn failure_view(attempt: &E2eEventSessionResult) -> Option<Failure<'_>> {
    let failure = attempt.events.failure.as_ref();
    if failure.is_none() && attempt.error.is_none() {
        return None;
    }
    let expected = mismatch(attempt);
    let seq = expected
        .map(|(_, seq)| seq)
        .or_else(|| failure?["reported_sequence"].as_u64());
    let expected = expected.and_then(|(event, _)| {
        let kind = event["kind"].as_str();
        let dependency_sequence = event["dependency_sequence"].as_u64().filter(|seq| *seq > 0);
        (kind.is_some() || dependency_sequence.is_some()).then_some(Expected {
            kind,
            dependency_sequence,
        })
    });
    Some(Failure {
        seq,
        expected,
        reason: failure
            .and_then(|failure| failure["reason"].as_str())
            .or(attempt.error.as_deref()),
        target_observation_id: failure
            .and_then(|failure| failure["target_observation_id"].as_str()),
    })
}

#[cfg(test)]
mod tests {
    use traffic_e2e::E2eEventSessionProgress;

    use super::*;

    fn attempt(phase: E2eEventSessionPhase, failure: Option<Value>) -> E2eEventSessionResult {
        E2eEventSessionResult {
            run_key: "fixture".into(),
            attempt_id: Uuid::from_u128(1).simple().to_string(),
            recording_root: "/recording".into(),
            target_commit: None,
            target_inputs: None,
            engine_revision: None,
            target_image_id: None,
            passed: false,
            events: E2eEventSessionProgress {
                last_sequence: Some(8),
                expected: Some(json!({"sequence": 10, "kind":"request"})),
                failure,
                ..Default::default()
            },
            phase,
            apis: Default::default(),
            cases: Default::default(),
            error: None,
            progress: "/progress.json".into(),
            report: "/report.json".into(),
        }
    }

    #[test]
    fn failure_shows_the_expected_event_frozen_at_the_first_mismatch() {
        let attempt = attempt(
            E2eEventSessionPhase::Replaying,
            Some(json!({
                "reason":"request mismatch",
                "expected":{"sequence":9,"kind":"request","dependency_sequence":9,"offset_micros":9100},
                "reported_sequence":15
            })),
        );
        assert_eq!(
            json!(failure_view(&attempt)),
            json!({"seq":9,"expected":{"kind":"request","dependency_sequence":9},
                "reason":"request mismatch"})
        );
        assert_eq!(mismatch_sequence(&attempt), Some(9));
    }

    #[test]
    fn setup_and_source_read_failures_do_not_claim_a_target_mismatch() {
        let mut build = attempt(E2eEventSessionPhase::Building, None);
        build.error = Some("build failed".into());
        assert_eq!(
            json!(failure_view(&build)),
            json!({"reason":"build failed"})
        );
        let source = attempt(
            E2eEventSessionPhase::Replaying,
            Some(json!({
                "reported_sequence":13,"reason":"prepare Source Session event: invalid Source row"
            })),
        );
        assert_eq!(mismatch_sequence(&source), None);
        assert_eq!(
            json!(failure_view(&source)),
            json!({"seq":13,"reason":"prepare Source Session event: invalid Source row"})
        );
    }
}
