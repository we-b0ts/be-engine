//! Compact Replay state and the coordinator's current action.

use std::{fmt::Display, path::Path};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};
use traffic_e2e::{
    E2eEventSessionPhase, E2eEventSessionResult, E2eEventSessionState, execution_identity, session,
    status_e2e_event_session,
};
use uuid::Uuid;

use crate::{
    print_json,
    round::{self, Recording, Repository, Round},
};

use super::workflow::{current_attempt, round_recording};

pub(super) fn show(
    root: &Path,
    id: Option<&str>,
    run_key: Option<&str>,
    attempt_id: Option<Uuid>,
    pretty: bool,
) -> Result<()> {
    let repo = Repository::load(root)?;
    let (round, needs_switch) = repo.inspect_round(id)?;
    if run_key.is_some() || attempt_id.is_some() {
        return historical_status(&repo, round.as_ref(), id, run_key, attempt_id, pretty);
    }
    match round {
        Some(round) => round_status(&repo, round, needs_switch, pretty),
        None => entry_status(&repo, id, needs_switch, pretty),
    }
}

pub(super) fn round_status(
    repo: &Repository,
    round: Round,
    needs_switch: bool,
    pretty: bool,
) -> Result<()> {
    let recording = round_recording(repo, &round, None)?;
    let status = current_attempt(repo, &round, &recording)?;
    let attempt = status.attempt.as_ref();
    let (state, mut action) = attempt_action(repo, &round, status.state, attempt);
    if needs_switch {
        action = switch_action(&recording.id);
    }
    let mut output = attempt_fields(attempt, &recording.root);
    output["recording_id"] = json!(recording.id);
    output["branch"] = json!(round.branch);
    output["state"] = state;
    output["action"] = action;
    print_json(&output, pretty)
}

pub(super) fn attempt_action(
    repo: &Repository,
    round: &Round,
    state: E2eEventSessionState,
    attempt: Option<&E2eEventSessionResult>,
) -> (Value, Value) {
    use E2eEventSessionState::{Failed, Interrupted, NotStarted, Passed, Running};

    let mut state_label = json!(state);
    let action = match (state, attempt) {
        (NotStarted, _) => run_action("Run the selected Source recording."),
        (Running, Some(_)) => json!({
            "kind":"wait_required", "summary":"Wait for Replay to finish.",
            "commands":{"status":["status"]}
        }),
        (Interrupted, Some(_)) => run_action("Restart the interrupted Replay."),
        (Failed, Some(last)) => {
            if let Some(action) = round.workflow.next(last, &repo.head) {
                action
            } else if last.target_commit.as_deref() != Some(&repo.head) {
                state_label = json!("candidate_changed");
                run_action("Verify the current Target revision.")
            } else {
                failure_action(last)
            }
        }
        (Passed, Some(last)) => {
            if last.target_commit.as_deref() == Some(&repo.head)
                && last.target_inputs.as_deref().is_some_and(|inputs| {
                    execution_identity::repository_fingerprint(&repo.root)
                        .is_ok_and(|current| current == inputs)
                })
            {
                json!({"kind":"complete", "summary":"The current Target passed full Replay."})
            } else {
                state_label = json!("candidate_changed");
                run_action("Verify the current Target revision and inputs.")
            }
        }
        _ => unreachable!("only not_started has no attempt"),
    };
    (state_label, action)
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
    let action = match id {
        _ if repo.branch.is_none() => json!({
            "kind":"checkout_target_branch", "summary":"Check out a named Target branch."
        }),
        None => json!({
            "kind":"select_recording", "summary":"Select a sealed Source recording.",
            "details":{"recording_ids":round::recordings(&repo.root)?},
            "commands":{"status":["status", "--recording-run-id", "<ID>"]}
        }),
        Some(id) if repo.on_base() => json!({
            "kind":"confirm_regression", "summary":"Ask the user to approve a regression round.",
            "commands":{"run":["run", "--user-confirm", "--recording-run-id", id]}
        }),
        Some(id) if needs_switch => switch_action(id),
        Some(id) => json!({
            "kind":"advance_required", "summary":"Run the selected Source recording.",
            "commands":{"run":["run", "--recording-run-id", id]}
        }),
    };
    print_json(
        &json!({
            "recording_id":id, "branch":repo.branch, "state":"not_started",
            "phase":null, "progress":null, "session":null, "action":action
        }),
        pretty,
    )
}

fn run_action(summary: &str) -> Value {
    json!({"kind":"advance_required", "summary":summary, "commands":{"run":["run"]}})
}

fn switch_action(id: &str) -> Value {
    json!({
        "kind":"switch_recording", "summary":"Switch the active Source recording.",
        "commands":{"switch":["switch-recording-id", id]}
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
    let mut output = attempt_fields(attempt, &recording.root);
    output["recording_id"] = json!(id);
    output["run_key"] = json!(attempt.map(|attempt| attempt.run_key.as_str()).or(key));
    output["state"] = json!(status.state);
    output["action"] = Value::Null;
    print_json(&output, pretty)
}

fn attempt_fields(attempt: Option<&E2eEventSessionResult>, root: &Path) -> Value {
    let mut fields = json!({
        "phase": attempt.map(|attempt| attempt.phase),
        "progress": attempt.map(|attempt| status_progress(attempt, root)),
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
    events: String,
}

fn status_progress(attempt: &E2eEventSessionResult, recording: &Path) -> StatusProgress {
    // A historical or damaged recording may have no readable end sequence.
    let end = session::recording_end_sequence(recording).ok().flatten();
    let current = end
        .filter(|_| attempt.events.complete)
        .or(attempt.events.last_sequence)
        .unwrap_or_default();
    StatusProgress {
        apis: ratio(attempt.apis.verified, attempt.apis.total),
        events: ratio(current, end),
    }
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

fn failure_action(attempt: &E2eEventSessionResult) -> Value {
    if mismatch_sequence(attempt).is_some() {
        json!({
            "kind":"analysis_required", "summary":"Assign the first Replay mismatch for analysis.",
            "details":{"role":"issue-analyst"},
            "commands":{"plan":["plan", "--attempt-id", attempt.attempt_id, "--findings", "<findings.json>"]}
        })
    } else {
        json!({
            "kind":"setup_required", "summary":"Resolve the Replay execution error, then retry.",
            "commands":{"run":["run"]}
        })
    }
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
