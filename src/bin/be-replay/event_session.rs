use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;
use serde_json::{Value, json};
use traffic_e2e::{E2eEventSessionResult, session};

mod workflow;

#[derive(Debug, Subcommand)]
pub(super) enum SourceCommand {
    /// Replay all events and publish API counts after successful verification.
    Run {
        /// Confirm that the user approved starting a new regression from pr_base.
        #[arg(long)]
        user_confirm: bool,
        /// Name the runtime scope when starting a round.
        #[arg(long)]
        run_key: Option<String>,
    },
    /// Read the current or specified Source Replay attempt.
    Status {
        /// Select attempts recorded under a custom run key.
        #[arg(long)]
        run_key: Option<String>,
        /// Read one attempt by its UUID.
        #[arg(long)]
        attempt_id: Option<uuid::Uuid>,
    },
    /// Read a bounded page of the Source timeline.
    Events {
        #[arg(long, default_value_t = 0)]
        from_seq: u64,
        #[arg(long, default_value_t = 0)]
        after_seq: u64,
        /// Limit the page series to this many seconds of original Source time.
        #[arg(long)]
        window_seconds: Option<u64>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Show an exact sequence, including a push event. Repeat to select several.
        #[arg(long = "seq")]
        sequences: Vec<u64>,
        /// Include protected primary request and response payloads.
        #[arg(long)]
        payload: bool,
        /// Include push notifications and their delivery events in timeline pages.
        #[arg(long)]
        with_push_event: bool,
    },
    /// Inspect one protected dependency exchange by its admission sequence.
    Dependency { sequence: u64 },
    /// Inspect a protected Target observation from the failed attempt.
    Target {
        #[arg(long)]
        report: PathBuf,
        observation_id: uuid::Uuid,
    },
    /// Group analysis findings and select independent work for implementers.
    Plan {
        /// JSON array of findings returned by the analysis workers.
        #[arg(long)]
        findings: PathBuf,
        /// Maximum implementers to assign in this plan.
        #[arg(long, default_value_t = 16)]
        max_implementers: usize,
        /// Require the latest failed attempt to have this identity.
        #[arg(long)]
        attempt_id: Option<uuid::Uuid>,
    },
    /// Register accepted implementation fixes or the published integration candidate.
    Report {
        /// JSON delivery receipt.
        #[arg(long)]
        file: PathBuf,
    },
}

pub(super) async fn run(
    target_root: PathBuf,
    recording_run_id: Option<String>,
    command: SourceCommand,
    pretty: bool,
) -> Result<()> {
    let id = recording_run_id.as_deref();
    match command {
        SourceCommand::Run {
            user_confirm,
            run_key,
        } => workflow::replay(&target_root, id, user_confirm, run_key, pretty).await,
        SourceCommand::Status {
            run_key,
            attempt_id,
        } => workflow::status(&target_root, id, run_key.as_deref(), attempt_id, pretty),
        SourceCommand::Plan {
            findings,
            max_implementers,
            attempt_id,
        } => workflow::plan(
            &target_root,
            id,
            &findings,
            max_implementers,
            attempt_id,
            pretty,
        ),
        SourceCommand::Report { file } => workflow::report(&target_root, id, &file, pretty),
        SourceCommand::Events {
            from_seq,
            after_seq,
            window_seconds,
            limit,
            payload,
            with_push_event,
            sequences,
        } => {
            let recording = workflow::evidence_recording(&target_root, id)?;
            let page = session::events(
                &recording.root,
                session::SessionEventQuery {
                    from_sequence: from_seq,
                    after_sequence: after_seq,
                    window_ms: window_seconds.map(|seconds| seconds.saturating_mul(1000)),
                    limit,
                    payload,
                    with_push_event,
                    selected: sequences.into_iter().collect(),
                },
            )?;
            super::print_json(&page, pretty)
        }
        SourceCommand::Dependency { sequence } => {
            let recording = workflow::evidence_recording(&target_root, id)?;
            super::print_json(&session::dependency(&recording.root, sequence)?, pretty)
        }
        SourceCommand::Target {
            report,
            observation_id,
        } => {
            let recording = workflow::evidence_recording(&target_root, id)?;
            super::print_json(
                &session::target_observation(&recording.root, &report, observation_id)?,
                pretty,
            )
        }
    }
}

fn failure_action(id: &str, result: &E2eEventSessionResult) -> Value {
    if result.events.failure.is_none() || result.events.complete {
        return json!({
            "action": "inspect_session_setup",
            "description": result.error,
            "report": result.report.is_file().then_some(&result.report),
            "run": ["run"],
        });
    }
    let expected = result.events.expected.as_ref();
    let sequence = expected
        .and_then(|event| event["sequence"].as_u64())
        .or(result.events.last_sequence)
        .unwrap_or(0);
    let dependency = expected
        .and_then(|event| event["dependency_sequence"].as_u64())
        .filter(|value| *value > 0)
        .map(|value| json!(["dependency", "--recording-run-id", id, value.to_string()]));
    let observed = result
        .events
        .failure
        .as_ref()
        .and_then(|failure| failure["target_observation_id"].as_str())
        .map(|observation| {
            json!([
                "target",
                "--recording-run-id",
                id,
                "--report",
                result.report,
                observation,
            ])
        });
    json!({
        "action": "analyze_session_failure",
        "description": result.error,
        "expected_sequence": sequence,
        "event": (sequence > 0).then(|| json!(["events", "--recording-run-id", id,
            "--seq", sequence.to_string()])),
        "events": ["events", "--recording-run-id", id,
            "--from-seq", sequence.to_string(), "--window-seconds", "60"],
        "dependency": dependency,
        "target": observed,
        "plan": ["plan", "--recording-run-id", id, "--attempt-id", result.attempt_id, "--findings", "<findings.json>"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use traffic_e2e::E2eEventSessionProgress;
    use uuid::Uuid;

    const RECORDING: &str = "20261125131020";

    fn attempt() -> E2eEventSessionResult {
        E2eEventSessionResult {
            run_key: "custom".into(),
            attempt_id: Uuid::from_u128(1).simple().to_string(),
            recording_root: "/recording".into(),
            target_commit: None,
            target_inputs: None,
            target_image_id: None,
            passed: false,
            events: E2eEventSessionProgress {
                total: 20,
                matched: 7,
                last_sequence: Some(8),
                expected: Some(json!({"sequence": 10, "dependency_sequence": 9})),
                failure: Some(json!({"target_observation_id": Uuid::from_u128(2)})),
                ..Default::default()
            },
            error: Some("test mismatch".into()),
            progress: "/progress.json".into(),
            report: "/report.json".into(),
        }
    }

    fn check_command(action: &Value, field: &str, command: &str) {
        let words = action[field].as_array().unwrap();
        assert_eq!(words[0], command);
        let argv = std::iter::once("test").chain(words.iter().map(|word| word.as_str().unwrap()));
        let parsed = crate::Cli::try_parse_from(argv).unwrap();
        assert_eq!(parsed.recording_run_id.as_deref(), Some(RECORDING));
    }

    #[test]
    fn failed_attempt_emits_flat_evidence_commands() {
        let action = failure_action(RECORDING, &attempt());
        assert_eq!(action["expected_sequence"], 10);
        for command in ["events", "dependency", "target", "plan"] {
            check_command(&action, command, command);
        }
        check_command(&action, "event", "events");
        assert_eq!(action["event"][3], "--seq");
        assert_eq!(action["event"][4], "10");
        assert_eq!(action["dependency"][3], "9");
        assert_eq!(action["target"][4], "/report.json");
    }

    #[test]
    fn a_setup_error_with_a_compiled_plan_does_not_dispatch_analysis() {
        let mut failed = attempt();
        failed.events.failure = None;
        assert_eq!(
            failure_action(RECORDING, &failed)["action"],
            "inspect_session_setup"
        );
    }
}
