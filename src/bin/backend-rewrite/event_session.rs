use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use traffic_e2e::{
    E2eEventSessionOptions, E2eEventSessionResult, config::regression::SessionRegression,
    repository::LOCAL_ARTIFACTS_ROOT, run_e2e_event_session, session,
};

#[derive(Debug, Args)]
pub(super) struct SessionArgs {
    /// Override the source recording selected in .traffic-e2e/regression.yaml.
    #[arg(long, global = true)]
    recording_run_id: Option<String>,
    #[command(subcommand)]
    command: SessionCommand,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// Replay all events and publish API counts after successful verification.
    Run {
        #[arg(long)]
        run_key: Option<String>,
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
        /// Show only this event sequence. Repeat for a reviewed finding.
        #[arg(long = "seq")]
        sequences: Vec<u64>,
        /// Include protected primary request and response payloads.
        #[arg(long)]
        payload: bool,
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
    },
}

pub(super) async fn run(target_root: PathBuf, args: SessionArgs, pretty: bool) -> Result<()> {
    let target_root = target_root.canonicalize()?;
    let scope = SessionRegression::load(&target_root)?;
    let id = args
        .recording_run_id
        .or(scope.recording_run_id)
        .context("set recording_run_id in .traffic-e2e/regression.yaml")?;
    let recording_root = resolve_recording(&target_root, &id)?;
    match args.command {
        SessionCommand::Run { run_key } => {
            let result = run_e2e_event_session(E2eEventSessionOptions {
                target_root: target_root.clone(),
                recording_root: recording_root.clone(),
                run_key,
            })
            .await?;
            let apis =
                session::api_counts(&target_root, &recording_root, result.events.last_sequence)?;
            let progress_published = if result.passed {
                session::publish_passed_progress(&target_root, &recording_root, &apis)?
            } else {
                false
            };
            let next =
                (!result.passed).then(|| failure_action(&id, &result, scope.max_implementers));
            super::print_json(
                &json!({
                    "recording_id": id, "session": result, "apis": apis,
                    "progress_published": progress_published, "next": next,
                }),
                pretty,
            )?;
            ensure!(result.passed, "Source session Replay failed");
            Ok(())
        }
        SessionCommand::Events {
            from_seq,
            after_seq,
            window_seconds,
            limit,
            payload,
            sequences,
        } => {
            let page = session::events(
                &recording_root,
                from_seq,
                after_seq,
                window_seconds.map(|seconds| seconds.saturating_mul(1000)),
                limit,
                payload,
                &sequences.into_iter().collect::<BTreeSet<_>>(),
            )?;
            super::print_json(&page, pretty)
        }
        SessionCommand::Dependency { sequence } => {
            super::print_json(&session::dependency(&recording_root, sequence)?, pretty)
        }
        SessionCommand::Target {
            report,
            observation_id,
        } => super::print_json(
            &session::target_observation(&recording_root, &report, observation_id)?,
            pretty,
        ),
        SessionCommand::Plan { findings } => {
            let findings: Vec<traffic_e2e::event_work::Finding> =
                serde_json::from_slice(&std::fs::read(&findings)?)
                    .context("parse event findings")?;
            let dispatch = traffic_e2e::event_work::plan(findings, scope.max_implementers)?;
            super::print_json(&dispatch, pretty)
        }
    }
}

fn failure_action(id: &str, result: &E2eEventSessionResult, max_implementers: usize) -> Value {
    if result.events.total == 0 {
        return json!({"action": "inspect_session_setup", "report": result.report});
    }
    let expected = result.events.expected.as_ref();
    let sequence = expected
        .and_then(|event| event["sequence"].as_u64())
        .or(result.events.last_sequence)
        .unwrap_or(0);
    let dependency = expected
        .and_then(|event| event["dependency_sequence"].as_u64())
        .filter(|value| *value > 0)
        .map(|value| {
            json!([
                "session",
                "--recording-run-id",
                id,
                "dependency",
                value.to_string()
            ])
        });
    let observed = result
        .events
        .failure
        .as_ref()
        .and_then(|failure| failure["target_observation_id"].as_str())
        .map(|observation| {
            json!([
                "session",
                "--recording-run-id",
                id,
                "target",
                "--report",
                result.report,
                observation,
            ])
        });
    json!({
        "action": "analyze_session_failure",
        "description": result.error,
        "expected_sequence": sequence,
        "max_implementers": max_implementers,
        "events": ["session", "--recording-run-id", id, "events",
            "--from-seq", sequence.to_string(), "--window-seconds", "60"],
        "dependency": dependency,
        "target": observed,
        "plan": ["session", "--recording-run-id", id, "plan", "--findings", "<findings.json>"],
    })
}

fn resolve_recording(target: &Path, id: &str) -> Result<PathBuf> {
    ensure!(
        id.len() == 14 && id.bytes().all(|byte| byte.is_ascii_digit()),
        "recording run ID must contain 14 digits"
    );
    let root = target
        .join(LOCAL_ARTIFACTS_ROOT)
        .join("recordings")
        .join(id);
    ensure!(
        root.is_dir(),
        "recording directory missing: {}",
        root.display()
    );
    Ok(root)
}
