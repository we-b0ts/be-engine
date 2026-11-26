use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;
use traffic_e2e::session;

mod status;
mod target;
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
    /// Switch the active recording on this Target branch without starting Replay.
    SwitchRecordingId {
        /// ID of the sealed Source recording.
        #[arg(value_name = "ID", conflicts_with = "recording_run_id")]
        recording_id: String,
    },
    /// Read the current or specified Source Replay attempt.
    Status {
        /// Select attempts recorded under a custom run key.
        #[arg(long)]
        run_key: Option<String>,
        /// Read one attempt by its UUID.
        #[arg(long)]
        attempt_id: Option<uuid::Uuid>,
        /// Include scopes, sequences and API work in the current assignments.
        #[arg(long)]
        with_assignments: bool,
    },
    /// List the recorded APIs, case patterns, groups and first Source sequences.
    Apis {
        /// Show only recorded labels without a case pattern and group.
        #[arg(long)]
        ungrouped: bool,
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
        /// UUID of a Replay attempt for the active recording.
        #[arg(long, required_unless_present = "report", conflicts_with = "report")]
        attempt: Option<uuid::Uuid>,
        /// Path to an explicitly supplied Replay report.
        #[arg(long)]
        report: Option<PathBuf>,
        observation_id: uuid::Uuid,
    },
    /// Submit the registered issue analyst's API groupings or event ownership.
    Plan {
        /// JSON findings with the current task_id and agent_handle.
        #[arg(long)]
        findings: PathBuf,
        /// Set the maximum active implementers for this round (default 16).
        #[arg(long)]
        max_implementers: Option<usize>,
    },
    /// Register agent dispatches, worker states, or deliveries.
    Report {
        /// JSON registration or delivery receipt.
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
        SourceCommand::SwitchRecordingId { recording_id } => {
            workflow::switch_recording(&target_root, &recording_id, pretty)
        }
        SourceCommand::Status {
            run_key,
            attempt_id,
            with_assignments,
        } => status::show(
            &target_root,
            id,
            run_key.as_deref(),
            attempt_id,
            with_assignments,
            pretty,
        ),
        SourceCommand::Apis { ungrouped } => {
            let recording = workflow::evidence_recording(&target_root, id)?;
            let mut apis = session::recorded_apis(&target_root, &recording.root)?;
            if ungrouped {
                apis.retain(|api| api.group.is_none());
            }
            super::print_json(
                &serde_json::json!({"recording_id": recording.id, "apis": apis}),
                pretty,
            )
        }
        SourceCommand::Plan {
            findings,
            max_implementers,
        } => workflow::plan(&target_root, id, &findings, max_implementers, pretty),
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
            attempt,
            report,
            observation_id,
        } => super::print_json(
            &target::observation(&target_root, id, attempt, report, observation_id)?,
            pretty,
        ),
    }
}
