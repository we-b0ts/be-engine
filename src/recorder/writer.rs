use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{Result, anyhow};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::warn;
use uuid::Uuid;

use super::dependencies::{case_dependency_filename, dependency_line, global_dependency_filename};
use super::jsonl::{BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool};
use super::summary::should_append_case_dependency;
use crate::active_case::DependencyTargets;
use crate::config::{BackgroundDependencyResponseRole, TrafficJsonlMode};

use super::{CaseContext, RecorderEvent, should_write_traffic_event};

type WriterAck = oneshot::Sender<std::result::Result<(), String>>;

pub(super) struct RecordEnvelope {
    pub(super) event: RecorderEvent,
    pub(super) targets: DependencyTargets,
    pub(super) background_rule: Option<(String, BackgroundDependencyResponseRole)>,
}

enum WriterCommand {
    Record(RecordEnvelope),
    RecordTraffic(RecorderEvent),
    AppendCase {
        case: CaseContext,
        event: RecorderEvent,
        matched_by: String,
        ack: WriterAck,
    },
    AppendGlobal {
        event: RecorderEvent,
        reason: String,
        phase: String,
        matched_by: String,
        ack: WriterAck,
    },
    FlushTraffic {
        ack: WriterAck,
    },
    FlushCase {
        dir: PathBuf,
        ack: WriterAck,
    },
    FlushGlobal {
        ack: WriterAck,
    },
    FlushAll {
        ack: WriterAck,
    },
}

#[derive(Clone)]
pub(super) struct RecorderWriter {
    sender: mpsc::Sender<Box<WriterCommand>>,
    failure: Arc<StdMutex<Option<String>>>,
}

struct WriterState {
    traffic_jsonl: TrafficJsonlMode,
    traffic_file: Option<BufferedJsonlWriter>,
    dependency_files: JsonlWriterPool,
    run_dir: Arc<PathBuf>,
    finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
}

impl RecorderWriter {
    pub(super) async fn start(
        run_dir: Arc<PathBuf>,
        traffic_jsonl: TrafficJsonlMode,
        settings: JsonlBufferSettings,
        queue_capacity: usize,
        finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
    ) -> Result<Self> {
        let traffic_file = if traffic_jsonl == TrafficJsonlMode::Off {
            None
        } else {
            Some(BufferedJsonlWriter::open(&run_dir.join("traffic.jsonl"), settings).await?)
        };
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let failure = Arc::new(StdMutex::new(None));
        let state = WriterState {
            traffic_jsonl,
            traffic_file,
            dependency_files: JsonlWriterPool::new(settings),
            run_dir,
            finalized_cases,
        };
        tokio::spawn(run_writer(
            receiver,
            state,
            settings.flush_interval,
            failure.clone(),
        ));
        Ok(Self { sender, failure })
    }

    pub(super) fn try_record(&self, envelope: RecordEnvelope) -> Result<()> {
        self.try_send(
            WriterCommand::Record(envelope),
            "recording writer queue is full",
        )
    }

    pub(super) fn try_record_traffic(&self, event: RecorderEvent) -> Result<()> {
        self.try_send(
            WriterCommand::RecordTraffic(event),
            "recording writer queue is full",
        )
    }

    fn try_send(&self, command: WriterCommand, full_message: &'static str) -> Result<()> {
        match self.sender.try_send(Box::new(command)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.mark_failed(full_message.to_string());
                Err(anyhow!(full_message))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let message = "recording writer task is closed".to_string();
                self.mark_failed(message.clone());
                Err(anyhow!(message))
            }
        }
    }

    pub(super) async fn append_case(
        &self,
        case: CaseContext,
        event: RecorderEvent,
        matched_by: &str,
    ) -> Result<()> {
        self.request(|ack| WriterCommand::AppendCase {
            case,
            event,
            matched_by: matched_by.to_string(),
            ack,
        })
        .await
    }

    pub(super) async fn append_global(
        &self,
        event: RecorderEvent,
        reason: &str,
        phase: &str,
        matched_by: &str,
    ) -> Result<()> {
        self.request(|ack| WriterCommand::AppendGlobal {
            event,
            reason: reason.to_string(),
            phase: phase.to_string(),
            matched_by: matched_by.to_string(),
            ack,
        })
        .await
    }

    pub(super) async fn flush_traffic(&self) -> Result<()> {
        self.request(|ack| WriterCommand::FlushTraffic { ack })
            .await
    }

    pub(super) async fn flush_case(&self, dir: &Path) -> Result<()> {
        let dir = dir.to_path_buf();
        self.request(|ack| WriterCommand::FlushCase { dir, ack })
            .await
    }

    pub(super) async fn flush_global(&self) -> Result<()> {
        self.request(|ack| WriterCommand::FlushGlobal { ack }).await
    }

    pub(super) async fn flush_all(&self) -> Result<()> {
        self.request(|ack| WriterCommand::FlushAll { ack }).await
    }

    pub(super) fn ensure_healthy(&self) -> Result<()> {
        let failure = self
            .failure
            .lock()
            .expect("recording writer failure state poisoned");
        match failure.as_deref() {
            Some(message) => Err(anyhow!(message.to_string())),
            None => Ok(()),
        }
    }

    async fn request(&self, build: impl FnOnce(WriterAck) -> WriterCommand) -> Result<()> {
        let (ack, result) = oneshot::channel();
        self.sender
            .send(Box::new(build(ack)))
            .await
            .map_err(|_| anyhow!("recording writer task is closed"))?;
        result
            .await
            .map_err(|_| anyhow!("recording writer task dropped a control response"))?
            .map_err(anyhow::Error::msg)?;
        self.ensure_healthy()
    }

    fn mark_failed(&self, message: String) {
        let mut failure = self
            .failure
            .lock()
            .expect("recording writer failure state poisoned");
        failure.get_or_insert(message);
    }
}

async fn run_writer(
    mut receiver: mpsc::Receiver<Box<WriterCommand>>,
    mut state: WriterState,
    flush_interval: std::time::Duration,
    failure: Arc<StdMutex<Option<String>>>,
) {
    let mut flush = tokio::time::interval_at(Instant::now() + flush_interval, flush_interval);
    flush.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            command = receiver.recv() => {
                let Some(command) = command else {
                    break;
                };
                process_command(*command, &mut state, &failure).await;
            }
            _ = flush.tick() => {
                if let Err(error) = state.flush_open().await {
                    record_failure(&failure, error.to_string());
                    warn!(%error, "failed to periodically flush recording JSONL");
                }
            }
        }
    }
    if let Err(error) = state.flush_all().await {
        record_failure(&failure, error.to_string());
        warn!(%error, "failed to flush recording JSONL after writer shutdown");
    }
}

async fn process_command(
    command: WriterCommand,
    state: &mut WriterState,
    failure: &Arc<StdMutex<Option<String>>>,
) {
    match command {
        WriterCommand::Record(envelope) => {
            if let Err(error) = state.record(envelope).await {
                record_failure(failure, error.to_string());
                warn!(%error, "failed to persist queued recorder event");
            }
        }
        WriterCommand::RecordTraffic(event) => {
            if let Err(error) = state.append_traffic(&event).await {
                record_failure(failure, error.to_string());
                warn!(%error, "failed to persist queued traffic event");
            }
        }
        WriterCommand::AppendCase {
            case,
            event,
            matched_by,
            ack,
        } => {
            acknowledge(
                ack,
                state.append_case(&case, &event, &matched_by).await,
                failure,
            );
        }
        WriterCommand::AppendGlobal {
            event,
            reason,
            phase,
            matched_by,
            ack,
        } => {
            acknowledge(
                ack,
                state
                    .append_global(&event, &reason, &phase, &matched_by, None)
                    .await,
                failure,
            );
        }
        WriterCommand::FlushTraffic { ack } => {
            acknowledge(ack, state.flush_traffic().await, failure);
        }
        WriterCommand::FlushCase { dir, ack } => {
            acknowledge(
                ack,
                state.dependency_files.flush_and_remove_under(&dir).await,
                failure,
            );
        }
        WriterCommand::FlushGlobal { ack } => {
            acknowledge(ack, state.flush_global().await, failure);
        }
        WriterCommand::FlushAll { ack } => {
            acknowledge(ack, state.flush_all().await, failure);
        }
    }
}

fn acknowledge(ack: WriterAck, result: Result<()>, failure: &Arc<StdMutex<Option<String>>>) {
    let result = result.map_err(|error| {
        let message = error.to_string();
        record_failure(failure, message.clone());
        message
    });
    let _ = ack.send(result);
}

fn record_failure(failure: &Arc<StdMutex<Option<String>>>, message: String) {
    let mut failure = failure
        .lock()
        .expect("recording writer failure state poisoned");
    failure.get_or_insert(message);
}

impl WriterState {
    async fn record(&mut self, envelope: RecordEnvelope) -> Result<()> {
        let RecordEnvelope {
            event,
            targets,
            background_rule,
        } = envelope;
        self.append_traffic(&event).await?;
        if !should_append_case_dependency(&event) {
            return Ok(());
        }
        if let Some((rule_name, response_role)) = background_rule {
            self.append_global(
                &event,
                "background_rule",
                if targets.bootstrap_open {
                    "bootstrap"
                } else {
                    "runtime"
                },
                &rule_name,
                Some(response_role),
            )
            .await?;
            return Ok(());
        }
        if targets.bootstrap_open {
            self.append_global(
                &event,
                "bootstrap_window",
                "bootstrap",
                "bootstrap_window",
                None,
            )
            .await?;
        }
        if targets.ambiguous_active_cases > 0 {
            warn!(
                active_cases = targets.ambiguous_active_cases,
                event_type = event.kind(),
                "skipping case dependency because active case ownership is ambiguous"
            );
        }
        for (case, matched_by) in &targets.cases {
            self.append_case(case, &event, matched_by).await?;
        }
        Ok(())
    }

    async fn append_traffic(&mut self, event: &RecorderEvent) -> Result<()> {
        if !should_write_traffic_event(self.traffic_jsonl, event) {
            return Ok(());
        }
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        if let Some(file) = self.traffic_file.as_mut() {
            file.append(&line).await?;
        }
        Ok(())
    }

    async fn append_case(
        &mut self,
        case: &CaseContext,
        event: &RecorderEvent,
        matched_by: &str,
    ) -> Result<()> {
        if !should_append_case_dependency(event)
            || self.finalized_cases.lock().await.contains(&case.id)
        {
            return Ok(());
        }
        let dir = case_staging_dir(&self.run_dir, case);
        let path = dir.join(case_dependency_filename(event));
        let line = dependency_line(event, "case_dependency_matched_by", matched_by)?;
        self.dependency_files.append(&path, &line).await
    }

    async fn append_global(
        &mut self,
        event: &RecorderEvent,
        reason: &str,
        phase: &str,
        matched_by: &str,
        response_role: Option<BackgroundDependencyResponseRole>,
    ) -> Result<()> {
        if !should_append_case_dependency(event) {
            return Ok(());
        }
        let path = self.run_dir.join(global_dependency_filename(event));
        let line = global_dependency_line(event, reason, phase, matched_by, response_role)?;
        self.dependency_files.append(&path, &line).await
    }

    async fn flush_traffic(&mut self) -> Result<()> {
        if let Some(file) = self.traffic_file.as_mut() {
            file.flush().await?;
        }
        Ok(())
    }

    async fn flush_global(&mut self) -> Result<()> {
        let semantic = self.run_dir.join("global-dependencies.jsonl");
        let debug = self.run_dir.join("global-dependencies-debug.jsonl");
        self.dependency_files.flush_and_remove(&semantic).await?;
        self.dependency_files.flush_and_remove(&debug).await
    }

    async fn flush_open(&mut self) -> Result<()> {
        self.flush_traffic().await?;
        self.dependency_files.flush_open().await
    }

    async fn flush_all(&mut self) -> Result<()> {
        self.flush_traffic().await?;
        self.dependency_files.flush_all().await
    }
}

fn global_dependency_line(
    event: &RecorderEvent,
    reason: &str,
    phase: &str,
    matched_by: &str,
    response_role: Option<BackgroundDependencyResponseRole>,
) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(event)?;
    if let serde_json::Value::Object(object) = &mut value {
        object.insert(
            "global_dependency_reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
        object.insert(
            "global_dependency_phase".to_string(),
            serde_json::Value::String(phase.to_string()),
        );
        object.insert(
            "global_dependency_matched_by".to_string(),
            serde_json::Value::String(matched_by.to_string()),
        );
        if let Some(response_role) = response_role {
            object.insert(
                "global_dependency_response_role".to_string(),
                serde_json::Value::String(response_role.as_str().to_string()),
            );
        }
    }
    let mut line = serde_json::to_vec(&value)?;
    line.push(b'\n');
    Ok(line)
}

fn case_staging_dir(run_dir: &Path, case: &CaseContext) -> PathBuf {
    let mut path = run_dir
        .join("staging")
        .join(super::sanitize_path_component(&case.rule_name));
    if let Some(uri_group) = &case.uri_group {
        path = path.join(super::sanitize_path_component(uri_group));
    }
    path.join(case.id.to_string())
}
