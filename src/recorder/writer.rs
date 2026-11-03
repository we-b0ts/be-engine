use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{Result, anyhow};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::warn;
use uuid::Uuid;

use super::jsonl::{BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool};
use super::summary::{SourceProcessTrafficSummaryBuilder, should_append_case_dependency};
use crate::active_case::DependencyTargets;
use crate::config::TrafficJsonlMode;
use crate::dependency::attribution::DependencyOwner;
use crate::dependency::observation::{CaptureCoverage, SourceArtifactIdentity};

use super::{CaseContext, RecorderEvent, should_write_traffic_event};

type WriterAck = oneshot::Sender<std::result::Result<(), String>>;

pub(super) struct RecordEnvelope {
    pub(super) event: RecorderEvent,
    pub(super) targets: DependencyTargets,
    pub(super) global_attribution: Option<super::GlobalDependencyAttribution>,
    pub(super) suppress_default_global: bool,
}

enum WriterCommand {
    CapturePolicyIdentity {
        identity: String,
        process_dependency_tasks: std::collections::BTreeMap<String, String>,
        ack: WriterAck,
    },
    SourceArtifactIdentity {
        identity: SourceArtifactIdentity,
        ack: WriterAck,
    },
    Lifecycle(super::ledger::LifecycleRecord),
    RegisterInput {
        case_id: Uuid,
        path: String,
        complete: bool,
        ack: WriterAck,
    },
    Seal {
        coverage: CaptureCoverage,
        ack: WriterAck,
    },
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
    #[cfg(test)]
    pub(super) completion: Arc<tokio::sync::Notify>,
}

struct WriterState {
    traffic_jsonl: TrafficJsonlMode,
    traffic_file: Option<BufferedJsonlWriter>,
    dependency_files: JsonlWriterPool,
    run_dir: Arc<PathBuf>,
    finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
    source_process_traffic: SourceProcessTrafficSummaryBuilder,
    ledger: super::ledger::persistence::LedgerWriter,
}

impl RecorderWriter {
    pub(super) async fn start(
        run_dir: Arc<PathBuf>,
        traffic_jsonl: TrafficJsonlMode,
        settings: JsonlBufferSettings,
        queue_capacity: usize,
        finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
        process_epoch: Uuid,
        capture_policy_identity: String,
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
            run_dir: run_dir.clone(),
            finalized_cases,
            source_process_traffic: SourceProcessTrafficSummaryBuilder::default(),
            ledger: super::ledger::persistence::LedgerWriter::new(
                &run_dir,
                process_epoch,
                capture_policy_identity,
            ),
        };
        super::storage::write(&run_dir.join("dependencies.jsonl"), b"").await?;
        super::storage::write(&run_dir.join("dependency-lifecycle.jsonl"), b"").await?;
        #[cfg(test)]
        let completion = Arc::new(tokio::sync::Notify::new());
        #[cfg(test)]
        let completed = completion.clone();
        let writer_failure = failure.clone();
        tokio::spawn(async move {
            run_writer(receiver, state, settings.flush_interval, writer_failure).await;
            #[cfg(test)]
            completed.notify_one();
        });
        Ok(Self {
            sender,
            failure,
            #[cfg(test)]
            completion,
        })
    }

    pub(super) async fn set_capture_policy_identity(
        &self,
        identity: String,
        process_dependency_tasks: std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        self.request(|ack| WriterCommand::CapturePolicyIdentity {
            identity,
            process_dependency_tasks,
            ack,
        })
        .await
    }

    pub(super) async fn set_source_artifact_identity(
        &self,
        identity: SourceArtifactIdentity,
    ) -> Result<()> {
        self.request(|ack| WriterCommand::SourceArtifactIdentity { identity, ack })
            .await
    }

    pub(super) fn try_record(&self, envelope: RecordEnvelope) -> Result<()> {
        self.try_send(
            WriterCommand::Record(envelope),
            "recording writer queue is full",
        )
    }

    pub(super) fn try_record_lifecycle(
        &self,
        record: super::ledger::LifecycleRecord,
    ) -> Result<()> {
        self.try_send(
            WriterCommand::Lifecycle(record),
            "recording lifecycle queue is full",
        )
    }

    pub(super) async fn register_input(
        &self,
        case_id: Uuid,
        path: String,
        complete: bool,
    ) -> Result<()> {
        self.request(|ack| WriterCommand::RegisterInput {
            case_id,
            path,
            complete,
            ack,
        })
        .await
    }

    pub(super) async fn seal(&self, coverage: CaptureCoverage) -> Result<()> {
        let (ack, result) = oneshot::channel();
        self.sender
            .send(Box::new(WriterCommand::Seal { coverage, ack }))
            .await
            .map_err(|_| anyhow!("recording writer task is closed before sealing"))?;
        result
            .await
            .map_err(|_| anyhow!("recording seal response was dropped"))?
            .map_err(anyhow::Error::msg)
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
        WriterCommand::Lifecycle(record) => {
            if let Err(error) = state
                .ledger
                .lifecycle(&mut state.dependency_files, &record)
                .await
            {
                record_failure(failure, error.to_string());
                warn!(%error,"failed to persist request capture lifecycle");
            }
        }
        WriterCommand::CapturePolicyIdentity {
            identity,
            process_dependency_tasks,
            ack,
        } => {
            state
                .ledger
                .set_capture_policy_identity(identity, process_dependency_tasks);
            acknowledge(ack, Ok(()), failure);
        }
        WriterCommand::SourceArtifactIdentity { identity, ack } => {
            state.ledger.set_source_artifact_identity(identity);
            acknowledge(ack, Ok(()), failure);
        }
        WriterCommand::RegisterInput {
            case_id,
            path,
            complete,
            ack,
        } => {
            state.ledger.register_input(case_id, path, complete);
            acknowledge(ack, Ok(()), failure);
        }
        WriterCommand::Seal { coverage, ack } => {
            let healthy = failure
                .lock()
                .expect("recording failure poisoned")
                .is_none();
            acknowledge(
                ack,
                state
                    .ledger
                    .seal(&mut state.dependency_files, coverage, healthy)
                    .await,
                failure,
            );
        }
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
                    .append_global(&event, &reason, &phase, &matched_by)
                    .await,
                failure,
            );
        }
        WriterCommand::FlushTraffic { ack } => {
            acknowledge(ack, state.flush_traffic().await, failure);
        }
        WriterCommand::FlushCase { dir, ack } => {
            let result = async {
                state.dependency_files.flush_all().await?;
                state.ledger.case_scope(&dir).await
            }
            .await;
            acknowledge(ack, result, failure);
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
            global_attribution,
            suppress_default_global,
        } = envelope;
        self.append_traffic(&event).await?;
        self.ledger
            .append(
                &mut self.dependency_files,
                &event,
                Some(&targets),
                None,
                global_attribution.as_ref(),
            )
            .await?;
        if !should_append_case_dependency(&event) {
            if let Some(attribution) = global_attribution.as_ref() {
                self.source_process_traffic.observe(
                    &event,
                    attribution.reason,
                    attribution.phase,
                    &attribution.matched_by,
                );
            } else if targets.bootstrap_open && !suppress_default_global {
                self.source_process_traffic.observe(
                    &event,
                    "bootstrap_window",
                    "bootstrap",
                    "bootstrap_window",
                );
            }
            return Ok(());
        }
        if let Some(attribution) = global_attribution {
            self.source_process_traffic.observe(
                &event,
                attribution.reason,
                attribution.phase,
                &attribution.matched_by,
            );
            return Ok(());
        }
        if targets.bootstrap_open && !suppress_default_global {
            self.source_process_traffic.observe(
                &event,
                "bootstrap_window",
                "bootstrap",
                "bootstrap_window",
            );
        }
        if targets.ambiguous_active_cases > 0 {
            warn!(
                active_cases = targets.ambiguous_active_cases,
                event_type = event.kind(),
                "dependency retained as unattributed because active case ownership is ambiguous"
            );
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
        _matched_by: &str,
    ) -> Result<()> {
        if self.finalized_cases.lock().await.contains(&case.id) {
            return Ok(());
        }
        self.ledger
            .append(
                &mut self.dependency_files,
                event,
                None,
                Some(DependencyOwner::Case {
                    origin_case_id: case.id,
                    task_instance: None,
                }),
                None,
            )
            .await
    }

    async fn append_global(
        &mut self,
        event: &RecorderEvent,
        reason: &str,
        phase: &str,
        matched_by: &str,
    ) -> Result<()> {
        self.source_process_traffic
            .observe(event, reason, phase, matched_by);
        self.ledger
            .append(
                &mut self.dependency_files,
                event,
                None,
                None,
                Some(&super::GlobalDependencyAttribution {
                    reason: if reason == "background_rule" {
                        "background_rule"
                    } else if reason == "preflight_probe" {
                        "preflight_probe"
                    } else if phase == "bootstrap" {
                        "bootstrap_window"
                    } else {
                        "unclassified_global"
                    },
                    phase: if phase == "bootstrap" {
                        "bootstrap"
                    } else {
                        "runtime"
                    },
                    matched_by: matched_by.into(),
                }),
            )
            .await
    }

    async fn flush_traffic(&mut self) -> Result<()> {
        if let Some(file) = self.traffic_file.as_mut() {
            file.flush().await?;
        }
        Ok(())
    }

    async fn flush_global(&mut self) -> Result<()> {
        self.dependency_files.flush_all().await?;
        self.ledger.global_scopes().await?;
        self.source_process_traffic.write(&self.run_dir).await
    }

    async fn flush_open(&mut self) -> Result<()> {
        self.flush_traffic().await?;
        self.dependency_files.flush_open().await
    }

    async fn flush_all(&mut self) -> Result<()> {
        self.flush_traffic().await?;
        self.dependency_files.flush_all().await?;
        self.ledger.global_scopes().await?;
        self.source_process_traffic.write(&self.run_dir).await
    }
}

#[cfg(test)]
#[path = "writer/tests.rs"]
mod tests;
