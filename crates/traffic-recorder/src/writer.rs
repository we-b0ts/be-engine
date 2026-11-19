use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use crate::{
    RecordingClock,
    clock::{SequenceBatch, recorded},
};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::warn;
use traffic_model::trace::RecordedEvent;
use uuid::Uuid;

use super::jsonl::{BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool};
use crate::CaptureScope;
use crate::TrafficJsonlMode;
use crate::source_process::SourceProcessTrafficSummaryBuilder;
use traffic_model::attribution::DependencyOwner;
use traffic_model::recording::{CaptureCoverage, SourceArtifactIdentity};

use super::{CaseContext, should_write_traffic_event};
use crate::CapturedEvent;
use traffic_protocol::capture::CaptureEvidence;
use traffic_recording_store::writer::RowStamp;

type WriterAck = oneshot::Sender<std::result::Result<(), String>>;

pub struct CaptureOptions {
    pub process_epoch: Uuid,
    pub policy_identity: String,
    pub evidence: Arc<traffic_protocol::evidence::EvidenceRegistry>,
}

pub struct RecordEnvelope {
    pub event: CapturedEvent,
    pub targets: Box<dyn CaptureScope>,
    pub global_attribution: Option<super::GlobalDependencyAttribution>,
    pub suppress_default_global: bool,
}

pub(crate) struct RecordStamps {
    pub start: Option<(RowStamp, DateTime<Utc>)>,
    pub request: Option<RowStamp>,
    pub response: Option<RowStamp>,
    pub terminal: Option<RowStamp>,
}

impl RecordStamps {
    pub(crate) fn allocate(
        batch: &mut SequenceBatch<'_>,
        event: &CapturedEvent,
        captured_message: Option<bool>,
    ) -> Result<Self> {
        let start = captured_message
            .is_none()
            .then(|| Ok::<_, anyhow::Error>((batch.next()?, Utc::now())))
            .transpose()?;
        let facts = event.facts();
        let request = (!facts.debug && captured_message != Some(true))
            .then(|| batch.next())
            .transpose()?;
        let response = (!facts.debug).then(|| batch.next()).transpose()?;
        let terminal = (!facts.debug && start.is_some())
            .then(|| batch.next())
            .transpose()?;
        Ok(Self {
            start,
            request,
            response,
            terminal,
        })
    }
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
    Lifecycle(RecordedEvent<super::ledger::LifecycleRecord>),
    RegisterInput {
        case_id: Uuid,
        path: String,
        complete: bool,
        ack: WriterAck,
    },
    Seal {
        coverage: CaptureCoverage,
        stamp: RowStamp,
        ack: WriterAck,
    },
    Record(RecordEnvelope, RecordStamps),
    RecordTraffic(CapturedEvent),
    AppendCase {
        case: CaseContext,
        event: CapturedEvent,
        matched_by: String,
        stamps: RecordStamps,
        ack: WriterAck,
    },
    AppendGlobal {
        event: CapturedEvent,
        reason: String,
        phase: String,
        matched_by: String,
        stamps: RecordStamps,
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
pub struct RecorderWriter {
    sender: mpsc::Sender<Box<WriterCommand>>,
    failure: Arc<StdMutex<Option<String>>>,
    pub(crate) clock: RecordingClock,
    #[cfg(any(test, feature = "test-support"))]
    pub completion: Arc<tokio::sync::Notify>,
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
    pub async fn start(
        run_dir: Arc<PathBuf>,
        traffic_jsonl: TrafficJsonlMode,
        settings: JsonlBufferSettings,
        queue_capacity: usize,
        finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
        capture: CaptureOptions,
    ) -> Result<Self> {
        let traffic_file = if traffic_jsonl == TrafficJsonlMode::Off {
            None
        } else {
            Some(BufferedJsonlWriter::open(&run_dir.join("traffic.jsonl"), settings).await?)
        };
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let failure = Arc::new(StdMutex::new(None));
        let clock = RecordingClock::default();
        let state = WriterState {
            traffic_jsonl,
            traffic_file,
            dependency_files: JsonlWriterPool::new(settings),
            run_dir: run_dir.clone(),
            finalized_cases,
            source_process_traffic: SourceProcessTrafficSummaryBuilder::new(
                capture.evidence.clone(),
            ),
            ledger: super::ledger::persistence::LedgerWriter::new(
                &run_dir,
                capture.process_epoch,
                capture.policy_identity,
                clock.clone(),
                capture.evidence,
            )
            .await?,
        };
        #[cfg(any(test, feature = "test-support"))]
        let completion = Arc::new(tokio::sync::Notify::new());
        #[cfg(any(test, feature = "test-support"))]
        let completed = completion.clone();
        let writer_failure = failure.clone();
        tokio::spawn(async move {
            run_writer(receiver, state, settings.flush_interval, writer_failure).await;
            #[cfg(any(test, feature = "test-support"))]
            completed.notify_one();
        });
        Ok(Self {
            sender,
            failure,
            clock,
            #[cfg(any(test, feature = "test-support"))]
            completion,
        })
    }

    pub async fn set_capture_policy_identity(
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

    pub async fn set_source_artifact_identity(
        &self,
        identity: SourceArtifactIdentity,
    ) -> Result<()> {
        self.request(|ack| WriterCommand::SourceArtifactIdentity { identity, ack })
            .await
    }

    pub fn try_record(&self, envelope: RecordEnvelope) -> Result<()> {
        let captured_message = envelope
            .targets
            .context()
            .capture
            .map(|capture| capture.is_message());
        let permit = self.try_reserve("recording writer queue is full")?;
        let mut envelope = Some(envelope);
        self.clock.publish(|batch| {
            let record = envelope.as_ref().expect("record ready for publication");
            let stamps = RecordStamps::allocate(batch, &record.event, captured_message)?;
            permit.send(Box::new(WriterCommand::Record(
                envelope.take().expect("stamped record"),
                stamps,
            )));
            Ok(())
        })
    }

    pub fn try_record_lifecycle(&self, record: super::ledger::LifecycleRecord) -> Result<()> {
        self.try_publish_lifecycle(|_| record).map(|_| ())
    }

    pub(crate) fn try_publish_lifecycle(
        &self,
        build: impl FnOnce(u64) -> super::ledger::LifecycleRecord,
    ) -> Result<u64> {
        let permit = self.try_reserve("recording lifecycle queue is full")?;
        self.clock.publish(|batch| {
            let stamp = batch.next()?;
            permit.send(Box::new(WriterCommand::Lifecycle(recorded(
                &stamp,
                build(stamp.sequence),
            ))));
            Ok(stamp.sequence)
        })
    }

    pub async fn register_input(&self, case_id: Uuid, path: String, complete: bool) -> Result<()> {
        self.request(|ack| WriterCommand::RegisterInput {
            case_id,
            path,
            complete,
            ack,
        })
        .await
    }

    pub async fn seal(&self, coverage: CaptureCoverage) -> Result<()> {
        let (ack, result) = oneshot::channel();
        let permit = self
            .sender
            .reserve()
            .await
            .map_err(|_| anyhow!("recording writer task is closed before sealing"))?;
        self.clock.publish(|batch| {
            permit.send(Box::new(WriterCommand::Seal {
                coverage,
                stamp: batch.next()?,
                ack,
            }));
            Ok(())
        })?;
        result
            .await
            .map_err(|_| anyhow!("recording seal response was dropped"))?
            .map_err(anyhow::Error::msg)
    }

    pub fn try_record_traffic(&self, event: impl CaptureEvidence) -> Result<()> {
        let event = CapturedEvent::capture(&event)?;
        self.try_send(
            WriterCommand::RecordTraffic(event),
            "recording writer queue is full",
        )
    }

    fn try_send(&self, command: WriterCommand, full_message: &'static str) -> Result<()> {
        self.try_reserve(full_message)?.send(Box::new(command));
        Ok(())
    }

    fn try_reserve(
        &self,
        full_message: &'static str,
    ) -> Result<mpsc::Permit<'_, Box<WriterCommand>>> {
        match self.sender.try_reserve() {
            Ok(permit) => Ok(permit),
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

    pub async fn append_case(
        &self,
        case: CaseContext,
        event: impl CaptureEvidence,
        matched_by: &str,
    ) -> Result<()> {
        let event = CapturedEvent::capture(&event)?;
        self.request_record(event, |event, stamps, ack| WriterCommand::AppendCase {
            case,
            event,
            matched_by: matched_by.to_string(),
            stamps,
            ack,
        })
        .await
    }

    pub async fn append_global(
        &self,
        event: impl CaptureEvidence,
        reason: &str,
        phase: &str,
        matched_by: &str,
    ) -> Result<()> {
        let event = CapturedEvent::capture(&event)?;
        self.request_record(event, |event, stamps, ack| WriterCommand::AppendGlobal {
            event,
            reason: reason.to_string(),
            phase: phase.to_string(),
            matched_by: matched_by.to_string(),
            stamps,
            ack,
        })
        .await
    }

    pub async fn flush_traffic(&self) -> Result<()> {
        self.request(|ack| WriterCommand::FlushTraffic { ack })
            .await
    }

    pub async fn flush_case(&self, dir: &Path) -> Result<()> {
        let dir = dir.to_path_buf();
        self.request(|ack| WriterCommand::FlushCase { dir, ack })
            .await
    }

    pub async fn flush_global(&self) -> Result<()> {
        self.request(|ack| WriterCommand::FlushGlobal { ack }).await
    }

    pub async fn flush_all(&self) -> Result<()> {
        self.request(|ack| WriterCommand::FlushAll { ack }).await
    }

    pub fn ensure_healthy(&self) -> Result<()> {
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
        self.check_ack(result).await
    }

    async fn request_record(
        &self,
        event: CapturedEvent,
        build: impl FnOnce(CapturedEvent, RecordStamps, WriterAck) -> WriterCommand,
    ) -> Result<()> {
        let (ack, result) = oneshot::channel();
        let permit = self
            .sender
            .reserve()
            .await
            .map_err(|_| anyhow!("recording writer task is closed"))?;
        self.clock.publish(|batch| {
            let stamps = RecordStamps::allocate(batch, &event, None)?;
            permit.send(Box::new(build(event, stamps, ack)));
            Ok(())
        })?;
        self.check_ack(result).await
    }

    async fn check_ack(
        &self,
        result: oneshot::Receiver<std::result::Result<(), String>>,
    ) -> Result<()> {
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
        WriterCommand::Seal {
            coverage,
            stamp,
            ack,
        } => {
            let healthy = failure
                .lock()
                .expect("recording failure poisoned")
                .is_none();
            acknowledge(
                ack,
                state
                    .ledger
                    .seal_stamped(&mut state.dependency_files, coverage, healthy, stamp)
                    .await,
                failure,
            );
        }
        WriterCommand::Record(envelope, stamps) => {
            if let Err(error) = state.record(envelope, stamps).await {
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
            stamps,
            ack,
        } => {
            acknowledge(
                ack,
                state.append_case(&case, event, &matched_by, stamps).await,
                failure,
            );
        }
        WriterCommand::AppendGlobal {
            event,
            reason,
            phase,
            matched_by,
            stamps,
            ack,
        } => {
            acknowledge(
                ack,
                state
                    .append_global(event, &reason, &phase, &matched_by, stamps)
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
    async fn record(&mut self, envelope: RecordEnvelope, stamps: RecordStamps) -> Result<()> {
        let RecordEnvelope {
            event,
            targets,
            global_attribution,
            suppress_default_global,
        } = envelope;
        let targets = targets.context();
        self.append_traffic(&event).await?;
        self.ledger
            .append_stamped(
                &mut self.dependency_files,
                &event,
                Some(&targets),
                None,
                global_attribution.as_ref(),
                stamps,
            )
            .await?;
        if !event.facts().case_dependency {
            if let Some(attribution) = global_attribution.as_ref() {
                self.source_process_traffic.observe(
                    &event,
                    attribution.reason,
                    attribution.phase,
                    &attribution.matched_by,
                )?;
            } else if targets.bootstrap_open && !suppress_default_global {
                self.source_process_traffic.observe(
                    &event,
                    "bootstrap_window",
                    "bootstrap",
                    "bootstrap_window",
                )?;
            }
            return Ok(());
        }
        if let Some(attribution) = global_attribution {
            self.source_process_traffic.observe(
                &event,
                attribution.reason,
                attribution.phase,
                &attribution.matched_by,
            )?;
            return Ok(());
        }
        if targets.bootstrap_open && !suppress_default_global {
            self.source_process_traffic.observe(
                &event,
                "bootstrap_window",
                "bootstrap",
                "bootstrap_window",
            )?;
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

    async fn append_traffic(&mut self, event: &CapturedEvent) -> Result<()> {
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
        event: CapturedEvent,
        _matched_by: &str,
        stamps: RecordStamps,
    ) -> Result<()> {
        if self.finalized_cases.lock().await.contains(&case.id) {
            return Ok(());
        }
        self.ledger
            .append_stamped(
                &mut self.dependency_files,
                &event,
                None,
                Some(DependencyOwner::Case {
                    origin_case_id: case.id,
                    task_instance: None,
                }),
                None,
                stamps,
            )
            .await
    }

    async fn append_global(
        &mut self,
        event: CapturedEvent,
        reason: &str,
        phase: &str,
        matched_by: &str,
        stamps: RecordStamps,
    ) -> Result<()> {
        self.source_process_traffic
            .observe(&event, reason, phase, matched_by)?;
        self.ledger
            .append_stamped(
                &mut self.dependency_files,
                &event,
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
                stamps,
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
        self.source_process_traffic.write(&self.run_dir).await
    }

    async fn flush_open(&mut self) -> Result<()> {
        self.flush_traffic().await?;
        self.dependency_files.flush_open().await
    }

    async fn flush_all(&mut self) -> Result<()> {
        self.flush_traffic().await?;
        self.dependency_files.flush_all().await?;
        self.source_process_traffic.write(&self.run_dir).await
    }
}
