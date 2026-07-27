use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use self::run::{RecorderRunState, new_run_id};
use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::{RecordingAccessPolicy, RecordingConfig, TrafficJsonlMode};
use crate::request_headers::RequestHeaderCapture;

mod artifact_owner;
mod capture;
mod dependencies;
mod event;
pub(crate) mod http;
mod jsonl;
pub(crate) mod kafka;
pub(crate) mod memcached;
pub(crate) mod motan;
pub(crate) mod mysql;
pub(crate) mod redis;
mod run;
mod summary;
mod writer;

pub use artifact_owner::ArtifactOwner;
pub use capture::*;
pub use event::*;

struct RecorderOptions {
    access_policy: RecordingAccessPolicy,
    traffic_jsonl: TrafficJsonlMode,
    buffer_settings: jsonl::JsonlBufferSettings,
    writer_queue_capacity: usize,
    run_id: Option<String>,
    recording_apis: Vec<String>,
    artifact_owner: Option<ArtifactOwner>,
    request_header_capture: RequestHeaderCapture,
}

#[derive(Clone)]
pub struct Recorder {
    artifact_owner: Option<ArtifactOwner>,
    traffic_jsonl: TrafficJsonlMode,
    writer: writer::RecorderWriter,
    pub(crate) run_dir: Arc<PathBuf>,
    pub(crate) run_state: Arc<Mutex<RecorderRunState>>,
    pub(crate) dependency_write_lock: Arc<Mutex<()>>,
    pub(crate) finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
    pub(crate) access_policy: RecordingAccessPolicy,
    request_header_capture: RequestHeaderCapture,
}

impl Recorder {
    pub async fn new(output_dir: impl AsRef<Path>) -> Result<Self> {
        Self::new_with_access_policy(output_dir, RecordingAccessPolicy::Unrestricted).await
    }

    pub(crate) async fn new_with_access_policy(
        output_dir: impl AsRef<Path>,
        access_policy: RecordingAccessPolicy,
    ) -> Result<Self> {
        let defaults = RecordingConfig::default();
        Self::new_with_options(
            output_dir,
            RecorderOptions {
                access_policy,
                traffic_jsonl: defaults.traffic_jsonl,
                buffer_settings: jsonl::JsonlBufferSettings {
                    capacity: defaults.jsonl_buffer_capacity_bytes,
                    flush_interval: Duration::from_millis(defaults.jsonl_flush_interval_ms),
                },
                writer_queue_capacity: defaults.writer_queue_capacity,
                run_id: None,
                recording_apis: Vec::new(),
                artifact_owner: None,
                request_header_capture: RequestHeaderCapture::from_environment(
                    &defaults.encrypt_request_headers,
                    &defaults.redact_headers,
                )?,
            },
        )
        .await
    }

    #[cfg(test)]
    async fn new_with_recording_config_and_run_id(
        config: &RecordingConfig,
        run_id: Option<String>,
    ) -> Result<Self> {
        Self::new_with_recording_config_at_and_run_id(
            config,
            &config.output_dir,
            run_id,
            Vec::new(),
            None,
        )
        .await
    }

    pub(crate) async fn new_with_recording_config_at_and_run_id(
        config: &RecordingConfig,
        output_dir: impl AsRef<Path>,
        run_id: Option<String>,
        recording_apis: Vec<String>,
        artifact_owner: Option<ArtifactOwner>,
    ) -> Result<Self> {
        Self::new_with_options(
            output_dir,
            RecorderOptions {
                access_policy: config.access_policy,
                traffic_jsonl: config.traffic_jsonl,
                buffer_settings: jsonl::JsonlBufferSettings {
                    capacity: config.jsonl_buffer_capacity_bytes,
                    flush_interval: Duration::from_millis(config.jsonl_flush_interval_ms),
                },
                writer_queue_capacity: config.writer_queue_capacity,
                run_id,
                recording_apis,
                artifact_owner,
                request_header_capture: RequestHeaderCapture::from_environment(
                    &config.encrypt_request_headers,
                    &config.redact_headers,
                )?,
            },
        )
        .await
    }

    #[cfg(test)]
    async fn new_with_recording_config(config: &RecordingConfig) -> Result<Self> {
        Self::new_with_recording_config_and_run_id(config, None).await
    }

    async fn new_with_options(
        output_dir: impl AsRef<Path>,
        options: RecorderOptions,
    ) -> Result<Self> {
        let RecorderOptions {
            access_policy,
            traffic_jsonl,
            buffer_settings,
            writer_queue_capacity,
            run_id,
            recording_apis,
            artifact_owner,
            request_header_capture,
        } = options;
        let output_dir = output_dir.as_ref();
        tokio::fs::create_dir_all(output_dir)
            .await
            .with_context(|| format!("failed to create recording dir {}", output_dir.display()))?;
        let run_id = run_id.unwrap_or_else(new_run_id);
        anyhow::ensure!(
            run_id.len() == 14
                && run_id.bytes().all(|byte| byte.is_ascii_digit())
                && NaiveDateTime::parse_from_str(&run_id, "%Y%m%d%H%M%S").is_ok(),
            "recording run ID must be a valid 14-digit UTC timestamp"
        );
        let run_dir = output_dir.join(&run_id);
        tokio::fs::create_dir(&run_dir)
            .await
            .with_context(|| format!("failed to create recording run dir {}", run_dir.display()))?;
        let run_dir = Arc::new(run_dir);
        let finalized_cases = Arc::new(Mutex::new(HashSet::new()));
        let writer = writer::RecorderWriter::start(
            run_dir.clone(),
            traffic_jsonl,
            buffer_settings,
            writer_queue_capacity,
            finalized_cases.clone(),
        )
        .await?;
        let recorder = Self {
            artifact_owner,
            traffic_jsonl,
            writer,
            run_dir,
            run_state: Arc::new(Mutex::new(RecorderRunState {
                run_id,
                recording_apis,
                ..Default::default()
            })),
            dependency_write_lock: Arc::new(Mutex::new(())),
            finalized_cases,
            access_policy,
            request_header_capture,
        };
        recorder.write_run_report("running").await?;
        Ok(recorder)
    }

    pub async fn record(&self, event: RecorderEvent) -> Result<()> {
        if !should_write_traffic_event(self.traffic_jsonl, &event) {
            return Ok(());
        }
        self.writer.try_record_traffic(event)
    }

    pub(crate) fn capture_request_headers(
        &self,
        headers: &hyper::HeaderMap,
    ) -> Result<HeaderMapSnapshot> {
        self.request_header_capture.capture(headers)
    }

    pub(crate) fn try_record_event(
        &self,
        event: RecorderEvent,
        targets: crate::active_case::DependencyTargets,
        background_rule_name: Option<String>,
    ) -> Result<()> {
        self.writer.try_record(writer::RecordEnvelope {
            event,
            targets,
            background_rule_name,
        })
    }

    /// Flush currently buffered run-level `traffic.jsonl` records.
    pub async fn flush_traffic(&self) -> Result<()> {
        self.writer.flush_traffic().await
    }

    pub async fn write_case_json<T: Serialize>(
        &self,
        case: &CaseContext,
        filename: &str,
        value: &T,
    ) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        let path = self.case_staging_dir(case).join(filename);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create case recording dir {}", parent.display())
            })?;
        }
        let mut payload =
            serde_json::to_vec_pretty(value).context("failed to serialize case recording file")?;
        payload.push(b'\n');
        tokio::fs::write(&path, payload)
            .await
            .with_context(|| format!("failed to write case recording file {}", path.display()))
    }
}

pub(super) fn should_write_traffic_event(mode: TrafficJsonlMode, event: &RecorderEvent) -> bool {
    match mode {
        TrafficJsonlMode::Full => true,
        TrafficJsonlMode::Off => false,
        TrafficJsonlMode::Errors => match event {
            RecorderEvent::HttpExchange(event) => {
                event.error.is_some() || event.response_status.is_some_and(|status| status >= 500)
            }
            RecorderEvent::TcpGatewayConnection(event) => event.error.is_some(),
            RecorderEvent::UdpDatagram(event) => event.error.is_some(),
            RecorderEvent::RedisConnection(event) => event.error.is_some(),
            RecorderEvent::MemcachedConnection(event) => event.error.is_some(),
            RecorderEvent::KafkaConnection(event) => event.error.is_some(),
            RecorderEvent::MotanConnection(event) => event.error.is_some(),
            RecorderEvent::MysqlConnection(event) => event.error.is_some(),
            RecorderEvent::MysqlPacket(event) => event.error_code.is_some(),
            RecorderEvent::MysqlResponse(event) => event.error_code.is_some(),
            RecorderEvent::MysqlExchange(event) => event.response.error_code.is_some(),
            RecorderEvent::MotanExchange(event) => {
                event.response_status == "exception" || !event.replay_safe
            }
            RecorderEvent::MysqlTlsRejected(_)
            | RecorderEvent::AccessPolicyAllow(_)
            | RecorderEvent::ReadonlyRejection(_)
            | RecorderEvent::ProxyError(_) => true,
            RecorderEvent::RedisExchange(_)
            | RecorderEvent::MemcachedExchange(_)
            | RecorderEvent::KafkaProduce(_)
            | RecorderEvent::KafkaFetch(_)
            | RecorderEvent::KafkaDelivery(_)
            | RecorderEvent::MysqlQuery(_) => false,
        },
    }
}

pub(crate) fn sanitize_path_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unnamed".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
