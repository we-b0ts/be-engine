use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use self::run::{RecorderRunState, new_run_id};
use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;

use crate::config::{RecordingAccessPolicy, RecordingConfig, TrafficJsonlMode};

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

pub use capture::*;
pub use event::*;

#[derive(Clone)]
pub struct Recorder {
    traffic_file: Arc<Mutex<Option<jsonl::BufferedJsonlWriter>>>,
    traffic_jsonl: TrafficJsonlMode,
    dependency_files: Arc<Mutex<jsonl::JsonlWriterPool>>,
    pub(crate) run_dir: Arc<PathBuf>,
    pub(crate) run_state: Arc<Mutex<RecorderRunState>>,
    pub(crate) dependency_write_lock: Arc<Mutex<()>>,
    pub(crate) finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
    pub(crate) access_policy: RecordingAccessPolicy,
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
            access_policy,
            defaults.traffic_jsonl,
            jsonl::JsonlBufferSettings {
                capacity: defaults.jsonl_buffer_capacity_bytes,
                flush_interval: Duration::from_millis(defaults.jsonl_flush_interval_ms),
            },
            None,
        )
        .await
    }

    pub(crate) async fn new_with_recording_config_and_run_id(
        config: &RecordingConfig,
        run_id: Option<String>,
    ) -> Result<Self> {
        Self::new_with_options(
            &config.output_dir,
            config.access_policy,
            config.traffic_jsonl,
            jsonl::JsonlBufferSettings {
                capacity: config.jsonl_buffer_capacity_bytes,
                flush_interval: Duration::from_millis(config.jsonl_flush_interval_ms),
            },
            run_id,
        )
        .await
    }

    #[cfg(test)]
    async fn new_with_recording_config(config: &RecordingConfig) -> Result<Self> {
        Self::new_with_recording_config_and_run_id(config, None).await
    }

    async fn new_with_options(
        output_dir: impl AsRef<Path>,
        access_policy: RecordingAccessPolicy,
        traffic_jsonl: TrafficJsonlMode,
        buffer_settings: jsonl::JsonlBufferSettings,
        run_id: Option<String>,
    ) -> Result<Self> {
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
        let traffic_file = if traffic_jsonl == TrafficJsonlMode::Off {
            None
        } else {
            Some(
                jsonl::BufferedJsonlWriter::open(&run_dir.join("traffic.jsonl"), buffer_settings)
                    .await?,
            )
        };
        let recorder = Self {
            traffic_file: Arc::new(Mutex::new(traffic_file)),
            traffic_jsonl,
            dependency_files: Arc::new(Mutex::new(jsonl::JsonlWriterPool::new(buffer_settings))),
            run_dir: Arc::new(run_dir),
            run_state: Arc::new(Mutex::new(RecorderRunState {
                run_id,
                ..Default::default()
            })),
            dependency_write_lock: Arc::new(Mutex::new(())),
            finalized_cases: Arc::new(Mutex::new(HashSet::new())),
            access_policy,
        };
        spawn_jsonl_flush_task(
            &recorder.traffic_file,
            &recorder.dependency_files,
            buffer_settings.flush_interval,
        );
        recorder.write_run_report("running").await?;
        Ok(recorder)
    }

    pub async fn record(&self, event: RecorderEvent) -> Result<()> {
        if !should_write_traffic_event(self.traffic_jsonl, &event) {
            return Ok(());
        }
        let mut line = serde_json::to_vec(&event).context("failed to serialize recorder event")?;
        line.push(b'\n');

        let mut file = self.traffic_file.lock().await;
        if let Some(file) = file.as_mut() {
            file.append(&line).await?;
        }
        Ok(())
    }

    /// Flush currently buffered run-level `traffic.jsonl` records.
    pub async fn flush_traffic(&self) -> Result<()> {
        let mut file = self.traffic_file.lock().await;
        if let Some(file) = file.as_mut() {
            file.flush().await?;
        }
        Ok(())
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

fn spawn_jsonl_flush_task(
    traffic_file: &Arc<Mutex<Option<jsonl::BufferedJsonlWriter>>>,
    dependency_files: &Arc<Mutex<jsonl::JsonlWriterPool>>,
    interval: Duration,
) {
    let traffic_file = Arc::downgrade(traffic_file);
    let dependency_files = Arc::downgrade(dependency_files);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;

            let Some(traffic_file) = traffic_file.upgrade() else {
                break;
            };
            let traffic_flush = {
                let mut writer = traffic_file.lock().await;
                match writer.as_mut() {
                    Some(writer) => writer.flush().await,
                    None => Ok(()),
                }
            };
            drop(traffic_file);
            if let Err(error) = traffic_flush {
                warn!(%error, "failed to periodically flush traffic JSONL");
            }

            let Some(dependency_files) = dependency_files.upgrade() else {
                break;
            };
            let dependency_flush = dependency_files.lock().await.flush_open().await;
            drop(dependency_files);
            if let Err(error) = dependency_flush {
                warn!(%error, "failed to periodically flush dependency JSONL");
            }
        }
    });
}

fn should_write_traffic_event(mode: TrafficJsonlMode, event: &RecorderEvent) -> bool {
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
