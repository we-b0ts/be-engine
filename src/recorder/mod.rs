pub(crate) mod cache_snapshot;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use self::run::RecorderRunState;
use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::ArtifactOwner;
use crate::config::{RecordingAccessPolicy, RecordingConfig, TrafficJsonlMode};
use crate::recording_completion::ExplicitApiCaseLimits;
use crate::recording_network::RecordedEndpoint;
use crate::request_headers::RequestHeaderCapture;

pub(crate) mod async_api;
pub(crate) mod background;
mod capture;
pub(crate) mod capture_health;
pub(crate) mod case;
pub(crate) mod connect_failure;
pub(crate) mod connections;
mod dependencies;
mod event;
pub(crate) mod http;
mod identity;
mod jsonl;
pub(crate) mod kafka;
pub(crate) mod ledger;
pub(crate) mod memcached;
pub(crate) mod motan;
pub(crate) mod native;
mod network;
mod preparation;
pub(crate) mod process_classification;
pub(crate) mod readiness;
pub(crate) mod request;
mod run;
mod shutdown;
mod storage;
mod summary;
#[cfg(test)]
pub(crate) mod test_io;
mod writer;

pub use capture::*;
pub(crate) use case::{
    CaseInvalidation, CaseInvalidationContext, PrimaryCaseDescriptor, PrimarySourceBinding,
};
pub use event::*;
pub(crate) use summary::{
    SourceProcessTrafficObservation, load_pre_readiness_traffic_summary,
    load_source_process_traffic_summary, should_append_case_dependency,
};

struct RecorderOptions {
    access_policy: RecordingAccessPolicy,
    traffic_jsonl: TrafficJsonlMode,
    buffer_settings: jsonl::JsonlBufferSettings,
    writer_queue_capacity: usize,
    run_id: Option<String>,
    recording_api_limits: Vec<(String, usize)>,
    artifact_owner: Option<ArtifactOwner>,
    request_header_capture: RequestHeaderCapture,
    capture_policy_identity: String,
    evidence: Arc<traffic_protocol::evidence::EvidenceRegistry>,
}

#[derive(Clone)]
pub struct Recorder {
    global_preparation: Option<Arc<preparation::GlobalPreparation>>,
    pub(crate) extensions: traffic_recording::RecordingExtensions,
    artifact_owner: Option<ArtifactOwner>,
    traffic_jsonl: TrafficJsonlMode,
    writer: writer::RecorderWriter,
    pub(crate) capture: ledger::CaptureRegistry,
    pub(crate) run_dir: Arc<PathBuf>,
    pub(crate) run_state: Arc<Mutex<RecorderRunState>>,
    pub(crate) dependency_write_lock: Arc<Mutex<()>>,
    pub(crate) finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
    network_observations: Arc<Mutex<NetworkObservations>>,
    pub(crate) access_policy: RecordingAccessPolicy,
    explicit_api_case_limits: ExplicitApiCaseLimits,
    request_header_capture: RequestHeaderCapture,
    capture_policy_identity: String,
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
                evidence: Arc::new(crate::protocols::default_providers().evidence().clone()),
                access_policy,
                traffic_jsonl: defaults.traffic_jsonl,
                buffer_settings: jsonl::JsonlBufferSettings {
                    capacity: defaults.jsonl_buffer_capacity_bytes,
                    flush_interval: Duration::from_millis(defaults.jsonl_flush_interval_ms),
                },
                writer_queue_capacity: defaults.writer_queue_capacity,
                run_id: None,
                recording_api_limits: Vec::new(),
                artifact_owner: None,
                request_header_capture: RequestHeaderCapture::from_environment(
                    &defaults.encrypt_request_headers,
                    &defaults.redact_headers,
                )?,
                capture_policy_identity: crate::policy_evidence::digest(&serde_json::to_vec(&(
                    &defaults,
                    access_policy,
                ))?),
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
            Arc::new(crate::protocols::default_providers().evidence().clone()),
        )
        .await
    }

    pub(crate) async fn new_with_recording_config_at_and_run_id(
        config: &RecordingConfig,
        output_dir: impl AsRef<Path>,
        run_id: Option<String>,
        recording_api_limits: Vec<(String, usize)>,
        artifact_owner: Option<ArtifactOwner>,
        evidence: Arc<traffic_protocol::evidence::EvidenceRegistry>,
    ) -> Result<Self> {
        Self::new_with_options(
            output_dir,
            RecorderOptions {
                evidence,
                access_policy: config.access_policy,
                traffic_jsonl: config.traffic_jsonl,
                buffer_settings: jsonl::JsonlBufferSettings {
                    capacity: config.jsonl_buffer_capacity_bytes,
                    flush_interval: Duration::from_millis(config.jsonl_flush_interval_ms),
                },
                writer_queue_capacity: config.writer_queue_capacity,
                run_id,
                capture_policy_identity: crate::policy_evidence::digest(&serde_json::to_vec(&(
                    config,
                    &recording_api_limits,
                ))?),
                recording_api_limits,
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
            evidence,
            access_policy,
            traffic_jsonl,
            buffer_settings,
            writer_queue_capacity,
            run_id,
            recording_api_limits,
            artifact_owner,
            request_header_capture,
            capture_policy_identity,
        } = options;
        let output_dir = output_dir.as_ref();
        tokio::fs::create_dir_all(output_dir)
            .await
            .with_context(|| format!("failed to create recording dir {}", output_dir.display()))?;
        let (run_id, run_dir) = run::create_run_dir(output_dir, run_id).await?;
        let run_dir = Arc::new(run_dir);
        let finalized_cases = Arc::new(Mutex::new(HashSet::new()));
        let process_epoch = Uuid::new_v4();
        let writer = writer::RecorderWriter::start(
            run_dir.clone(),
            traffic_jsonl,
            buffer_settings,
            writer_queue_capacity,
            finalized_cases.clone(),
            writer::CaptureOptions {
                process_epoch,
                policy_identity: capture_policy_identity.clone(),
                evidence,
            },
        )
        .await?;
        let recording_apis = recording_api_limits
            .iter()
            .map(|(api, _)| api.clone())
            .collect();
        let recorder = Self {
            global_preparation: None,
            extensions: Default::default(),
            artifact_owner,
            traffic_jsonl,
            capture: ledger::CaptureRegistry::new(writer.clone(), process_epoch),
            writer,
            run_dir,
            run_state: Arc::new(Mutex::new(RecorderRunState {
                run_id,
                recording_apis,
                ..Default::default()
            })),
            dependency_write_lock: Arc::new(Mutex::new(())),
            finalized_cases,
            network_observations: Arc::new(Mutex::new(NetworkObservations::default())),
            access_policy,
            explicit_api_case_limits: ExplicitApiCaseLimits::new(recording_api_limits),
            request_header_capture,
            capture_policy_identity,
        };
        recorder.write_run_report("running").await?;
        Ok(recorder)
    }

    pub async fn record(
        &self,
        event: impl traffic_protocol::capture::CaptureEvidence,
    ) -> Result<()> {
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
        event: impl traffic_protocol::capture::CaptureEvidence,
        targets: crate::active_case::DependencyTargets,
        global_attribution: Option<GlobalDependencyAttribution>,
        suppress_default_global: bool,
    ) -> Result<()> {
        self.writer.try_record(writer::RecordEnvelope {
            event: traffic_recording::CapturedEvent::capture(&event)?,
            targets,
            global_attribution,
            suppress_default_global,
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
        if filename == "admission.json" {
            let directory = self.case_staging_dir(case);
            self.writer
                .register_input(
                    case.id,
                    directory
                        .strip_prefix(self.run_dir.as_ref())?
                        .to_string_lossy()
                        .into(),
                    false,
                )
                .await?;
        }
        let mut payload =
            serde_json::to_vec_pretty(value).context("failed to serialize case recording file")?;
        payload.push(b'\n');
        storage::write(&path, &payload)
            .await
            .with_context(|| format!("failed to write case recording file {}", path.display()))
    }
}

#[derive(Debug, Clone, Default)]
struct NetworkObservations {
    resolved_domains: BTreeSet<String>,
    accessed_endpoints: BTreeSet<RecordedEndpoint>,
}

pub(crate) struct GlobalDependencyAttribution {
    pub(crate) reason: &'static str,
    pub(crate) phase: &'static str,
    pub(crate) matched_by: String,
}

pub(super) fn should_write_traffic_event(
    mode: TrafficJsonlMode,
    event: &impl traffic_protocol::capture::CaptureEvidence,
) -> bool {
    match mode {
        TrafficJsonlMode::Full => true,
        TrafficJsonlMode::Off => false,
        TrafficJsonlMode::Errors => event.capture_facts().traffic_error,
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
