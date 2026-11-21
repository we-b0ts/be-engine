//! Application construction of protocol-aware recording capabilities.
use super::events::HeaderMapSnapshot;
use crate::ArtifactOwner;
use crate::config::{RecordingAccessPolicy, RecordingConfig};
use crate::recorder::{Recorder, RecorderOptions, jsonl};
use crate::request_headers::RequestHeaderCapture;
use anyhow::{Context, Result};
use std::{path::Path, sync::Arc, time::Duration};

fn header_extensions(config: &RecordingConfig) -> Result<traffic_recorder::RecordingExtensions> {
    let extensions = traffic_recorder::RecordingExtensions::default();
    extensions.insert(RequestHeaderCapture::from_environment(
        &config.encrypt_request_headers,
        &config.redact_headers,
    )?);
    Ok(extensions)
}

impl Recorder {
    pub async fn new(output_dir: impl AsRef<Path>) -> Result<Self> {
        Self::new_with_access_policy(output_dir, RecordingAccessPolicy::Unrestricted).await
    }

    pub async fn new_with_access_policy(
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
                extensions: header_extensions(&defaults)?,
                source_preparation: super::super::recording_preparation::strict(Arc::new(
                    crate::protocols::default_providers().evidence().clone(),
                )),
                capture_policy_identity: crate::policy_evidence::digest(&serde_json::to_vec(&(
                    &defaults,
                    access_policy,
                ))?),
            },
        )
        .await
    }

    #[cfg(any(test, feature = "test-support"))]
    pub async fn new_with_recording_config_and_run_id(
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

    pub async fn new_with_recording_config_at_and_run_id(
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
                source_preparation: super::super::recording_preparation::strict(evidence.clone()),
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
                extensions: header_extensions(config)?,
            },
        )
        .await
    }

    #[cfg(any(test, feature = "test-support"))]
    pub async fn new_with_recording_config(config: &RecordingConfig) -> Result<Self> {
        Self::new_with_recording_config_and_run_id(config, None).await
    }

    pub fn capture_request_headers(&self, headers: &hyper::HeaderMap) -> Result<HeaderMapSnapshot> {
        self.extensions
            .existing::<RequestHeaderCapture>()
            .context("recording header capture is not configured")?
            .capture(headers)
    }
}
