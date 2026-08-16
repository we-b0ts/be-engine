use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use super::model::{ApiCountMap, ApiCounts};
use crate::recording_completion::RecordingCompletionReason;

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct ComparisonRecordingCounts {
    pub(super) received: usize,
    pub(super) matched: usize,
    pub(super) unmatched: usize,
    pub(super) excluded: usize,
    pub(super) not_ready: usize,
    pub(super) overloaded: usize,
    pub(super) request_too_large: usize,
    pub(super) baseline_only: usize,
    pub(super) fixed_response: usize,
    pub(super) dual_dispatched: usize,
    pub(super) dual_completed: usize,
    pub(super) baseline_success: usize,
    pub(super) baseline_error: usize,
    pub(super) baseline_response_too_large: usize,
    pub(super) baseline_recheck_success: usize,
    pub(super) baseline_recheck_error: usize,
    pub(super) baseline_recheck_response_too_large: usize,
    pub(super) candidate_success: usize,
    pub(super) candidate_error: usize,
    pub(super) candidate_response_too_large: usize,
    pub(super) published: usize,
    pub(super) failed: usize,
    pub(super) suppressed_by_case_limit: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ComparisonRecordingRunReport {
    version: u8,
    run_id: String,
    status: String,
    output_dir: String,
    recording_apis: Vec<String>,
    started_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_reason: Option<RecordingCompletionReason>,
    ready: bool,
    in_flight: usize,
    counts: ComparisonRecordingCounts,
    apis: ApiCountMap,
    errors: Vec<String>,
}

#[derive(Clone)]
pub(super) struct ComparisonRecordingSummary {
    path: Arc<PathBuf>,
    state: Arc<Mutex<ComparisonRecordingRunReport>>,
}

impl ComparisonRecordingSummary {
    pub(super) fn new(run_id: String, run_dir: &Path, recording_apis: Vec<String>) -> Self {
        Self {
            path: Arc::new(run_dir.join("comparison-recording-run.json")),
            state: Arc::new(Mutex::new(ComparisonRecordingRunReport {
                version: 1,
                run_id,
                status: "running".to_string(),
                output_dir: run_dir.display().to_string(),
                recording_apis,
                started_at: Utc::now(),
                finished_at: None,
                completion_reason: None,
                ready: false,
                in_flight: 0,
                counts: ComparisonRecordingCounts::default(),
                apis: ApiCountMap::new(),
                errors: Vec::new(),
            })),
        }
    }

    pub(super) async fn update(&self, change: impl FnOnce(&mut ComparisonRecordingCounts)) {
        change(&mut self.state.lock().await.counts);
    }

    pub(super) async fn set_ready(&self) {
        self.state.lock().await.ready = true;
    }

    pub(super) async fn set_in_flight(&self, value: usize) {
        self.state.lock().await.in_flight = value;
    }

    pub(super) async fn api_update(
        &self,
        recording_api: &str,
        change: impl FnOnce(&mut ApiCounts),
    ) {
        change(
            self.state
                .lock()
                .await
                .apis
                .entry(recording_api.to_string())
                .or_default(),
        );
    }

    pub(super) async fn record_error(&self, error: String) {
        self.state.lock().await.errors.push(error);
    }

    pub(super) async fn published(&self) -> usize {
        self.state.lock().await.counts.published
    }

    pub(super) async fn finish(&self, completion_reason: RecordingCompletionReason) -> Result<()> {
        {
            let mut state = self.state.lock().await;
            state.status = if state.errors.is_empty() {
                "completed".to_string()
            } else {
                "completed_with_errors".to_string()
            };
            state.finished_at = Some(Utc::now());
            state.completion_reason = Some(completion_reason);
            state.in_flight = 0;
        }
        self.flush().await
    }

    pub(super) async fn flush(&self) -> Result<()> {
        let payload = {
            let state = self.state.lock().await;
            let mut payload = serde_json::to_vec_pretty(&*state)
                .context("failed to serialize comparison recording run report")?;
            payload.push(b'\n');
            payload
        };
        let temporary = self.path.with_extension("json.tmp");
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .await
            .with_context(|| format!("failed to open {}", temporary.display()))?;
        file.write_all(&payload).await?;
        crate::artifact_file::flush_all_and_evict(&mut file, 0)
            .await
            .with_context(|| format!("failed to finalize {}", temporary.display()))?;
        drop(file);
        tokio::fs::rename(&temporary, self.path.as_ref())
            .await
            .with_context(|| format!("failed to publish {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn finalized_summary_records_the_completion_reason() {
        let temp = tempfile::tempdir().unwrap();
        let summary = ComparisonRecordingSummary::new(
            "20260803120000".to_string(),
            temp.path(),
            vec!["GET /api".to_string()],
        );

        summary
            .finish(RecordingCompletionReason::PerApiCaseLimitReached)
            .await
            .unwrap();

        let report: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(temp.path().join("comparison-recording-run.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["status"], "completed");
        assert_eq!(report["completion_reason"], "per_api_case_limit_reached");
    }
}
