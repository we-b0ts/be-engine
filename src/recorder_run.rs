use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::dependency_summary::{
    write_bootstrap_dependency_summary, write_case_dependency_summary,
};
use crate::recorder::{CaseContext, Recorder, sanitize_path_component};

#[derive(Debug, Serialize)]
struct RecorderRunReport {
    run_id: String,
    status: &'static str,
    output_dir: String,
    published_cases: usize,
    failed_cases: usize,
    errors: Vec<RecordingErrorSummary>,
}

#[derive(Debug, Default)]
pub(crate) struct RecorderRunState {
    pub(crate) run_id: String,
    pub(crate) published_cases: usize,
    pub(crate) failed_cases: usize,
    pub(crate) errors: Vec<RecordingErrorSummary>,
    pub(crate) finished: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RecordingErrorSummary {
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) rule_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) uri_group: Option<String>,
    pub(crate) case_id: Uuid,
    pub(crate) reason: String,
    pub(crate) detail_path: String,
}

#[derive(Debug, Serialize)]
struct RecordingErrorDetail {
    timestamp: DateTime<Utc>,
    rule_name: String,
    uri_group: Option<String>,
    case_id: Uuid,
    reason: String,
    message: String,
}

impl Recorder {
    pub async fn publish_case(&self, case: &CaseContext) -> Result<()> {
        {
            let _guard = self.dependency_write_lock.lock().await;
            let staging_dir = self.case_staging_dir(case);
            let published_dir = self.case_dir(case);
            write_case_dependency_summary(&staging_dir).await?;
            if let Some(parent) = published_dir.parent() {
                tokio::fs::create_dir_all(parent).await.with_context(|| {
                    format!(
                        "failed to create published case parent dir {}",
                        parent.display()
                    )
                })?;
            }
            remove_dir_if_exists(&published_dir).await?;
            if tokio::fs::try_exists(&staging_dir).await.with_context(|| {
                format!(
                    "failed to inspect staging case dir {}",
                    staging_dir.display()
                )
            })? {
                tokio::fs::rename(&staging_dir, &published_dir)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to publish case {} from {} to {}",
                            case.id,
                            staging_dir.display(),
                            published_dir.display()
                        )
                    })?;
            } else {
                tokio::fs::create_dir_all(&published_dir)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to create published case dir {}",
                            published_dir.display()
                        )
                    })?;
            }
            self.finalized_cases.lock().await.insert(case.id);
        }

        {
            let mut state = self.run_state.lock().await;
            state.published_cases += 1;
        }
        self.write_run_report("running").await
    }

    pub async fn fail_case(
        &self,
        case: &CaseContext,
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<()> {
        let reason = reason.into();
        let message = message.into();
        let failed_dir = {
            let _guard = self.dependency_write_lock.lock().await;
            let staging_dir = self.case_staging_dir(case);
            let failed_dir = self.case_failed_dir(case);
            if let Some(parent) = failed_dir.parent() {
                tokio::fs::create_dir_all(parent).await.with_context(|| {
                    format!(
                        "failed to create failed case parent dir {}",
                        parent.display()
                    )
                })?;
            }
            remove_dir_if_exists(&failed_dir).await?;
            if tokio::fs::try_exists(&staging_dir).await.with_context(|| {
                format!(
                    "failed to inspect staging case dir {}",
                    staging_dir.display()
                )
            })? {
                tokio::fs::rename(&staging_dir, &failed_dir)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to move invalid case {} from {} to {}",
                            case.id,
                            staging_dir.display(),
                            failed_dir.display()
                        )
                    })?;
            } else {
                tokio::fs::create_dir_all(&failed_dir)
                    .await
                    .with_context(|| {
                        format!("failed to create failed case dir {}", failed_dir.display())
                    })?;
            }
            self.finalized_cases.lock().await.insert(case.id);
            failed_dir
        };

        let timestamp = Utc::now();
        let detail = RecordingErrorDetail {
            timestamp,
            rule_name: case.rule_name.clone(),
            uri_group: case.uri_group.clone(),
            case_id: case.id,
            reason: reason.clone(),
            message,
        };
        let detail_path = failed_dir.join("recording-error.json");
        write_pretty_json(&detail_path, &detail).await?;

        let summary = RecordingErrorSummary {
            timestamp,
            rule_name: case.rule_name.clone(),
            uri_group: case.uri_group.clone(),
            case_id: case.id,
            reason,
            detail_path: path_relative_to(&detail_path, &self.run_dir),
        };
        {
            let mut state = self.run_state.lock().await;
            state.failed_cases += 1;
            state.errors.push(summary.clone());
        }
        self.append_run_error(&summary).await?;
        self.write_run_report("failed").await
    }

    pub async fn finish_run(&self) -> Result<bool> {
        self.finalize_bootstrap_dependency_summary().await?;
        let has_failed_cases = {
            let mut state = self.run_state.lock().await;
            state.finished = true;
            state.failed_cases > 0
        };
        self.write_run_report(if has_failed_cases {
            "failed"
        } else {
            "completed"
        })
        .await?;
        Ok(has_failed_cases)
    }

    pub(crate) async fn finalize_bootstrap_dependency_summary(&self) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        write_bootstrap_dependency_summary(&self.run_dir).await
    }

    pub(crate) fn case_dir(&self, case: &CaseContext) -> PathBuf {
        let mut path = self.run_dir.join(sanitize_path_component(&case.rule_name));
        if let Some(uri_group) = &case.uri_group {
            path = path.join(sanitize_path_component(uri_group));
        }
        path.join(case.id.to_string())
    }

    pub(crate) fn case_staging_dir(&self, case: &CaseContext) -> PathBuf {
        self.run_case_dir("staging", case)
    }

    pub(crate) fn case_failed_dir(&self, case: &CaseContext) -> PathBuf {
        self.run_case_dir("failed", case)
    }

    fn run_case_dir(&self, bucket: &str, case: &CaseContext) -> PathBuf {
        let mut path = self
            .run_dir
            .join(bucket)
            .join(sanitize_path_component(&case.rule_name));
        if let Some(uri_group) = &case.uri_group {
            path = path.join(sanitize_path_component(uri_group));
        }
        path.join(case.id.to_string())
    }

    async fn append_run_error(&self, summary: &RecordingErrorSummary) -> Result<()> {
        let path = self.run_dir.join("errors.jsonl");
        let mut line =
            serde_json::to_vec(summary).context("failed to serialize recording error summary")?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open recording errors file {}", path.display()))?;
        file.write_all(&line)
            .await
            .context("failed to append recording error")?;
        file.flush()
            .await
            .context("failed to flush recording error")?;
        Ok(())
    }

    pub(crate) async fn write_run_report(&self, status: &'static str) -> Result<()> {
        let state = self.run_state.lock().await;
        let status = if state.finished {
            if state.failed_cases > 0 {
                "failed"
            } else {
                "completed"
            }
        } else if state.failed_cases > 0 {
            "failed"
        } else {
            status
        };
        let report = RecorderRunReport {
            run_id: state.run_id.clone(),
            status,
            output_dir: self.run_dir.display().to_string(),
            published_cases: state.published_cases,
            failed_cases: state.failed_cases,
            errors: state.errors.clone(),
        };
        drop(state);
        write_pretty_json(&self.run_dir.join("recording-run.json"), &report).await
    }
}

pub(crate) async fn write_pretty_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
    }
    let mut payload = serde_json::to_vec_pretty(value).context("failed to serialize JSON file")?;
    payload.push(b'\n');
    tokio::fs::write(path, payload)
        .await
        .with_context(|| format!("failed to write JSON file {}", path.display()))
}

async fn remove_dir_if_exists(path: &Path) -> Result<()> {
    if tokio::fs::try_exists(path)
        .await
        .with_context(|| format!("failed to inspect dir {}", path.display()))?
    {
        tokio::fs::remove_dir_all(path)
            .await
            .with_context(|| format!("failed to remove dir {}", path.display()))?;
    }
    Ok(())
}

pub(crate) fn new_run_id() -> String {
    Utc::now().format("%Y%m%d%H%M%S").to_string()
}

fn path_relative_to(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .display()
        .to_string()
}
