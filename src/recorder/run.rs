use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::info;
use uuid::Uuid;

use super::dependencies::ensure_case_dependency_file;
use super::http::case::CaseInvalidationContext;
use super::summary::{write_bootstrap_dependency_summary, write_case_dependency_summary};
use super::{CaseContext, Recorder, sanitize_path_component};

#[derive(Debug, Serialize)]
struct RecorderRunReport {
    run_id: String,
    status: &'static str,
    output_dir: String,
    recording_apis: Vec<String>,
    access_policy: &'static str,
    traffic_jsonl: &'static str,
    published_cases: usize,
    failed_cases: usize,
    errors: Vec<RecordingErrorSummary>,
}

#[derive(Debug, Default)]
pub(crate) struct RecorderRunState {
    pub(crate) run_id: String,
    pub(crate) recording_apis: Vec<String>,
    pub(crate) published_cases: usize,
    pub(crate) published_cases_by_group: BTreeMap<(String, Option<String>), usize>,
    pub(crate) failed_cases: usize,
    pub(crate) errors: Vec<RecordingErrorSummary>,
    pub(crate) finishing: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<CaseInvalidationContext>,
}

impl Recorder {
    pub async fn publish_case(&self, case: &CaseContext) -> Result<()> {
        self.flush_traffic().await?;
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        let staging_dir = self.case_staging_dir(case);
        let published_dir = self.case_dir(case);
        self.flush_case_dependency_files(&staging_dir).await?;
        ensure_case_dependency_file(&staging_dir).await?;
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

        {
            let mut state = self.run_state.lock().await;
            state.published_cases += 1;
            *state
                .published_cases_by_group
                .entry((case.rule_name.clone(), case.uri_group.clone()))
                .or_default() += 1;
        }
        self.write_run_report("running").await
    }

    pub(crate) async fn published_case_count(&self, case: &CaseContext) -> usize {
        self.run_state
            .lock()
            .await
            .published_cases_by_group
            .get(&(case.rule_name.clone(), case.uri_group.clone()))
            .copied()
            .unwrap_or_default()
    }

    pub async fn fail_case(
        &self,
        case: &CaseContext,
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<()> {
        self.fail_case_with_context(case, reason, message, None)
            .await
    }

    pub(crate) async fn fail_case_with_context(
        &self,
        case: &CaseContext,
        reason: impl Into<String>,
        message: impl Into<String>,
        context: Option<CaseInvalidationContext>,
    ) -> Result<()> {
        let reason = reason.into();
        let message = message.into();
        self.flush_traffic().await?;
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        let failed_dir = self.move_case_to_failed(case).await?;
        self.record_case_failure(case, reason, message, context, failed_dir)
            .await
    }

    pub(crate) async fn discard_unadmitted_case(&self, case: &CaseContext) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        self.flush_case_dependency_files(&self.case_staging_dir(case))
            .await?;
        remove_dir_if_exists(&self.case_staging_dir(case)).await
    }

    async fn record_case_failure(
        &self,
        case: &CaseContext,
        reason: String,
        message: String,
        context: Option<CaseInvalidationContext>,
        failed_dir: PathBuf,
    ) -> Result<()> {
        let timestamp = Utc::now();
        let detail = RecordingErrorDetail {
            timestamp,
            rule_name: case.rule_name.clone(),
            uri_group: case.uri_group.clone(),
            case_id: case.id,
            reason: reason.clone(),
            message,
            context,
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
        self.write_run_report("running").await
    }

    pub async fn finish_run(&self) -> Result<bool> {
        self.finish_run_with_status("completed").await
    }

    pub(crate) async fn finish_run_after_runtime(&self, runtime_succeeded: bool) -> Result<bool> {
        self.finish_run_with_status(if runtime_succeeded {
            "completed"
        } else {
            "failed"
        })
        .await
    }

    async fn finish_run_with_status(&self, status: &'static str) -> Result<bool> {
        {
            let mut state = self.run_state.lock().await;
            state.finishing = true;
        }
        let unfinished = {
            let _guard = self.dependency_write_lock.lock().await;
            self.flush_all_dependency_files().await?;
            write_bootstrap_dependency_summary(&self.run_dir).await?;
            let mut unfinished = Vec::new();
            for case in self.unfinished_staging_cases().await? {
                let failed_dir = self.move_case_to_failed(&case).await?;
                unfinished.push((case, failed_dir));
            }
            unfinished
        };
        for (case, failed_dir) in unfinished {
            self.record_case_failure(
                &case,
                "recording_incomplete_at_shutdown".to_string(),
                "case remained in staging when the recording run finished".to_string(),
                None,
                failed_dir,
            )
            .await?;
        }
        let has_failed_cases = {
            let mut state = self.run_state.lock().await;
            state.finished = true;
            state.failed_cases > 0
        };
        self.write_run_report(status).await?;
        self.flush_traffic().await?;
        if let Some(owner) = self.artifact_owner {
            owner.assign_to(&self.run_dir).await.with_context(|| {
                format!(
                    "failed to assign finalized recording run {} to {}",
                    self.run_dir.display(),
                    owner
                )
            })?;
            info!(
                run_dir = %self.run_dir.display(),
                uid = owner.uid(),
                gid = owner.gid(),
                "assigned finalized recording artifact ownership"
            );
        }
        Ok(has_failed_cases)
    }

    pub(super) async fn ensure_run_accepts_case_writes(&self) -> Result<()> {
        let state = self.run_state.lock().await;
        if state.finishing || state.finished {
            bail!("recording run is already finishing");
        }
        Ok(())
    }

    async fn move_case_to_failed(&self, case: &CaseContext) -> Result<PathBuf> {
        let staging_dir = self.case_staging_dir(case);
        let failed_dir = self.case_failed_dir(case);
        self.flush_case_dependency_files(&staging_dir).await?;
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
        Ok(failed_dir)
    }

    async fn unfinished_staging_cases(&self) -> Result<Vec<CaseContext>> {
        let staging_root = self.run_dir.join("staging");
        let mut rules = match tokio::fs::read_dir(&staging_root).await {
            Ok(rules) => rules,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to inspect staging root {}", staging_root.display())
                });
            }
        };
        let mut cases = Vec::new();
        while let Some(rule) = rules.next_entry().await? {
            if !rule.file_type().await?.is_dir() {
                continue;
            }
            let rule_name = rule.file_name().to_string_lossy().into_owned();
            let mut children = tokio::fs::read_dir(rule.path()).await?;
            while let Some(child) = children.next_entry().await? {
                if !child.file_type().await?.is_dir() {
                    continue;
                }
                let child_name = child.file_name().to_string_lossy().into_owned();
                if let Ok(id) = Uuid::parse_str(&child_name) {
                    cases.push(CaseContext {
                        id,
                        rule_name: rule_name.clone(),
                        uri_group: None,
                    });
                    continue;
                }
                let mut grouped_cases = tokio::fs::read_dir(child.path()).await?;
                while let Some(grouped_case) = grouped_cases.next_entry().await? {
                    if !grouped_case.file_type().await?.is_dir() {
                        continue;
                    }
                    let case_id = grouped_case.file_name().to_string_lossy().into_owned();
                    if let Ok(id) = Uuid::parse_str(&case_id) {
                        cases.push(CaseContext {
                            id,
                            rule_name: rule_name.clone(),
                            uri_group: Some(child_name.clone()),
                        });
                    }
                }
            }
        }
        Ok(cases)
    }

    pub(crate) async fn seal_bootstrap_dependencies(&self) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        self.flush_bootstrap_dependency_files().await
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
        let report = RecorderRunReport {
            run_id: state.run_id.clone(),
            status,
            output_dir: self.run_dir.display().to_string(),
            recording_apis: state.recording_apis.clone(),
            access_policy: self.access_policy.as_str(),
            traffic_jsonl: self.traffic_jsonl.as_str(),
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    fn case(group: &str) -> CaseContext {
        CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some(group.to_string()),
        }
    }

    #[tokio::test]
    async fn published_case_counts_are_grouped_and_ignore_failed_cases() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let first = case("api-users-wildcard");
        let second = case("api-users-wildcard");
        let other = case("api-projects-wildcard");
        let failed = case("api-users-wildcard");

        recorder.publish_case(&first).await.unwrap();
        recorder.publish_case(&second).await.unwrap();
        recorder.publish_case(&other).await.unwrap();
        recorder
            .fail_case(&failed, "test_failure", "expected test failure")
            .await
            .unwrap();

        assert_eq!(recorder.published_case_count(&first).await, 2);
        assert_eq!(recorder.published_case_count(&other).await, 1);
        assert!(recorder.case_dir(&first).is_dir());
        assert!(recorder.case_dir(&second).is_dir());
        assert!(recorder.case_dir(&other).is_dir());
        assert!(recorder.case_failed_dir(&failed).is_dir());
        assert!(!recorder.case_dir(&failed).is_dir());

        let report_raw = tokio::fs::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
        assert_eq!(report["status"], "running");
        assert_eq!(report["published_cases"], 3);
        assert_eq!(report["failed_cases"], 1);
    }

    #[tokio::test]
    async fn finish_run_moves_unfinished_staging_cases_to_failed() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let grouped = case("api-users-wildcard");
        let ungrouped = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-health".to_string(),
            uri_group: None,
        };

        recorder
            .write_case_json(
                &grouped,
                "admission.json",
                &serde_json::json!({ "admitted": true }),
            )
            .await
            .unwrap();
        recorder
            .write_case_json(
                &ungrouped,
                "admission.json",
                &serde_json::json!({ "admitted": true }),
            )
            .await
            .unwrap();

        assert!(recorder.finish_run().await.unwrap());
        assert!(!recorder.case_staging_dir(&grouped).exists());
        assert!(!recorder.case_staging_dir(&ungrouped).exists());
        assert!(
            recorder
                .case_failed_dir(&grouped)
                .join("admission.json")
                .exists()
        );
        assert!(
            recorder
                .case_failed_dir(&ungrouped)
                .join("admission.json")
                .exists()
        );

        let report_raw = tokio::fs::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
        assert_eq!(report["status"], "completed");
        assert_eq!(report["published_cases"], 0);
        assert_eq!(report["failed_cases"], 2);
        assert_eq!(
            report["errors"][0]["reason"],
            "recording_incomplete_at_shutdown"
        );
        assert_eq!(
            report["errors"][1]["reason"],
            "recording_incomplete_at_shutdown"
        );

        assert!(
            recorder
                .write_case_json(&grouped, "late.json", &serde_json::json!({ "late": true }),)
                .await
                .is_err()
        );
        assert!(!recorder.case_staging_dir(&grouped).exists());
    }

    #[tokio::test]
    async fn runtime_failure_is_distinct_from_individual_case_failures() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();

        assert!(!recorder.finish_run_after_runtime(false).await.unwrap());

        let report_raw = tokio::fs::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
        assert_eq!(report["status"], "failed");
        assert_eq!(report["failed_cases"], 0);
    }

    #[tokio::test]
    async fn finish_run_assigns_the_configured_artifact_owner() {
        let temp = tempfile::tempdir().unwrap();
        let mut recorder = Recorder::new(temp.path()).await.unwrap();
        let owner = super::super::ArtifactOwner::new(unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        });
        recorder.artifact_owner = Some(owner);
        let artifact = recorder.run_dir.join("nested/request.json");
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&artifact, "{}\n").await.unwrap();

        recorder.finish_run().await.unwrap();

        for path in [recorder.run_dir.as_ref(), artifact.as_path()] {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            assert_eq!(metadata.uid(), owner.uid());
            assert_eq!(metadata.gid(), owner.gid());
        }
    }
}
