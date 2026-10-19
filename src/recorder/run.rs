use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::info;
use uuid::Uuid;

use super::dependencies::ensure_case_dependency_file;
use super::summary::{write_case_dependency_summary, write_global_dependency_summary};
use super::{CaseContext, CaseInvalidationContext, Recorder, sanitize_path_component};
use crate::recording_completion::RecordingCompletionReason;

#[derive(Debug, Serialize)]
struct RecorderRunReport {
    run_id: String,
    status: &'static str,
    output_dir: String,
    recording_apis: Vec<String>,
    observed_api_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_methods: Option<crate::recording_api::methods::ApiMethods>,
    access_policy: &'static str,
    traffic_jsonl: &'static str,
    published_cases: usize,
    failed_cases: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_reason: Option<RecordingCompletionReason>,
    errors: Vec<RecordingErrorSummary>,
}

#[derive(Debug, Default)]
pub(crate) struct RecorderRunState {
    pub(crate) run_id: String,
    pub(crate) recording_apis: Vec<String>,
    pub(crate) observed_apis: BTreeSet<String>,
    pub(crate) published_cases: usize,
    pub(crate) published_cases_by_group: BTreeMap<Option<String>, usize>,
    pub(crate) failed_cases: usize,
    pub(crate) completion_reason: Option<RecordingCompletionReason>,
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
        self.publish_case_for_api(case, None).await
    }

    pub(crate) async fn publish_case_for_api(
        &self,
        case: &CaseContext,
        recording_api: Option<&str>,
    ) -> Result<()> {
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
            if let Some(recording_api) = recording_api {
                state.observed_apis.insert(recording_api.to_string());
            }
            *state
                .published_cases_by_group
                .entry(case.uri_group.clone())
                .or_default() += 1;
        }
        self.write_run_report("running").await?;
        if let Some(recording_api) = recording_api {
            self.explicit_api_case_limits
                .record_published(recording_api)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn published_case_count(&self, case: &CaseContext) -> usize {
        self.run_state
            .lock()
            .await
            .published_cases_by_group
            .get(&case.uri_group)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) async fn published_recording_api_count(&self, recording_api: &str) -> Option<usize> {
        self.explicit_api_case_limits.published(recording_api).await
    }

    pub(crate) async fn wait_for_explicit_api_case_limit(&self) {
        self.explicit_api_case_limits.wait_until_complete().await;
    }

    pub(crate) async fn set_completion_reason(&self, reason: RecordingCompletionReason) {
        self.run_state.lock().await.completion_reason = Some(reason);
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
            write_global_dependency_summary(&self.run_dir).await?;
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
        self.write_network_manifest().await?;
        self.prepare_global_report().await;
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
            super::summary::refresh_owned_dependency_indexes(&self.run_dir, owner).await?;
            info!(
                run_dir = %self.run_dir.display(),
                uid = owner.uid(),
                gid = owner.gid(),
                "assigned finalized recording artifact ownership"
            );
        }
        if status == "completed" {
            let root = self.run_dir.clone();
            let catalog =
                tokio::task::spawn_blocking(move || crate::dependency_index::evidence::seal(&root))
                    .await
                    .context("Source proof index task failed")
                    .and_then(|result| result);
            match catalog {
                Ok(catalog) => {
                    if let Some(owner) = self.artifact_owner {
                        owner.assign_to(&catalog).await?;
                    }
                }
                Err(error) => {
                    tracing::warn!(error=%error,"Source proof index prewarm failed; first use will rebuild it")
                }
            }
            self.prepare_mysql_ownership().await;
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
        self.flush_global_dependency_files().await
    }

    pub(crate) fn case_dir(&self, case: &CaseContext) -> PathBuf {
        self.run_dir
            .join("apis")
            .join(case_archive_directory(case))
            .join(case.id.to_string())
    }

    pub(crate) fn case_staging_dir(&self, case: &CaseContext) -> PathBuf {
        self.run_case_dir("staging", case)
    }

    pub(crate) fn case_failed_dir(&self, case: &CaseContext) -> PathBuf {
        self.run_case_dir("failed", case)
    }

    fn run_case_dir(&self, bucket: &str, case: &CaseContext) -> PathBuf {
        self.run_dir
            .join(bucket)
            .join(case_archive_directory(case))
            .join(case.id.to_string())
    }

    async fn append_run_error(&self, summary: &RecordingErrorSummary) -> Result<()> {
        let path = self.run_dir.join("errors.jsonl");
        let mut line =
            serde_json::to_vec(summary).context("failed to serialize recording error summary")?;
        line.push(b'\n');
        super::storage::append(&path, &line)
            .await
            .with_context(|| format!("failed to append recording error {}", path.display()))
    }

    pub(crate) async fn write_run_report(&self, status: &'static str) -> Result<()> {
        let state = self.run_state.lock().await;
        let report = RecorderRunReport {
            run_id: state.run_id.clone(),
            status,
            output_dir: self.run_dir.display().to_string(),
            recording_apis: state.recording_apis.clone(),
            observed_api_count: state.observed_apis.len(),
            api_methods: state
                .finished
                .then(|| crate::recording_api::methods::from_observed(&state.observed_apis)),
            access_policy: self.access_policy.as_str(),
            traffic_jsonl: self.traffic_jsonl.as_str(),
            published_cases: state.published_cases,
            failed_cases: state.failed_cases,
            completion_reason: state.completion_reason,
            errors: state.errors.clone(),
        };
        drop(state);
        write_pretty_json(&self.run_dir.join("recording-run.json"), &report).await
    }
}

fn case_archive_directory(case: &CaseContext) -> String {
    sanitize_path_component(case.uri_group.as_deref().unwrap_or(&case.rule_name))
}

pub(crate) async fn write_pretty_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
    }
    let mut payload = serde_json::to_vec_pretty(value).context("failed to serialize JSON file")?;
    payload.push(b'\n');
    super::storage::write(path, &payload)
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

pub(super) async fn create_run_dir(
    root: &Path,
    explicit: Option<String>,
) -> Result<(String, PathBuf)> {
    if let Some(id) = &explicit {
        anyhow::ensure!(
            id.len() == 14
                && id.bytes().all(|c| c.is_ascii_digit())
                && chrono::NaiveDateTime::parse_from_str(id, "%Y%m%d%H%M%S").is_ok(),
            "recording run ID must be a valid 14-digit UTC timestamp"
        );
    }
    let now = Utc::now();
    for offset in 0..120 {
        let run_id = explicit.clone().unwrap_or_else(|| {
            (now + chrono::Duration::seconds(offset))
                .format("%Y%m%d%H%M%S")
                .to_string()
        });
        let run_dir = root.join(&run_id);
        match tokio::fs::create_dir(&run_dir).await {
            Ok(()) => return Ok((run_id, run_dir)),
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && explicit.is_none() =>
            {
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create recording run dir {}", run_dir.display())
                });
            }
        }
    }
    bail!("failed to reserve a unique recording run ID")
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
            rule_name: "http-rule".to_string(),
            uri_group: Some(group.to_string()),
        }
    }

    #[tokio::test]
    async fn automatic_run_ids_are_unique_and_explicit_ids_never_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let (first, second) = tokio::join!(
            create_run_dir(root.path(), None),
            create_run_dir(root.path(), None)
        );
        let (first, first_dir) = first.unwrap();
        let (second, second_dir) = second.unwrap();
        assert_ne!(first, second);
        assert_ne!(first_dir, second_dir);
        tokio::fs::write(first_dir.join("keep"), b"evidence")
            .await
            .unwrap();
        assert!(create_run_dir(root.path(), Some(first)).await.is_err());
        assert_eq!(
            tokio::fs::read(first_dir.join("keep")).await.unwrap(),
            b"evidence"
        );
        assert!(
            create_run_dir(root.path(), Some("20261399000000".into()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn published_case_counts_are_grouped_and_ignore_failed_cases() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let first = case("api-users-wildcard");
        let mut second = case("api-users-wildcard");
        second.rule_name = "another-http-rule".to_string();
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
        assert_eq!(
            recorder.case_dir(&first).parent(),
            Some(recorder.run_dir.join("apis/api-users-wildcard").as_path())
        );
        assert!(!recorder.run_dir.join("http-rule").exists());
        assert!(!recorder.run_dir.join("another-http-rule").exists());
        assert!(recorder.run_dir.join("apis").is_dir());

        let report_raw = tokio::fs::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
        assert_eq!(report["status"], "running");
        assert_eq!(report["published_cases"], 3);
        assert_eq!(report["failed_cases"], 1);
        assert_eq!(report["observed_api_count"], 0);
    }

    #[tokio::test]
    async fn final_manifest_persists_per_api_methods_from_successfully_published_cases() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        for api in [
            "GET /api/teams",
            "OPTIONS /api/teams",
            "GET /api/teams",
            "POST /api/users",
        ] {
            recorder
                .publish_case_for_api(&case("api"), Some(api))
                .await
                .unwrap();
        }
        let path = recorder.run_dir.join("recording-run.json");
        let running: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        assert!(running.get("api_methods").is_none());
        recorder
            .fail_case(&case("failed-only-api"), "failed", "failed case")
            .await
            .unwrap();
        recorder.finish_run().await.unwrap();
        let methods = crate::recording_api::methods::load(&recorder.run_dir).unwrap();
        assert_eq!(
            serde_json::to_value(methods).unwrap(),
            serde_json::json!({
                "/api/teams": ["GET", "OPTIONS"], "/api/users": ["POST"]
            })
        );
        let finalized = tokio::fs::read(&path).await.unwrap();
        // The finalized metadata cannot be changed by a late case.
        assert!(
            recorder
                .publish_case_for_api(&case("api"), Some("DELETE /api/teams"))
                .await
                .is_err()
        );
        assert_eq!(tokio::fs::read(&path).await.unwrap(), finalized);
    }

    #[tokio::test]
    async fn explicit_api_case_limits_complete_only_after_published_cases() {
        let temp = tempfile::tempdir().unwrap();
        let config = crate::config::RecordingConfig::default();
        let recorder = Recorder::new_with_recording_config_at_and_run_id(
            &config,
            temp.path(),
            None,
            vec![("GET /api/users/*".to_string(), 2)],
            None,
        )
        .await
        .unwrap();
        let failed = case("api-users-wildcard");
        recorder
            .fail_case(&failed, "test_failure", "expected test failure")
            .await
            .unwrap();
        assert_eq!(
            recorder
                .published_recording_api_count("GET /api/users/*")
                .await,
            Some(0)
        );

        recorder
            .publish_case_for_api(&case("api-users-wildcard"), Some("GET /api/users/*"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(recorder.run_dir.join("recording-run.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["observed_api_count"], serde_json::json!(1));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                recorder.wait_for_explicit_api_case_limit(),
            )
            .await
            .is_err()
        );

        recorder
            .publish_case_for_api(&case("api-users-wildcard"), Some("GET /api/users/*"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(recorder.run_dir.join("recording-run.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["observed_api_count"], serde_json::json!(1));
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            recorder.wait_for_explicit_api_case_limit(),
        )
        .await
        .unwrap();
        recorder
            .set_completion_reason(RecordingCompletionReason::PerApiCaseLimitReached)
            .await;
        assert!(recorder.finish_run().await.unwrap());

        let report_raw = tokio::fs::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
        assert_eq!(report["published_cases"], 2);
        assert_eq!(report["observed_api_count"], 1);
        assert_eq!(report["completion_reason"], "per_api_case_limit_reached");
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

        let indexed_case = case("api-index");
        recorder.publish_case(&indexed_case).await.unwrap();
        recorder.finish_run().await.unwrap();

        let dependency = recorder.case_dir(&indexed_case).join("dependencies.jsonl");
        let fragment = recorder
            .case_dir(&indexed_case)
            .join(crate::dependency_index::FRAGMENT);
        let index: crate::dependency_index::FileIndex =
            crate::dependency_index::store::read_json(&fragment).unwrap();
        assert_eq!(
            index.stamp,
            crate::dependency_index::FileStamp::read(&dependency).unwrap()
        );
        assert_eq!(std::fs::metadata(&fragment).unwrap().uid(), owner.uid());

        for path in [recorder.run_dir.as_ref(), artifact.as_path()] {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            assert_eq!(metadata.uid(), owner.uid());
            assert_eq!(metadata.gid(), owner.gid());
        }
    }
}
