use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::info;

use super::model::{CaseKind, ComparisonRecordingCase};
use super::summary::ComparisonRecordingSummary;
use crate::recorder::sanitize_path_component;
use crate::recording_completion::ExplicitApiCaseLimits;

#[derive(Default)]
struct Quota {
    published: usize,
    reserved: usize,
}

#[derive(Clone)]
pub(super) struct ComparisonRecordingStore {
    run_dir: Arc<PathBuf>,
    quotas: Arc<Mutex<HashMap<String, Quota>>>,
    explicit_api_case_limits: ExplicitApiCaseLimits,
    summary: ComparisonRecordingSummary,
}

pub(super) struct Reservation {
    key: String,
}

impl ComparisonRecordingStore {
    pub(super) async fn create(
        output_dir: &Path,
        run_id: &str,
        recording_api_limits: Vec<(String, usize)>,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(output_dir)
            .await
            .with_context(|| format!("failed to create {}", output_dir.display()))?;
        let run_dir = output_dir.join(run_id);
        tokio::fs::create_dir(&run_dir).await.with_context(|| {
            format!(
                "failed to create comparison recording run {}",
                run_dir.display()
            )
        })?;
        let recording_apis = recording_api_limits
            .iter()
            .map(|(api, _)| api.clone())
            .collect();
        let summary = ComparisonRecordingSummary::new(run_id.to_string(), &run_dir, recording_apis);
        summary.flush().await?;
        Ok(Self {
            run_dir: Arc::new(run_dir),
            quotas: Arc::new(Mutex::new(HashMap::new())),
            explicit_api_case_limits: ExplicitApiCaseLimits::new(recording_api_limits),
            summary,
        })
    }

    pub(super) fn summary(&self) -> &ComparisonRecordingSummary {
        &self.summary
    }

    pub(super) async fn fail_unfinished(&self) -> Result<()> {
        let staging_root = self.run_dir.join("staging");
        if !tokio::fs::try_exists(&staging_root).await? {
            return Ok(());
        }
        let failed_root = self.run_dir.join("failed");
        let unfinished = tokio::task::spawn_blocking(move || {
            let mut leaves = Vec::new();
            collect_leaf_directories(&staging_root, &staging_root, &mut leaves)?;
            for relative in &leaves {
                let source = staging_root.join(relative);
                let target = failed_root.join(relative);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::rename(&source, &target)?;
                std::fs::write(
                    target.join("recording-error.json"),
                    b"{\"error\":\"comparison recording case remained in staging during shutdown\"}\n",
                )?;
            }
            Ok::<usize, anyhow::Error>(leaves.len())
        })
        .await
        .context("unfinished comparison recording case cleanup task panicked")??;
        if unfinished > 0 {
            self.summary
                .update(|counts| counts.failed += unfinished)
                .await;
            self.summary
                .record_error(format!(
                    "{unfinished} comparison recording case(s) remained in staging during shutdown"
                ))
                .await;
        }
        Ok(())
    }

    pub(super) async fn try_reserve(
        &self,
        recording_api: &str,
        limit: usize,
    ) -> Option<Reservation> {
        let key = recording_api.to_string();
        let mut quotas = self.quotas.lock().await;
        let quota = quotas.entry(key.clone()).or_default();
        if quota.published.saturating_add(quota.reserved) >= limit {
            drop(quotas);
            self.summary
                .update(|counts| counts.suppressed_by_case_limit += 1)
                .await;
            self.summary
                .api_update(recording_api, |counts| counts.suppressed_by_case_limit += 1)
                .await;
            return None;
        }
        quota.reserved += 1;
        Some(Reservation { key })
    }

    pub(super) async fn publish(
        &self,
        case: &ComparisonRecordingCase,
        reservation: Reservation,
    ) -> Result<()> {
        let result = self.write_and_publish(case).await;
        match result {
            Ok(()) => {
                self.commit(reservation).await;
                self.summary.update(|counts| counts.published += 1).await;
                let recording_api = format!("{} {}", case.request.method, case.request.api_pattern);
                self.summary
                    .api_update(&recording_api, |counts| counts.published += 1)
                    .await;
                if self
                    .explicit_api_case_limits
                    .record_published(&recording_api)
                    .await
                {
                    info!("every explicitly selected comparison API reached its case limit");
                }
                Ok(())
            }
            Err(error) => {
                self.release(reservation).await;
                let message = format!(
                    "comparison recording case {} failed to publish: {error:#}",
                    case.id
                );
                let _ = self.move_to_failed(case, &message).await;
                self.summary.update(|counts| counts.failed += 1).await;
                let recording_api = format!("{} {}", case.request.method, case.request.api_pattern);
                self.summary
                    .api_update(&recording_api, |counts| counts.failed += 1)
                    .await;
                self.summary.record_error(message).await;
                Err(error)
            }
        }
    }

    async fn write_and_publish(&self, case: &ComparisonRecordingCase) -> Result<()> {
        let staging = self.case_path("staging", case);
        tokio::fs::create_dir_all(&staging)
            .await
            .with_context(|| format!("failed to create {}", staging.display()))?;
        write_json(&staging.join("case-kind.json"), &CaseKind::default()).await?;
        write_json(&staging.join("request.json"), &case.request).await?;
        write_json(&staging.join("expected-response.json"), &case.baseline).await?;
        write_json(&staging.join("response.json"), &case.candidate).await?;
        if let Some(recheck) = &case.baseline_recheck {
            write_json(&staging.join("expected-response-after.json"), recheck).await?;
        }
        sync_dir(&staging).await?;

        let published = self.published_path(case);
        let parent = published
            .parent()
            .context("comparison recording case has no parent")?;
        tokio::fs::create_dir_all(parent).await?;
        tokio::fs::rename(&staging, &published)
            .await
            .with_context(|| {
                format!(
                    "failed to publish comparison recording case from {} to {}",
                    staging.display(),
                    published.display()
                )
            })?;
        sync_dir(parent).await
    }

    async fn move_to_failed(&self, case: &ComparisonRecordingCase, message: &str) -> Result<()> {
        let staging = self.case_path("staging", case);
        let failed = self.case_path("failed", case);
        if let Some(parent) = failed.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if tokio::fs::try_exists(&staging).await? {
            tokio::fs::rename(&staging, &failed).await?;
        } else {
            tokio::fs::create_dir_all(&failed).await?;
        }
        write_json(
            &failed.join("recording-error.json"),
            &serde_json::json!({
                "case_id": case.id,
                "error": message,
            }),
        )
        .await
    }

    fn published_path(&self, case: &ComparisonRecordingCase) -> PathBuf {
        self.run_dir
            .join("apis")
            .join(sanitize_path_component(&case.group))
            .join(case.id.to_string())
    }

    fn case_path(&self, area: &str, case: &ComparisonRecordingCase) -> PathBuf {
        self.run_dir
            .join(area)
            .join(sanitize_path_component(&case.group))
            .join(case.id.to_string())
    }

    async fn commit(&self, reservation: Reservation) {
        let mut quotas = self.quotas.lock().await;
        let quota = quotas
            .get_mut(&reservation.key)
            .expect("comparison recording reservation quota exists");
        quota.reserved -= 1;
        quota.published += 1;
    }

    pub(super) async fn release(&self, reservation: Reservation) {
        if let Some(quota) = self.quotas.lock().await.get_mut(&reservation.key) {
            quota.reserved = quota.reserved.saturating_sub(1);
        }
    }

    pub(super) async fn wait_for_explicit_api_case_limit(&self) {
        self.explicit_api_case_limits.wait_until_complete().await;
    }
}

async fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut payload = serde_json::to_vec_pretty(value)
        .context("failed to serialize comparison recording artifact")?;
    payload.push(b'\n');
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .await
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(&payload).await?;
    crate::artifact_file::flush_all_and_evict(&mut file, 0)
        .await
        .with_context(|| format!("failed to finalize {}", path.display()))?;
    Ok(())
}

async fn sync_dir(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        std::fs::File::open(&path)
            .and_then(|file| file.sync_all())
            .with_context(|| format!("failed to sync directory {}", path.display()))
    })
    .await
    .context("comparison recording directory sync task panicked")?
}

fn collect_leaf_directories(root: &Path, directory: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if directory != root
        && directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| uuid::Uuid::parse_str(name).is_ok())
    {
        out.push(directory.strip_prefix(root)?.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_leaf_directories(root, &entry.path(), out)?;
        }
    }
    Ok(())
}
