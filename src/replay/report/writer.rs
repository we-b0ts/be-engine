use std::future::pending;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

use super::super::ReplayState;
use super::dependency_evidence::{build_dependency_evidence, dependency_evidence_path};

const SNAPSHOT_DEBOUNCE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub(in crate::replay) struct ReplayReportWriter {
    report_path: Option<PathBuf>,
    notify: Arc<Notify>,
    #[cfg(test)]
    completed_writes: Arc<AtomicUsize>,
}

impl ReplayReportWriter {
    pub(in crate::replay) fn new(report_path: Option<PathBuf>) -> Self {
        Self {
            report_path,
            notify: Arc::new(Notify::new()),
            #[cfg(test)]
            completed_writes: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(in crate::replay) fn request(&self) {
        if self.report_path.is_some() {
            self.notify.notify_one();
        }
    }

    pub(in crate::replay) async fn run(&self, state: Arc<Mutex<ReplayState>>) -> Result<()> {
        let Some(report_path) = self.report_path.clone() else {
            return pending::<Result<()>>().await;
        };
        loop {
            self.notify.notified().await;
            tokio::time::sleep(SNAPSHOT_DEBOUNCE).await;
            write_report_snapshot_to_path(state.clone(), &report_path).await?;
            #[cfg(test)]
            self.completed_writes.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(in crate::replay) async fn flush(&self, state: Arc<Mutex<ReplayState>>) -> Result<()> {
        write_report_snapshot(state, self.report_path.clone()).await
    }

    #[cfg(test)]
    pub(super) fn completed_writes(&self) -> usize {
        self.completed_writes.load(Ordering::Relaxed)
    }
}

pub(in crate::replay) async fn write_report_snapshot(
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    let Some(report_path) = report_path else {
        return Ok(());
    };
    write_report_snapshot_to_path(state, &report_path).await
}

async fn write_report_snapshot_to_path(
    state: Arc<Mutex<ReplayState>>,
    report_path: &Path,
) -> Result<()> {
    let report_write_lock = {
        let state = state.lock().await;
        state.report_write_lock.clone()
    };
    let _write_guard = report_write_lock.lock().await;
    let report = {
        let state = state.lock().await;
        if state.finalized_at.is_some() {
            return Ok(());
        }
        state.snapshot_report()
    };
    write_report_value(report_path, &report).await
}

pub(in crate::replay) async fn write_final_report_value(
    state: Arc<Mutex<ReplayState>>,
    report_path: PathBuf,
    report: &Value,
) -> Result<()> {
    let report_write_lock = {
        let state = state.lock().await;
        state.report_write_lock.clone()
    };
    let _write_guard = report_write_lock.lock().await;
    write_report_value(&report_path, report).await?;
    let evidence = build_dependency_evidence(report);
    write_report_value(&dependency_evidence_path(&report_path), &evidence).await
}

async fn write_report_value(report_path: &Path, report: &impl Serialize) -> Result<()> {
    if let Some(parent) = report_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create replay report dir {}", parent.display()))?;
    }
    let mut payload = serde_json::to_vec(report).context("failed to serialize replay report")?;
    payload.push(b'\n');
    let file_name = report_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("replay-report.json");
    let temporary_path = report_path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    tokio::fs::write(&temporary_path, payload)
        .await
        .with_context(|| {
            format!(
                "failed to write temporary replay report {}",
                temporary_path.display()
            )
        })?;
    if let Err(error) = tokio::fs::rename(&temporary_path, report_path).await {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(error)
            .with_context(|| format!("failed to publish replay report {}", report_path.display()));
    }
    Ok(())
}
