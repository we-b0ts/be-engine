use super::*;

pub(crate) mod aggregate;
#[cfg(test)]
mod aggregate_tests;
pub(super) mod command;
mod model;

pub(super) use model::*;

pub(super) async fn write_report_snapshot(
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    let Some(report_path) = report_path else {
        return Ok(());
    };
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
    write_report_value(&report_path, &report).await
}

pub(super) async fn write_final_report_value(
    state: Arc<Mutex<ReplayState>>,
    report_path: PathBuf,
    report: &Value,
) -> Result<()> {
    let report_write_lock = {
        let state = state.lock().await;
        state.report_write_lock.clone()
    };
    let _write_guard = report_write_lock.lock().await;
    write_report_value(&report_path, report).await
}

async fn write_report_value(report_path: &Path, report: &impl Serialize) -> Result<()> {
    if let Some(parent) = report_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create replay report dir {}", parent.display()))?;
    }
    let mut payload =
        serde_json::to_vec_pretty(&report).context("failed to serialize replay report")?;
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
    if let Err(error) = tokio::fs::rename(&temporary_path, &report_path).await {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(error)
            .with_context(|| format!("failed to publish replay report {}", report_path.display()));
    }
    Ok(())
}
