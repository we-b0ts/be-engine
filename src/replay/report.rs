use super::*;

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
        state.snapshot_report()
    };
    if let Some(parent) = report_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create replay report dir {}", parent.display()))?;
    }
    let mut payload =
        serde_json::to_vec_pretty(&report).context("failed to serialize replay report")?;
    payload.push(b'\n');
    tokio::fs::write(&report_path, payload)
        .await
        .with_context(|| format!("failed to write replay report {}", report_path.display()))
}
