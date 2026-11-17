#[cfg(any(test, feature = "test-support"))]
use super::*;
pub use traffic_engine::replay::report::writer::*;
#[cfg(any(test, feature = "test-support"))]
pub(crate) async fn write_report_snapshot<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    let Some(report_path) = report_path else {
        return Ok(());
    };
    write_report_snapshot_to_path(state, &report_path).await
}
#[cfg(any(test, feature = "test-support"))]
async fn write_report_snapshot_to_path<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
    report_path: &Path,
) -> Result<()> {
    let report = {
        let state = state.lock().await;
        state.snapshot_report()
    };
    write_report_value(report_path, &report).await
}
