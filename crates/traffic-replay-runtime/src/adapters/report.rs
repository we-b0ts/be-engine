use super::*;
pub use traffic_engine::protocols::replay::report::*;
use traffic_replay::report::{
    Change, GlobalReportProjection, GlobalReportRuntime, ReportRows, Row,
};
impl GlobalReportProjection for ReplayProtocols {
    fn global_report_protocols(&self) -> Vec<String> {
        Vec::new()
    }
    fn global_report_semantics(&self, _: &str) -> Option<String> {
        None
    }
    fn global_report_is_stable(&self, _: &str) -> bool {
        true
    }
    fn global_report_layout(&self, _: &str) -> Result<Vec<usize>> {
        anyhow::bail!("unknown specialized report")
    }
    fn visit_global_report(
        &self,
        _: &str,
        _: ReportRows,
        _: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        anyhow::bail!("unknown specialized report")
    }
}
impl GlobalReportRuntime for ReplayProtocols {
    fn global_report_snapshot(&self, _: &str) -> Result<(usize, Vec<Change>)> {
        anyhow::bail!("unknown specialized report")
    }
    fn initialize_global_report(&mut self, _: &str, _: usize) -> Result<()> {
        anyhow::bail!("unknown specialized report")
    }
}

impl ReplayProtocols {
    pub(crate) fn global_report_extensions(
        &self,
        _protocol: &str,
        _report: &Path,
    ) -> Result<BTreeMap<String, serde_json::Value>> {
        Ok(BTreeMap::new())
    }
    pub(crate) fn global_report_fallback(
        &self,
        _protocol: &str,
        _report: &Path,
        pages: crate::dependency_index::PageManifest,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(pages)?)
    }
}
