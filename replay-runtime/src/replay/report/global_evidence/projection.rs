//! Common report ownership composes application adapters and registered native inventories.
use crate::replay::{ReplayProtocolSet, RuntimeState};
use anyhow::Result;
use traffic_replay::report::{
    Change, GlobalReportProjection, GlobalReportRuntime, JoinedProjection, ReportRows, Row,
};

impl<P: ReplayProtocolSet> GlobalReportProjection for RuntimeState<P> {
    fn global_report_protocols(&self) -> Vec<String> {
        JoinedProjection::new(&self.protocols, &self.native).global_report_protocols()
    }
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>> {
        JoinedProjection::new(&self.protocols, &self.native).global_report_layout(protocol)
    }
    fn global_report_semantics(&self, protocol: &str) -> Option<String> {
        JoinedProjection::new(&self.protocols, &self.native).global_report_semantics(protocol)
    }
    fn global_report_is_stable(&self, protocol: &str) -> bool {
        JoinedProjection::new(&self.protocols, &self.native).global_report_is_stable(protocol)
    }
    fn visit_global_report(
        &self,
        protocol: &str,
        rows: ReportRows,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        JoinedProjection::new(&self.protocols, &self.native)
            .visit_global_report(protocol, rows, visitor)
    }
}
impl<P: ReplayProtocolSet> GlobalReportRuntime for RuntimeState<P> {
    fn global_report_snapshot(&self, protocol: &str) -> Result<(usize, Vec<Change>)> {
        if self.native.owns_global_report(protocol) {
            self.native.global_report_snapshot(protocol)
        } else {
            self.protocols.global_report_snapshot(protocol)
        }
    }
    fn initialize_global_report(&mut self, protocol: &str, visible: usize) -> Result<()> {
        if self.native.owns_global_report(protocol) {
            self.native.initialize_global_report(protocol, visible)
        } else {
            self.protocols.initialize_global_report(protocol, visible)
        }
    }
}
