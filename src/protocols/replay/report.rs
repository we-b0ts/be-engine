//! Native report adapters bind protocol facts to shared row and visibility contracts.
pub(crate) mod aggregate;
#[cfg(test)]
mod aggregate_tests;
use crate::protocols::replay::mysql;
use mysql::MysqlReplayState;
pub(crate) mod artifacts;
pub(crate) mod codecs;
pub(crate) mod evidence;
pub(crate) mod ownership;
pub(crate) mod snapshot;
pub(super) mod unused_source;
pub(crate) mod validation;
use super::*;

use traffic_replay::report::{
    Change, GlobalReportProjection, GlobalReportRuntime, ReportRows, Row,
};

pub(crate) const PROTOCOLS: [&str; 1] = ["mysql"];
pub(crate) fn semantics(protocol: &str) -> Option<String> {
    (protocol == "mysql").then(|| "mysql-transaction-diagnostics-v6-source-read-proof".to_owned())
}
pub(crate) struct ReportView<'a> {
    pub mysql: &'a MysqlReplayState,
}

impl<'a> From<&'a ReplayProtocols> for ReportView<'a> {
    fn from(protocols: &'a ReplayProtocols) -> Self {
        Self {
            mysql: &protocols.mysql,
        }
    }
}

impl GlobalReportProjection for ReportView<'_> {
    fn global_report_protocols(&self) -> Vec<String> {
        PROTOCOLS
            .iter()
            .map(|protocol| (*protocol).into())
            .collect()
    }
    fn global_report_semantics(&self, protocol: &str) -> Option<String> {
        semantics(protocol)
    }
    fn global_report_is_stable(&self, protocol: &str) -> bool {
        let _ = protocol;
        true
    }
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>> {
        Ok(match protocol {
            "mysql" => self.mysql.global_report_usage().layout().to_vec(),

            _ => anyhow::bail!("unknown Global projection protocol"),
        })
    }
    fn visit_global_report(
        &self,
        protocol: &str,
        rows: ReportRows,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        let extras = matches!(rows, ReportRows::Extras);
        match protocol {
            "mysql" => self.mysql.visit_global_report_range(extras, visitor),
            _ => anyhow::bail!("unknown Global projection protocol"),
        }
    }
}

impl GlobalReportProjection for ReplayProtocols {
    fn global_report_protocols(&self) -> Vec<String> {
        ReportView::from(self).global_report_protocols()
    }
    fn global_report_semantics(&self, protocol: &str) -> Option<String> {
        semantics(protocol)
    }
    fn global_report_is_stable(&self, protocol: &str) -> bool {
        ReportView::from(self).global_report_is_stable(protocol)
    }
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>> {
        ReportView::from(self).global_report_layout(protocol)
    }
    fn visit_global_report(
        &self,
        protocol: &str,
        rows: ReportRows,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        ReportView::from(self).visit_global_report(protocol, rows, visitor)
    }
}
impl GlobalReportRuntime for ReplayProtocols {
    fn global_report_snapshot(&self, protocol: &str) -> Result<(usize, Vec<Change>)> {
        match protocol {
            "mysql" => self.mysql.global_report_snapshot(),

            _ => anyhow::bail!("unknown Global projection protocol"),
        }
    }
    fn initialize_global_report(&mut self, protocol: &str, visible: usize) -> Result<()> {
        match protocol {
            "mysql" => self.mysql.initialize_global_report_usage(visible),

            _ => anyhow::bail!("unknown Global projection protocol"),
        }
        Ok(())
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
