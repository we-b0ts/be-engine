//! Native report adapters bind protocol facts to shared row and visibility contracts.
pub(crate) mod aggregate;
#[cfg(test)]
mod aggregate_tests;
use crate::protocols::replay::http;
use crate::protocols::replay::mysql;
use mysql::MysqlReplayState;
pub(crate) mod artifacts;
pub(crate) mod codecs;
pub(crate) mod evidence;
pub(crate) mod ownership;
pub(crate) mod redis;
pub(crate) mod snapshot;
pub(super) mod unused_source;
pub(crate) mod validation;
use super::redis as redis_state;
use super::*;

use traffic_replay::report::{
    Change, GlobalReportProjection, GlobalReportRuntime, ReportRows, Row,
};

pub(crate) const PROTOCOLS: [&str; 3] = ["mysql", "redis", "http"];
pub(crate) fn semantics(protocol: &str) -> Option<String> {
    (protocol == "mysql").then(|| "mysql-transaction-diagnostics-v6-source-read-proof".to_owned())
}
pub(crate) struct ReportView<'a> {
    pub mysql: &'a MysqlReplayState,
    pub http: &'a [http::ReplayHttpExchange],
    pub http_events: &'a http::HttpReplayEvents,
    pub redis: &'a redis_state::RedisReplayState,
}

impl<'a> From<&'a ReplayProtocols> for ReportView<'a> {
    fn from(protocols: &'a ReplayProtocols) -> Self {
        Self {
            mysql: &protocols.mysql,
            http: &protocols.http_exchanges,
            http_events: &protocols.http_events,
            redis: &protocols.redis,
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
        protocol != "http" || http::global_report_sharing_is_stable(self.http)
    }
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>> {
        Ok(match protocol {
            "mysql" => self.mysql.global_report_usage().layout().to_vec(),
            "http" => self.http_events.global_report.layout().to_vec(),
            "redis" => self.redis.global_report_layout(),

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
            "http" => http::visit_global_report_rows(
                self.http,
                &self.http_events.global_report,
                extras,
                visitor,
            ),
            "redis" if extras => self.redis.visit_global_report_extras(visitor),
            "redis" => self.redis.visit_global_report_rows(visitor),

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
            "http" => self.http_events.global_report.snapshot(),
            "redis" => self.redis.global_report_snapshot(),

            _ => anyhow::bail!("unknown Global projection protocol"),
        }
    }
    fn initialize_global_report(&mut self, protocol: &str, visible: usize) -> Result<()> {
        match protocol {
            "mysql" => self.mysql.initialize_global_report_usage(visible),
            "http" => self.http_events.global_report.initialize(visible),
            "redis" => self.redis.initialize_global_report_usage(visible),

            _ => anyhow::bail!("unknown Global projection protocol"),
        }
        Ok(())
    }
}

impl ReplayProtocols {
    pub(crate) fn global_report_extensions(
        &self,
        protocol: &str,
        report: &Path,
    ) -> Result<BTreeMap<String, serde_json::Value>> {
        if protocol != "redis" {
            return Ok(BTreeMap::new());
        }
        redis::fields(redis::notifications::NotificationEvidence::prepare(
            report,
            self.redis.global_notification_evidence()?,
        )?)
    }
    pub(crate) fn global_report_fallback(
        &self,
        protocol: &str,
        report: &Path,
        pages: crate::dependency_index::PageManifest,
    ) -> Result<serde_json::Value> {
        if protocol == "redis"
            && let Some(evidence) = redis::notifications::RedisEvidence::prepare(
                report,
                pages.clone(),
                self.redis.global_notification_evidence()?,
            )?
        {
            return Ok(serde_json::to_value(evidence)?);
        }
        Ok(serde_json::to_value(pages)?)
    }
}
