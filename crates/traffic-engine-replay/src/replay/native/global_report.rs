//! Complete Global evidence for registered protocols uses shared rows and actual delivery state.
use super::*;
use traffic_replay::report::{
    Change, GlobalReportProjection, GlobalReportRuntime, Position, ReportRows, Row, Usage,
};

impl Inventory {
    pub fn freeze_global_report_layout(&mut self) {
        self.global_usage = self
            .providers
            .registrations()
            .iter()
            .filter(|entry| entry.provider.native_protocol().is_some())
            .map(|entry| {
                let mut usage = Usage::default();
                usage.freeze_layout(vec![self.core.exchanges.len()]);
                (entry.kind.id(), usage)
            })
            .collect();
    }
    pub fn owns_global_report(&self, protocol: &str) -> bool {
        self.global_usage.keys().any(|id| id.as_str() == protocol)
    }
    fn report_usage(&self, protocol: &str) -> Result<&Usage> {
        self.global_usage
            .iter()
            .find(|(id, _)| id.as_str() == protocol)
            .map(|(_, usage)| usage)
            .context("registered Global report inventory is absent")
    }
    pub fn refresh_global_report(&mut self, index: usize) {
        let exchange = &self.core.exchanges[index];
        if exchange.source.source.is_run_owned()
            && let Some(usage) = self.global_usage.get_mut(&exchange.protocol)
        {
            usage.observe(
                0,
                index,
                true,
                !self
                    .core
                    .lifecycle
                    .live_status(index, exchange.status)
                    .is_consumed(),
            );
        }
    }
    fn report_value(&self, index: usize) -> Result<Value> {
        let exchange = &self.core.exchanges[index];
        let native = self
            .providers
            .provider(crate::protocols::DependencyProtocol::new(
                exchange.protocol.as_str(),
            ))?
            .native_protocol()
            .context("registered Global report has no native protocol capability")?;
        let summary = native.report_summary(&exchange.native)?;
        Ok(serde_json::json!({
            "index":index,"source":exchange.source.source,"case_id":exchange.source.case_id,
            "protocol_ref":exchange.native.reference,"target":exchange.native.endpoint,
            "source_exchange_id":exchange.source.capture.as_ref().map(|capture| capture.exchange_id),
            "native":summary,
        }))
    }
    pub fn visit_global_unused(
        &self,
        protocol: &str,
        visitor: &mut dyn FnMut(Value) -> Result<()>,
    ) -> Result<()> {
        for exchange in &self.core.exchanges {
            if exchange.protocol.as_str() == protocol
                && exchange.source.source.is_run_owned()
                && !self
                    .core
                    .lifecycle
                    .live_status(exchange.index, exchange.status)
                    .is_consumed()
            {
                visitor(self.report_value(exchange.index)?)?;
            }
        }
        Ok(())
    }
}
impl GlobalReportProjection for Inventory {
    fn global_report_protocols(&self) -> Vec<String> {
        self.global_usage.keys().map(ToString::to_string).collect()
    }
    fn global_report_semantics(&self, protocol: &str) -> Option<String> {
        let provider = self
            .providers
            .registrations()
            .iter()
            .find(|entry| entry.kind.as_str() == protocol)?;
        Some(format!(
            "registered-native-global/v1:{}",
            provider.provider.native_protocol()?.report_semantics()
        ))
    }
    fn global_report_is_stable(&self, _protocol: &str) -> bool {
        true
    }
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>> {
        Ok(self.report_usage(protocol)?.layout().to_vec())
    }
    fn visit_global_report(
        &self,
        protocol: &str,
        rows: ReportRows,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        let extras = matches!(rows, ReportRows::Extras);
        for (index, exchange) in self
            .report_usage(protocol)?
            .rows(0, &self.core.exchanges, extras)
        {
            if exchange.protocol.as_str() == protocol && exchange.source.source.is_run_owned() {
                visitor(Row {
                    position: Position { section: 0, index },
                    visible: true,
                    value: self.report_value(index)?,
                })?;
            }
        }
        Ok(())
    }
}
impl GlobalReportRuntime for Inventory {
    fn global_report_snapshot(&self, protocol: &str) -> Result<(usize, Vec<Change>)> {
        self.report_usage(protocol)?.snapshot()
    }
    fn initialize_global_report(&mut self, protocol: &str, visible: usize) -> Result<()> {
        let usage = self
            .global_usage
            .iter_mut()
            .find(|(id, _)| id.as_str() == protocol)
            .map(|(_, usage)| usage)
            .context("registered Global report inventory is absent")?;
        usage.initialize(visible);
        Ok(())
    }
}
