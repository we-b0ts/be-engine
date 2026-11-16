//! Read-only layouts for retired protocol reports.
use serde_json::Value;
use traffic_protocol::report::{ReportCodec, diagnostics::DiagnosticSchema};

pub(crate) const HISTORICAL_PROTOCOLS: [&str; 3] = ["memcached", "motan", "kafka"];

pub(crate) struct Builtin;
impl DiagnosticSchema for Builtin {
    fn section<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report[protocol]
    }
    fn matched_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report[protocol]["matched"]
    }
}
impl ReportCodec for Builtin {
    fn validate_legacy_session(
        &self,
        report: &Value,
        protocol: &str,
    ) -> anyhow::Result<Option<usize>> {
        traffic_protocol::report::validation::named_section(report, protocol)
    }
    fn diagnostics(&self) -> &dyn DiagnosticSchema {
        self
    }
    fn unused_case_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report[protocol]["unused_case"]
    }
    fn reclassified_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report[protocol]["unused_global"]
    }
    fn supports_source_occurrences(&self) -> bool {
        false
    }
}
