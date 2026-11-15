//! Application bindings retain historical report field locations and native codecs.
mod diagnostics;
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
use traffic_protocol::report::{ReportCodec, ReportSection};

pub(crate) struct Builtin(pub &'static str);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyFields {
    #[serde(default)]
    notifications: Option<Value>,
}
struct Empty;
impl ReportSection for Empty {
    fn count(&self) -> Result<usize> {
        Ok(0)
    }
    fn read(
        &self,
        _report: &Path,
        _offset: usize,
        _limit: usize,
        _items: &mut Vec<Value>,
    ) -> Result<()> {
        Ok(())
    }
    fn stage(&self, _source: &Path, _destination: &Path) -> Result<Value> {
        Ok(serde_json::json!({}))
    }
}
impl ReportCodec for Builtin {
    fn diagnostics(&self) -> &dyn traffic_protocol::report::diagnostics::DiagnosticSchema {
        self
    }
    fn unused_case_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        match self.0 {
            "mysql" => &report["unused_case_exchanges"],
            "http" => &report["unused_case_http_exchanges"],
            _ => &report[protocol]["unused_case"],
        }
    }
    fn supports_source_occurrences(&self) -> bool {
        matches!(self.0, "mysql" | "redis")
    }
    fn requires_source_exchange_id(&self, row: &Value) -> bool {
        self.0 == "redis" && row["command"] == "PUBSUB_PUSH"
    }
    fn decode(&self, report: &Path, value: &Value) -> Result<Option<Box<dyn ReportSection>>> {
        if self.0 == "redis" {
            super::redis::decode(report, value)
        } else {
            Ok(None)
        }
    }
    fn decode_extensions(
        &self,
        report: &Path,
        fields: &BTreeMap<String, Value>,
    ) -> Result<Box<dyn ReportSection>> {
        if self.0 == "redis" {
            return super::redis::decode_extensions(report, fields);
        }
        let fields: EmptyFields = serde_json::from_value(serde_json::to_value(fields)?)?;
        ensure!(
            fields.notifications.is_none(),
            "Global inventory protocol differs from its report section"
        );
        Ok(Box::new(Empty))
    }
    fn reclassified_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        match self.0 {
            "mysql" => &report["unused_global_exchanges"],
            "http" => &report["unused_global_http_exchanges"],
            _ => &report[protocol]["unused_global"],
        }
    }
}
