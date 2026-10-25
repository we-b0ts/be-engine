//! HTTP body bindings use immutable API selection and dependency-local clocks.
use super::*;

impl RequestContracts {
    pub(super) fn observe_unified_http_source(&self, case: &str, event: &Value) -> Result<()> {
        if event["event_type"] != "http_exchange" || self.compiled_rules().is_none() {
            return Ok(());
        }
        let anchor = self.anchor(case)?;
        crate::replay::http::contracts::observe_source(self, case, event, &anchor.dir)
    }
}
