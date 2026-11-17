//! Session layout validation delegates to the installed report adapters.
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_replay::report::evidence::SessionEvidence;

pub(crate) fn validate_completed_receipt(
    report: &Value,
) -> Result<crate::replay::BatchReconciliation> {
    crate::replay::validate_completed_receipt_with(report, &NativeSessionEvidence)
}

pub(crate) struct NativeSessionEvidence;
impl SessionEvidence for NativeSessionEvidence {
    fn validate_session(&self, report: &Value) -> Result<BTreeMap<String, usize>> {
        crate::protocols::default_providers()
            .report_codecs()
            .validate_legacy_sessions(report)
    }
}
