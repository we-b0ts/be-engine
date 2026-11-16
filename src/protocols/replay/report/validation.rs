//! Historical native fields validate through the application evidence adapter.
use anyhow::{Result, ensure};
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_replay::report::evidence::{SessionEvidence, array, empty, number};

pub(crate) fn validate_completed_receipt(
    report: &Value,
) -> Result<crate::replay::BatchReconciliation> {
    crate::replay::validate_completed_receipt_with(report, &NativeSessionEvidence)
}

pub(crate) struct NativeSessionEvidence;
impl SessionEvidence for NativeSessionEvidence {
    fn validate_session(&self, report: &Value) -> Result<BTreeMap<String, usize>> {
        empty(
            report,
            &[
                "unmatched_queries",
                "unsupported_commands",
                "unused_case_exchanges",
                "unmatched_http_requests",
                "unsupported_http_exchanges",
                "http_request_header_mismatches",
                "unused_case_http_exchanges",
            ],
        )?;
        let mut unused = BTreeMap::from([
            (
                "mysql".into(),
                number(report, "unused_global_exchange_count")? as usize,
            ),
            (
                "http".into(),
                number(report, "unused_global_http_exchange_count")? as usize,
            ),
        ]);
        empty(
            report,
            &["unused_global_exchanges", "unused_global_http_exchanges"],
        )?;
        for protocol in ["redis", "memcached", "motan", "kafka"] {
            let native = match report.get(protocol) {
                Some(native) => native,
                None if super::codecs::HISTORICAL_PROTOCOLS.contains(&protocol) => continue,
                None => anyhow::bail!("actual Replay report lacks {protocol} evidence"),
            };
            empty(
                native,
                &[
                    "unmatched",
                    "unsupported",
                    "unsafe_events",
                    "unused_case",
                    "unused_global",
                ],
            )?;
            let count = native["unused_global_count"].as_u64().unwrap_or(0) as usize;
            unused.insert(protocol.into(), count);
        }
        let ingress = &report["http_ingress"];
        ensure!(
            number(ingress, "omitted")? == 0
                && number(ingress, "pending")? == 0
                && array(ingress, "observations")?
                    .iter()
                    .all(|o| o["status"] == "body_complete"),
            "actual HTTP request ingress remains incomplete or cancelled"
        );
        Ok(unused)
    }
}
