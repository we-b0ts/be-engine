//! Bounded native diagnostics and complete finite-consumption counts.
use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct RequestFailure {
    pub case_id: Option<String>,
    pub protocol: String,
    pub target: TargetKey,
    pub target_event_index: Option<usize>,
    pub target_observation_id: Option<Uuid>,
    pub reason: String,
    #[serde(flatten)]
    pub diagnostics: diagnosis::CandidateDiagnostics,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnusedExchange {
    pub index: usize,
    pub case_id: Option<String>,
    pub source: ReplaySource,
    pub protocol_ref: traffic_model::recording::ProtocolRef,
    pub source_exchange_id: Option<Uuid>,
    pub target: TargetKey,
    pub status: ReplayExchangeStatus,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProtocolReport {
    pub matched_count: usize,
    pub unmatched_count: usize,
    pub unmatched: Vec<RequestFailure>,
    pub unused_case: Vec<UnusedExchange>,
    pub unused_global_count: usize,
    pub unused_global: Vec<UnusedExchange>,
}

impl Inventory {
    /// Publish counters only after the shared inventory commits delivery.
    pub fn publish_delivery(&mut self, index: usize, protocol: traffic_protocol::ProtocolId) {
        self.refresh_global_report(index);
        *self.matched.entry(protocol.as_str().into()).or_default() += 1;
    }

    pub fn source_occurrence_rows(
        &self,
        report: &Value,
    ) -> Vec<crate::replay::report::unused_source::SourceRow> {
        use crate::replay::report::unused_source::{SourceIdentity, SourceRow};
        let mut rows = Vec::new();
        for (protocol, section) in report["dependency_protocols"]
            .as_object()
            .into_iter()
            .flatten()
        {
            for (position, row) in section["unused_case"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                let Some(index) = row["index"]
                    .as_u64()
                    .and_then(|index| usize::try_from(index).ok())
                else {
                    continue;
                };
                let Some(exchange) = self.core.exchanges.get(index) else {
                    continue;
                };
                let Some(case) = exchange.source.case_id.as_deref() else {
                    continue;
                };
                let Some(capture) = &exchange.source.capture else {
                    continue;
                };
                if exchange.protocol.as_str() != protocol
                    || row["case_id"].as_str() != Some(case)
                    || exchange.source.source != ReplaySource::Case
                {
                    continue;
                }
                let escaped = protocol.replace('~', "~0").replace('/', "~1");
                rows.push(SourceRow {
                    pointer: format!("/dependency_protocols/{escaped}/unused_case/{position}"),
                    case: case.into(),
                    exchange_id: capture.exchange_id,
                    identity: SourceIdentity::Reference(exchange.native.reference.clone()),
                });
            }
        }
        rows
    }

    pub fn case_has_runtime_failure(&self, case: &str) -> bool {
        self.failure_counts
            .keys()
            .any(|(_, owner)| owner.as_deref() == Some(case))
    }

    pub fn case_is_dirty(&self, case: &str) -> bool {
        self.case_has_runtime_failure(case)
            || self.core.exchanges.iter().any(|exchange| {
                exchange.source.case_id.as_deref() == Some(case)
                    && !self
                        .core
                        .lifecycle
                        .live_status(exchange.index, exchange.status)
                        .is_consumed()
            })
    }

    pub fn failures_for_case(&self, case: &str, limit: usize) -> Vec<Value> {
        self.failures.iter().filter(|failure| failure.case_id.as_deref() == Some(case)).take(limit)
            .map(|failure| serde_json::json!({"protocol":failure.protocol,"kind":"native_request_or_delivery_failed","event":failure})).collect()
    }

    pub fn startup_counts(
        &mut self,
        close: bool,
    ) -> BTreeMap<String, traffic_replay::StartupCounts> {
        let mut counts = BTreeMap::<String, traffic_replay::StartupCounts>::new();
        for exchange in &mut self.core.exchanges {
            counts
                .entry(exchange.protocol.as_str().into())
                .or_default()
                .observe(exchange.source.source, &mut exchange.status, true, close);
        }
        counts
    }

    pub fn record_failure(
        &mut self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        case_id: Option<String>,
        observation: (Option<usize>, Option<Uuid>),
        reason: &str,
        diagnostics: diagnosis::CandidateDiagnostics,
    ) {
        // Each physical request or failed delivery keeps a bounded diagnostic.
        // The count remains independent of diagnostic retention.
        let (target_event_index, target_observation_id) = observation;
        self.failure_counts
            .entry((protocol.as_str().into(), case_id.clone()))
            .and_modify(|count| *count += 1)
            .or_insert(1);
        if self.failures.len() < 4096 {
            self.failures.push(RequestFailure {
                case_id,
                protocol: protocol.as_str().into(),
                target: TargetKey {
                    host: endpoint.host.clone(),
                    port: endpoint.port,
                },
                target_event_index,
                target_observation_id,
                reason: reason.into(),
                diagnostics,
            });
        }
    }

    pub fn snapshot(&self) -> BTreeMap<String, ProtocolReport> {
        let mut reports = BTreeMap::<String, ProtocolReport>::new();
        for (protocol, count) in &self.matched {
            reports.entry(protocol.clone()).or_default().matched_count = *count;
        }
        for ((protocol, _), count) in &self.failure_counts {
            reports.entry(protocol.clone()).or_default().unmatched_count += count;
        }
        for failure in &self.failures {
            reports
                .entry(failure.protocol.clone())
                .or_default()
                .unmatched
                .push(failure.clone());
        }
        for exchange in &self.core.exchanges {
            let report = reports
                .entry(exchange.protocol.as_str().into())
                .or_default();
            let status = self
                .core
                .lifecycle
                .live_status(exchange.index, exchange.status);
            if status.is_consumed() {
                continue;
            }
            let row = UnusedExchange {
                index: exchange.index,
                case_id: exchange.source.case_id.clone(),
                source: exchange.source.source,
                protocol_ref: exchange.native.reference.clone(),
                source_exchange_id: exchange
                    .source
                    .capture
                    .as_ref()
                    .map(|capture| capture.exchange_id),
                target: TargetKey {
                    host: exchange.native.endpoint.host.clone(),
                    port: exchange.native.endpoint.port,
                },
                status,
            };
            if exchange.source.source.is_run_owned() {
                report.unused_global_count += 1;
                if report.unused_global.len() < 100 {
                    report.unused_global.push(row);
                }
            } else {
                report.unused_case.push(row);
            }
        }
        reports
    }

    pub fn case_failures(&self) -> Vec<Value> {
        let mut counts = BTreeMap::<(String, String), (usize, usize)>::new();
        for ((protocol, case), count) in &self.failure_counts {
            if let Some(case) = case {
                counts
                    .entry((case.clone(), protocol.clone()))
                    .or_default()
                    .0 += count;
            }
        }
        for exchange in &self.core.exchanges {
            if let Some(case) = &exchange.source.case_id
                && !self
                    .core
                    .lifecycle
                    .live_status(exchange.index, exchange.status)
                    .is_consumed()
            {
                counts
                    .entry((case.clone(), exchange.protocol.as_str().into()))
                    .or_default()
                    .1 += 1;
            }
        }
        counts.into_iter().map(|((case, protocol), (unmatched, unused))| serde_json::json!({
            "case_id":case,"kind":"dependency_protocol_failure","protocol":protocol,
            "unmatched_or_failed":unmatched,"unused_dependencies":unused,
            "reason":"registered dependency requests or actual deliveries did not satisfy the finite Source contract"
        })).collect()
    }
}
