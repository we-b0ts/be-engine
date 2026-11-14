//! Bounded native diagnostics and complete finite-consumption counts.
use super::*;

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct RequestFailure {
    pub case_id: Option<String>,
    pub protocol: String,
    pub target: TargetKey,
    pub target_event_index: Option<usize>,
    pub target_observation_id: Option<Uuid>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct UnusedExchange {
    pub index: usize,
    pub case_id: Option<String>,
    pub source: ReplaySource,
    pub protocol_ref: traffic_model::recording::ProtocolRef,
    pub source_exchange_id: Option<Uuid>,
    pub target: TargetKey,
    pub status: ReplayExchangeStatus,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(in crate::replay) struct ProtocolReport {
    pub matched_count: usize,
    pub unmatched_count: usize,
    pub unmatched: Vec<RequestFailure>,
    pub unused_case: Vec<UnusedExchange>,
    pub unused_global_count: usize,
    pub unused_global: Vec<UnusedExchange>,
}

impl Inventory {
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

    pub fn startup_counts(&mut self, close: bool) -> BTreeMap<String, startup::Counts> {
        let mut counts = BTreeMap::<String, startup::Counts>::new();
        for exchange in &mut self.core.exchanges {
            counts
                .entry(exchange.protocol.as_str().into())
                .or_default()
                .observe(exchange.source.source, &mut exchange.status, true, close);
        }
        counts
    }

    pub(super) fn record_failure(
        &mut self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        case_id: Option<String>,
        target_event_index: Option<usize>,
        target_observation_id: Option<Uuid>,
        reason: &str,
    ) {
        // Each physical request or failed delivery keeps a bounded diagnostic.
        // The count remains independent of diagnostic retention.
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
