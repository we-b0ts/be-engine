//! Candidate diagnostics retain actual Source references and registered findings.
use super::*;
use traffic_contract::compare::Comparison;
use traffic_policy_value::diagnosis::message::MessageFinding;

#[derive(Debug, Clone, Default, Serialize)]
pub struct CandidateDiagnostics {
    pub candidate_comparisons: Vec<CandidateDifference>,
    pub candidate_comparisons_omitted: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateDifference {
    pub source: ReplaySource,
    pub source_case_id: Option<String>,
    pub source_reference: traffic_model::recording::ProtocolRef,
    pub source_exchange_id: Option<Uuid>,
    pub differences: Vec<traffic_contract::comparison::Difference>,
    pub differences_omitted: usize,
    pub policy_findings: Vec<MessageFinding>,
    pub analysis_limited: bool,
    pub analysis_unavailable: bool,
}

impl CandidateDiagnostics {
    pub fn observe(
        &mut self,
        inventory: &Inventory,
        exchange: &traffic_replay::exchange::PreparedExchange<crate::value_extensions::ValueRules>,
        request: &request::Request,
        comparison: &Comparison,
    ) {
        if comparison.passed() {
            return;
        }
        if self.candidate_comparisons.len() >= 4 {
            self.candidate_comparisons_omitted += 1;
            return;
        }
        let facts = serde_json::json!({"surface":"dependency.request",
            "clocks":inventory.clocks(exchange.index, request.observed, false).observations()});
        let analysis = traffic_policy_value::diagnosis::message::analyze(
            exchange.native.request().expect("request candidate"),
            request.message.as_ref(),
            inventory.providers.bindings().codecs(),
            inventory.contracts.metadata().policies(),
            &comparison.differences,
            &facts,
        );
        let unavailable = analysis.is_err();
        let analysis = analysis.unwrap_or_default();
        self.candidate_comparisons.push(CandidateDifference {
            source: exchange.source.source,
            source_case_id: exchange.source.case_id.clone(),
            source_reference: exchange.native.reference.clone(),
            source_exchange_id: exchange
                .source
                .capture
                .as_ref()
                .map(|capture| capture.exchange_id),
            differences: comparison.differences.iter().take(16).cloned().collect(),
            differences_omitted: comparison.differences.len().saturating_sub(16),
            policy_findings: analysis.findings,
            analysis_limited: analysis.limited,
            analysis_unavailable: unavailable,
        });
    }
}
