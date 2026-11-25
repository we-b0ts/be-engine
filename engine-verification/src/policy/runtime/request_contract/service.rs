//! Application binding of shared request, clock and value-rule capabilities.
use super::*;
use crate::replay::policy::RequestRuleRuntime;
use crate::replay::policy::ValueRuleHost;
use crate::value_contract::response_delivery::IdentityDeliveryHost;
use std::borrow::Cow;
use traffic_contract::{
    compare::{AnchorClocks, Comparison},
    identity::{IdentityDecision, IdentityPair},
    time::ClockPair,
};
use traffic_policy_value::identity::IdentityDelivery;
use traffic_protocol::{
    ProtocolId,
    connection::{Endpoint, NativeFuture},
    message::ProtocolMessage,
};

mod document_policy;
mod redis_eval_time;
mod response_constraints;
mod response_identities;

impl IdentityDeliveryHost for RequestContracts {
    fn translate_identity_plan(
        &self,
        case: &str,
        source: &Value,
        delivered: &mut Value,
        global: &crate::policy::CompiledJsonPolicy,
    ) -> Result<(IdentityDecision, Vec<String>)> {
        Self::translate_identity_plan(self, case, source, delivered, global)
    }
}

impl ValueRuleHost for RequestContracts {
    fn metadata(&self) -> &(dyn traffic_contract::compare::RuleMetadata + 'static) {
        &crate::value_contract::json::PolicyMetadata
    }

    fn configure_session_identities(&self, scope: &str, dependency_count: usize) -> Result<()> {
        self.values
            .configure_session_identities(scope, dependency_count)
    }

    fn observe_source_comparison(&self, comparison: &Comparison) {
        self.observe_value_slot_applicable(comparison.evaluated.iter().cloned());
    }

    fn prefetch_source_response(&self) -> bool {
        true
    }

    fn prefetch_delivery_revision(&self, scope: &str) -> Option<u64> {
        self.values.prefetch_delivery_revision(scope)
    }

    fn prefetched_identity_is_current(&self, proposed: &IdentityDecision) -> bool {
        self.values.prefetched_identity_is_current(proposed)
    }

    fn prefetched_identity_is_committed(&self, proposed: &IdentityDecision) -> bool {
        self.values.prefetched_identity_is_committed(proposed)
    }

    fn translate_document(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Value,
        clocks: AnchorClocks,
    ) -> Result<()> {
        let mut document = Cow::Owned(std::mem::take(delivered));
        let result = self.translate_delivery_document(scope, source, &mut document, clocks);
        *delivered = document.into_owned();
        result
    }
    fn translate_delivery_document(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Cow<'_, Value>,
        clocks: AnchorClocks,
    ) -> Result<()> {
        if let Some(global) = self.global_json() {
            crate::value_contract::global::translate_times_cow(source, delivered, global, clocks)?;
            self.translate_identity_plan_cow(scope, source, delivered, global)?;
        }
        Ok(())
    }
    fn document_policy(
        &self,
        clocks: AnchorClocks,
    ) -> Option<Arc<dyn traffic_policy_value::DocumentPolicy>> {
        self.global_json().map(|_| {
            Arc::new(document_policy::GlobalDocumentPolicy::new(
                self.clone(),
                clocks,
            )) as Arc<dyn traffic_policy_value::DocumentPolicy>
        })
    }
    fn native_request_bindings(
        &self,
        exchange: &traffic_protocol::connection::RecordedExchange,
    ) -> Result<Option<Vec<traffic_policy_value::RuleBinding>>> {
        match self.compiled.as_deref() {
            Some(policy) => redis_eval_time::bindings(policy, exchange),
            None => Ok(None),
        }
    }
    fn native_request_projection(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        request: Arc<dyn ProtocolMessage>,
        source: Option<&Value>,
    ) -> Result<Arc<dyn ProtocolMessage>> {
        let http = self
            .compiled
            .as_ref()
            .and_then(|compiled| compiled.http.as_ref());
        if let Some(http) = http
            && matches!(protocol.as_str(), "http" | "https")
        {
            traffic_protocol_http::request_metadata::request(
                &http.request_metadata,
                endpoint,
                request,
                source,
            )
        } else {
            Ok(request)
        }
    }
    fn may_bind_native_documents(&self) -> bool {
        self.global_json()
            .is_some_and(|policy| !policy.fields.is_empty())
    }
    fn begin_case(&self, case: &str) {
        Self::begin_case(self, case);
    }
    fn clear_case_values(&self, case: &str) {
        Self::clear_time_copies(self, case);
        Self::clear_identities(self, case);
    }

    fn preview_identity_pairs(
        &self,
        scope: &str,
        pairs: &[IdentityPair],
        case_owned: bool,
    ) -> Result<IdentityDecision> {
        if case_owned {
            Self::preview_identity_pairs(self, scope, pairs)
        } else {
            Self::preview_run_identity_pairs(self, scope, pairs)
        }
    }

    fn identity_deliveries(
        &self,
        scope: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        Self::identity_deliveries(self, scope, selected)
    }

    fn commit_comparison(&self, comparison: Comparison, identity: IdentityDecision) -> Result<()> {
        ensure!(
            comparison.passed(),
            "failed value comparison cannot commit identities"
        );
        let mut decision = Decision::from_value_comparison(comparison);
        decision.identity = Some(identity);
        Self::commit(self, decision)
    }

    fn contract_clocks(
        &self,
        case: Option<&str>,
        source_dependency: Option<DateTime<Utc>>,
        target_dependency: Option<DateTime<Utc>>,
        source_delivery: Option<DateTime<Utc>>,
        target_delivery: Option<DateTime<Utc>>,
    ) -> AnchorClocks {
        Self::contract_clocks(
            self,
            case,
            source_dependency,
            target_dependency,
            source_delivery,
            target_delivery,
        )
    }
}

impl RequestRuleRuntime for RequestContracts {
    type PreparedInput = PreparedDerivedInputs;

    fn native_rules(&self) -> Arc<dyn ValueRuleHost> {
        Arc::new(self.clone())
    }
    fn configure_pre_match(&mut self, enabled: bool) {
        Self::configure_pre_match(self, enabled);
    }
    fn configure_witnesses(
        &mut self,
        witnesses: crate::policy_evidence::WitnessStore,
        observe: bool,
    ) -> Result<()> {
        Self::configure_witnesses(self, witnesses, observe)
    }
    fn prepare_case_rules(
        &self,
        case: &str,
    ) -> Result<crate::replay::execution_plan::PreparedCaseRules> {
        Self::prepare_case_rules(self, case)
    }
    fn request_begin(&self, case: &str) -> Result<()> {
        Self::request_begin(self, case)
    }
    fn request_times(&self, case: &str) -> ClockPair {
        Self::request_times(self, case)
    }
    fn case_flags(&self, case: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([(
            "has_response_time_copies".into(),
            serde_json::json!(self.has_time_copies(case)),
        )])
    }
    fn clear_case_values(&self, case: &str) {
        Self::clear_time_copies(self, case);
        Self::clear_identities(self, case);
    }
    fn control_is_read_only(&self, command: &str) -> bool {
        command == "response_time_copies"
    }
    fn control(
        &self,
        case: Option<&str>,
        command: &str,
        parameters: &BTreeMap<String, traffic_value::Value>,
    ) -> Result<Option<Value>> {
        response_constraints::control(self, case, command, parameters)
    }
    fn prepare_derived_inputs(
        &self,
        case: &str,
        sent_at: DateTime<Utc>,
        actual: &Value,
    ) -> Result<Self::PreparedInput> {
        Self::prepare_derived_inputs(self, case, sent_at, actual)
    }
    fn commit_derived_inputs(&self, prepared: Self::PreparedInput) -> Result<()> {
        Self::commit_derived_inputs(self, prepared)
    }
    fn hypothesis_attempts(&self) -> Vec<HypothesisAttempt> {
        Self::hypothesis_attempts(self)
    }
    fn hypothesis_coverage_error(&self) -> Option<String> {
        Self::hypothesis_coverage_error(self)
    }
    fn hypothesis_journal_manifest(
        &self,
    ) -> Option<crate::policy_evidence::hypotheses::JournalManifest> {
        Self::hypothesis_journal_manifest(self)
    }
    fn pre_match_reports(&self) -> Vec<crate::value_contract::pre_match::Candidate> {
        Self::pre_match_reports(self)
    }
    fn await_hypotheses_durable(&self) -> NativeFuture<'_, ()> {
        Box::pin(Self::await_hypotheses_durable(self))
    }
}
