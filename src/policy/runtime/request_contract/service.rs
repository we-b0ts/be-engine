//! Application binding of shared request, clock and value-rule capabilities.
use super::*;
use crate::replay::policy::RequestRuleRuntime;
use crate::replay::policy::ValueRuleHost;
use crate::value_contract::response_delivery::IdentityDeliveryHost;
use traffic_contract::{
    compare::{AnchorClocks, Comparison},
    identity::{IdentityDecision, IdentityPair},
    time::ClockPair,
};
use traffic_policy_value::identity::IdentityDelivery;
use traffic_protocol::connection::NativeFuture;

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

struct GlobalDocumentPolicy {
    owner: RequestContracts,
    clocks: AnchorClocks,
}
impl traffic_policy_value::DocumentPolicy for GlobalDocumentPolicy {
    fn paths(&self, source: &traffic_value::Value) -> Result<Vec<String>> {
        crate::value_contract::global::policy_paths(
            source,
            self.owner
                .global_json()
                .expect("prepared global document policy"),
            self.clocks,
        )
    }
    fn compare(
        &self,
        source: &traffic_value::Value,
        target: &traffic_value::Value,
        fields: &[traffic_contract::compare::Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        crate::value_contract::global::compare_fields(
            source,
            target,
            self.owner
                .global_json()
                .expect("prepared global document policy"),
            fields,
            clocks,
        )
    }
}

impl ValueRuleHost for RequestContracts {
    fn translate_document(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Value,
        clocks: AnchorClocks,
    ) -> Result<()> {
        if let Some(global) = self.global_json() {
            let timed =
                crate::value_contract::global::materialize_logical(source, global, &[], clocks)?;
            for field in global.selected_delivery_fields_with_clocks(source, clocks)? {
                let pointer = field.pointer;
                if field.contract.time().is_some()
                    && source.pointer(&pointer) == delivered.pointer(&pointer)
                {
                    *delivered
                        .pointer_mut(&pointer)
                        .context("global time delivery field disappeared")? = timed
                        .pointer(&pointer)
                        .context("global time delivery value disappeared")?
                        .clone();
                }
            }
            self.translate_identity_plan(scope, source, delivered, global)?;
        }
        Ok(())
    }
    fn document_policy(
        &self,
        clocks: AnchorClocks,
    ) -> Option<Arc<dyn traffic_policy_value::DocumentPolicy>> {
        self.global_json().map(|_| {
            Arc::new(GlobalDocumentPolicy {
                owner: self.clone(),
                clocks,
            }) as Arc<dyn traffic_policy_value::DocumentPolicy>
        })
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
