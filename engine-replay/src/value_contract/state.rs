//! Application correspondence and read-provenance stores supplied to Replay.
use crate::replay::policy::ValueRuleHost;
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::{
    borrow::Cow,
    sync::{Arc, Mutex, OnceLock},
};
use traffic_contract::{
    compare::{AnchorClocks, Comparison},
    identity::{IdentityDecision, IdentityPair, IdentityPreview, IdentityScope, IdentityStore},
    time::ClockPair,
};
use traffic_policy_value::identity::IdentityDelivery;
use traffic_protocol::{ProtocolId, connection::Endpoint, message::ProtocolMessage};

#[derive(Clone, Default)]
pub struct ValueState {
    pub identities: Arc<Mutex<IdentityStore>>,
    pub time_copies: Arc<Mutex<crate::value_contract::time_copies::TimeCopyStore>>,
    session_scope: Arc<OnceLock<String>>,
    identity_preview: Option<Arc<IdentityPreview>>,
}

impl std::fmt::Debug for ValueState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ValueState").finish_non_exhaustive()
    }
}

impl ValueState {
    pub fn configure_session_identities(&self, scope: &str, dependency_count: usize) -> Result<()> {
        self.identities
            .lock()
            .expect("identity contracts")
            .configure_session(dependency_count)?;
        self.session_scope
            .set(scope.into())
            .map_err(|_| anyhow::anyhow!("identity Session scope is already configured"))
    }

    fn identity_scope(&self, scope: &str) -> IdentityScope {
        if self.is_session_identity_scope(scope) {
            IdentityScope::Session
        } else {
            IdentityScope::Case(scope.into())
        }
    }

    pub fn is_session_identity_scope(&self, scope: &str) -> bool {
        self.session_scope
            .get()
            .is_some_and(|session| session == scope)
    }

    pub fn preview(&self, scope: &str, pairs: &[IdentityPair]) -> Result<IdentityDecision> {
        let decision =
            IdentityDecision::prepare_in_scope(self.identity_scope(scope), pairs.to_vec())?;
        self.validate_identity(&decision)?;
        Ok(decision)
    }

    pub fn validate_identity(&self, decision: &IdentityDecision) -> Result<()> {
        self.identities
            .lock()
            .expect("identity contracts")
            .validate_with_preview(decision, self.identity_preview.as_deref())
    }

    pub fn prefetched_identity_is_current(&self, proposed: &IdentityDecision) -> bool {
        self.session_scope.get().is_some()
            && self.identity_preview.is_none()
            && self
                .identities
                .lock()
                .expect("identity contracts")
                .prefetched_session_identity_is_current(proposed)
    }

    pub fn prefetched_identity_is_committed(&self, proposed: &IdentityDecision) -> bool {
        self.session_scope.get().is_some()
            && self.identity_preview.is_none()
            && self
                .identities
                .lock()
                .expect("identity contracts")
                .prefetched_session_identity_is_committed(proposed)
    }

    pub fn with_identity_preview(&self, decision: IdentityDecision) -> Result<Self> {
        let preview = self
            .identities
            .lock()
            .expect("identity contracts")
            .preview(decision, self.identity_preview.as_deref())?;
        Ok(Self {
            identity_preview: Some(Arc::new(preview)),
            ..self.clone()
        })
    }

    pub fn knows_identity(&self, scope: &str, pair: IdentityPair) -> Result<bool> {
        self.identities
            .lock()
            .expect("identity contracts")
            .contains_pair_in_scope(
                &self.identity_scope(scope),
                pair,
                self.identity_preview.as_deref(),
            )
    }

    pub fn commit(&self, decision: IdentityDecision) -> Result<()> {
        if !decision.is_empty() {
            ensure!(
                self.identity_preview.is_none(),
                "staged identity previews cannot publish observations"
            );
            self.identities
                .lock()
                .expect("identity contracts")
                .commit(decision)?;
        }
        Ok(())
    }

    pub fn deliveries(
        &self,
        scope: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        if selected.is_empty() {
            return Ok((
                vec![],
                IdentityDecision::prepare_in_scope(self.identity_scope(scope), vec![])?,
            ));
        }
        ensure!(
            selected.len() <= 4096,
            "identity delivery leaf bound exceeded"
        );
        let prepared = selected
            .iter()
            .copied()
            .map(|selected| selected.prepare(traffic_extensions::policies()))
            .collect::<Result<Vec<_>>>()?;
        self.identities
            .lock()
            .expect("identity contracts")
            .deliveries_in_scope(
                self.identity_scope(scope),
                &prepared,
                self.identity_preview.as_deref(),
            )
    }

    pub fn prefetch_session_identity_deliveries(
        &self,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<Option<(Vec<Value>, IdentityDecision)>> {
        if self.session_scope.get().is_none()
            || self.identity_preview.is_some()
            || selected.is_empty()
        {
            return Ok(None);
        }
        ensure!(
            selected.len() <= 4096,
            "identity delivery leaf bound exceeded"
        );
        let prepared = selected
            .iter()
            .copied()
            .map(|selected| selected.prepare(traffic_extensions::policies()))
            .collect::<Result<_>>()?;
        let snapshot = self
            .identities
            .lock()
            .expect("identity contracts")
            .committed_session_delivery(prepared);
        snapshot.map(|snapshot| snapshot.resolve()).transpose()
    }

    pub fn clear(&self, scope: &str) {
        self.identities
            .lock()
            .expect("identity contracts")
            .begin_case(scope);
    }
}

/// Strict sessions still share finite, case-local identity accounting.
impl ValueRuleHost for ValueState {
    fn metadata(&self) -> &(dyn traffic_contract::compare::RuleMetadata + 'static) {
        &crate::value_contract::json::PolicyMetadata
    }

    fn native_request_projection(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        request: Arc<dyn ProtocolMessage>,
        source: Option<&Value>,
    ) -> Result<Arc<dyn ProtocolMessage>> {
        if matches!(protocol.as_str(), "http" | "https") {
            traffic_protocol_http::request_sigv4::request(&[], endpoint, request, source)
        } else {
            Ok(request)
        }
    }

    fn prefetch_source_response(&self) -> bool {
        true
    }

    fn prefetch_delivery_revision(&self, scope: &str) -> Option<u64> {
        (self.identity_preview.is_none() && self.is_session_identity_scope(scope)).then(|| {
            self.identities
                .lock()
                .expect("identity contracts")
                .revision()
        })
    }

    fn prefetched_identity_is_current(&self, proposed: &IdentityDecision) -> bool {
        Self::prefetched_identity_is_current(self, proposed)
    }

    fn prefetched_identity_is_committed(&self, proposed: &IdentityDecision) -> bool {
        Self::prefetched_identity_is_committed(self, proposed)
    }

    fn translate_delivery_document(
        &self,
        _: &str,
        _: &Value,
        _: &mut Cow<'_, Value>,
        _: AnchorClocks,
    ) -> Result<()> {
        Ok(())
    }

    fn configure_session_identities(&self, scope: &str, dependency_count: usize) -> Result<()> {
        Self::configure_session_identities(self, scope, dependency_count)
    }

    fn begin_case(&self, case: &str) {
        self.clear(case);
    }
    fn clear_case_values(&self, case: &str) {
        self.clear(case);
    }
    fn case_flags(&self, _: &str) -> std::collections::BTreeMap<String, Value> {
        std::collections::BTreeMap::from([("has_response_time_copies".into(), Value::Bool(false))])
    }
    fn control_is_read_only(&self, command: &str) -> bool {
        command == "response_time_copies"
    }
    fn control(
        &self,
        case: Option<&str>,
        command: &str,
        _: &std::collections::BTreeMap<String, traffic_value::Value>,
    ) -> Result<Option<Value>> {
        if command != "response_time_copies" {
            return Ok(None);
        }
        ensure!(
            case.is_some(),
            "response provenance requires the active case"
        );
        Ok(Some(serde_json::json!({"ok":true,
            "time_copies":crate::value_contract::time_copies::DeliveredTimeCopies::default()})))
    }
    fn preview_identity_pairs(
        &self,
        scope: &str,
        pairs: &[IdentityPair],
        _: bool,
    ) -> Result<IdentityDecision> {
        self.preview(scope, pairs)
    }
    fn identity_deliveries(
        &self,
        scope: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        self.deliveries(scope, selected)
    }
    fn commit_comparison(&self, comparison: Comparison, identity: IdentityDecision) -> Result<()> {
        ensure!(
            comparison.passed(),
            "failed value comparison cannot commit identities"
        );
        self.commit(identity)
    }
    fn contract_clocks(
        &self,
        _: Option<&str>,
        source_dependency: Option<DateTime<Utc>>,
        target_dependency: Option<DateTime<Utc>>,
        source_delivery: Option<DateTime<Utc>>,
        target_delivery: Option<DateTime<Utc>>,
    ) -> AnchorClocks {
        AnchorClocks::for_request(
            ClockPair::default(),
            ClockPair {
                source: source_dependency,
                target: target_dependency,
            },
            ClockPair {
                source: source_delivery,
                target: target_delivery,
            },
        )
    }
}
