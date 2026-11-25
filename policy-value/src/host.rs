//! Phase-independent value services supplied by the execution owner.
use crate::{RuleBinding, identity::IdentityDelivery};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::{borrow::Cow, sync::Arc};
use traffic_contract::{
    compare::{AnchorClocks, Comparison},
    identity::{IdentityDecision, IdentityPair},
};
use traffic_protocol::{ProtocolId, connection::Endpoint, message::ProtocolMessage};

pub struct ValueDecision {
    pub comparison: Comparison,
    pub identity: Option<IdentityDecision>,
}

pub trait ValueRuleHost: std::fmt::Debug + Send + Sync {
    fn metadata(&self) -> &(dyn traffic_contract::compare::RuleMetadata + 'static);

    fn configure_session_identities(&self, _scope: &str, _dependency_count: usize) -> Result<()> {
        Ok(())
    }

    fn translate_document(
        &self,
        _scope: &str,
        _source: &Value,
        _delivered: &mut Value,
        _clocks: AnchorClocks,
    ) -> Result<()> {
        Ok(())
    }
    /// Native delivery can keep Source JSON borrowed until a field is edited.
    /// Hosts that supply the mutable document callback keep that behavior.
    fn translate_delivery_document(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Cow<'_, Value>,
        clocks: AnchorClocks,
    ) -> Result<()> {
        self.translate_document(scope, source, delivered.to_mut(), clocks)
    }
    fn document_policy(&self, _clocks: AnchorClocks) -> Option<Arc<dyn crate::DocumentPolicy>> {
        None
    }
    /// Bind an exact, protocol-owned request shape with strict comparison of
    /// its remaining values. Other requests use the normal policy bindings.
    fn native_request_bindings(
        &self,
        _exchange: &traffic_protocol::connection::RecordedExchange,
    ) -> Result<Option<Vec<RuleBinding>>> {
        Ok(None)
    }
    fn native_request_projection(
        &self,
        _protocol: ProtocolId,
        _endpoint: &Endpoint,
        request: Arc<dyn ProtocolMessage>,
        _source: Option<&Value>,
    ) -> Result<Arc<dyn ProtocolMessage>> {
        Ok(request)
    }
    /// Conservative capability check before any Source messages are prepared.
    fn may_bind_native_documents(&self) -> bool {
        true
    }
    /// Opt in when Source validation is independent of live Target state and
    /// publication of a Source comparison needs only the evaluated rule IDs.
    fn prefetch_source_response(&self) -> bool {
        false
    }
    /// Committed identity revision for speculative delivery in this Session.
    /// The consumer rechecks it before using the prepared result.
    fn prefetch_delivery_revision(&self, _scope: &str) -> Option<u64> {
        None
    }
    /// Recheck identity bindings from a delivery validated by this Session owner.
    /// Returning true permits reuse but does not commit the proposal.
    fn prefetched_identity_is_current(&self, _proposed: &IdentityDecision) -> bool {
        false
    }
    /// Batch reuse permits an already committed Session pair as well as an
    /// empty decision. Committing these decisions adds no correspondences.
    fn prefetched_identity_is_committed(&self, proposed: &IdentityDecision) -> bool {
        proposed.is_empty()
    }
    fn observe_source_comparison(&self, _comparison: &Comparison) {}
    fn begin_case(&self, case: &str);
    fn clear_case_values(&self, case: &str);
    fn case_flags(&self, _case: &str) -> std::collections::BTreeMap<String, Value> {
        Default::default()
    }
    fn control_is_read_only(&self, _command: &str) -> bool {
        false
    }
    fn control(
        &self,
        _case: Option<&str>,
        _command: &str,
        _parameters: &std::collections::BTreeMap<String, traffic_value::Value>,
    ) -> Result<Option<Value>> {
        Ok(None)
    }
    fn preview_identity_pairs(
        &self,
        scope: &str,
        pairs: &[IdentityPair],
        case_owned: bool,
    ) -> Result<IdentityDecision>;
    fn identity_deliveries(
        &self,
        scope: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)>;
    fn commit_comparison(&self, comparison: Comparison, identity: IdentityDecision) -> Result<()>;
    fn contract_clocks(
        &self,
        case: Option<&str>,
        source_dependency: Option<DateTime<Utc>>,
        target_dependency: Option<DateTime<Utc>>,
        source_delivery: Option<DateTime<Utc>>,
        target_delivery: Option<DateTime<Utc>>,
    ) -> AnchorClocks;
}
