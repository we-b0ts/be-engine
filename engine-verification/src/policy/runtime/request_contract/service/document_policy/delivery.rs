//! Retain Source delivery field selection for the live identity owner.
use super::super::super::global_value::ResolvedRootIdentities;
use super::{GlobalDocumentPolicy, RequestContracts, policy, retained_fields};
use anyhow::Result;
use serde_json::Value;
use std::{borrow::Cow, mem::size_of, sync::Arc};
use traffic_contract::{compare::AnchorClocks, identity::IdentityDecision, rule::FieldContract};
use traffic_policy_execution::global;
use traffic_policy_value::{PreparedDeliveryGuard, PreparedDocumentDelivery};

pub(super) fn prepare(
    document: &GlobalDocumentPolicy,
    source: &Value,
) -> Result<Option<Box<dyn PreparedDocumentDelivery>>> {
    let global_policy = policy(&document.owner);
    let context = crate::value_contract::execution_context();
    let time_fields =
        global::time_delivery_fields(&context, source, global_policy, document.clocks)?;
    let time_bytes = match &time_fields {
        Some(fields) => {
            let Some(bytes) = retained_fields(fields, fields.capacity()) else {
                return Ok(None);
            };
            bytes
        }
        None => 0,
    };
    let identities = global_policy.identity_fields(source)?;
    let identities = match document
        .owner
        .prefetch_root_identities(source, &identities)?
    {
        Some(committed) => DeliveryIdentities::Committed(committed),
        None => DeliveryIdentities::Selected(identities),
    };
    Ok(Some(Box::new(DeliveryFields {
        owner: document.owner.clone(),
        clocks: document.clocks,
        time_fields,
        time_bytes,
        identities,
    })))
}

struct DeliveryFields {
    owner: Arc<RequestContracts>,
    clocks: AnchorClocks,
    time_fields: Option<Vec<traffic_policy_value::fields::SelectedGlobalField>>,
    time_bytes: usize,
    identities: DeliveryIdentities,
}

enum DeliveryIdentities {
    Committed(ResolvedRootIdentities),
    Selected(Vec<(String, FieldContract)>),
}

impl DeliveryIdentities {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::Committed(committed) => committed.retained_bytes(),
            Self::Selected(identities) => {
                identities.capacity() * size_of::<(String, FieldContract)>()
                    + identities
                        .iter()
                        .map(|(pointer, contract)| {
                            pointer.capacity()
                                + match contract {
                                    FieldContract::Identity { prefix, .. } => prefix.capacity(),
                                    _ => 0,
                                }
                        })
                        .sum::<usize>()
            }
        }
    }
}

impl PreparedDocumentDelivery for DeliveryFields {
    fn retained_bytes(&self) -> usize {
        size_of::<Self>() + self.identities.retained_bytes() + self.time_bytes
    }

    fn clock_independent(&self) -> bool {
        self.time_fields.is_none()
    }

    fn apply(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Cow<'_, Value>,
        clocks: AnchorClocks,
    ) -> Result<bool> {
        Ok(self
            .apply_identities(scope, source, delivered, clocks)?
            .is_some())
    }

    fn prefetch_apply(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Cow<'_, Value>,
        clocks: AnchorClocks,
    ) -> Result<Option<Box<dyn PreparedDeliveryGuard>>> {
        if !self.clock_independent() || !self.owner.values.is_session_identity_scope(scope) {
            return Ok(None);
        }
        let Some(identity) = self.apply_identities(scope, source, delivered, clocks)? else {
            return Ok(None);
        };
        Ok(Some(Box::new(DeliveryIdentityGuard {
            owner: self.owner.clone(),
            identity,
        })))
    }
}

impl DeliveryFields {
    fn apply_identities(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Cow<'_, Value>,
        clocks: AnchorClocks,
    ) -> Result<Option<IdentityDecision>> {
        if self.clocks.observation().source != clocks.observation().source
            || matches!(self.identities, DeliveryIdentities::Committed(_))
                && !self.owner.values.is_session_identity_scope(scope)
        {
            return Ok(None);
        }
        if let Some(fields) = &self.time_fields {
            global::translate_selected_times(
                &crate::value_contract::execution_context(),
                source,
                delivered,
                fields,
                clocks,
            )?;
        }
        let global = policy(&self.owner);
        let (identity, _) = match &self.identities {
            DeliveryIdentities::Committed(committed) => {
                self.owner.translate_resolved_identities_cow(
                    scope,
                    source,
                    delivered,
                    global,
                    committed.clone(),
                )?
            }
            DeliveryIdentities::Selected(selected) => self
                .owner
                .translate_selected_identities_cow(scope, source, delivered, global, selected)?,
        };
        Ok(Some(identity))
    }
}

struct DeliveryIdentityGuard {
    owner: Arc<RequestContracts>,
    identity: IdentityDecision,
}

impl PreparedDeliveryGuard for DeliveryIdentityGuard {
    fn retained_bytes(&self) -> usize {
        size_of::<Self>() + self.identity.retained_bytes()
    }

    fn is_current(&self) -> bool {
        self.owner
            .values
            .prefetched_identity_is_current(&self.identity)
    }
}
