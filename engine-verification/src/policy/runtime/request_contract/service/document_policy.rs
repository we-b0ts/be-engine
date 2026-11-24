//! Reuse immutable field applicability across Source and live document comparisons.
use std::{mem::size_of, sync::Arc};

use anyhow::Result;
use traffic_contract::{
    compare::{AnchorClocks, Comparison, Field, LogicalProjection},
    rule::{ClockScope, FieldContract},
};
use traffic_policy_value::{
    DocumentPolicy, DocumentPolicyPreparation, PreparedDocumentComparison,
    fields::SelectedGlobalField,
};
use traffic_value::Value;

use super::RequestContracts;
use crate::value_contract::global;

mod delivery;
#[cfg(test)]
mod delivery_tests;

pub(super) struct GlobalDocumentPolicy {
    owner: Arc<RequestContracts>,
    clocks: AnchorClocks,
}

impl GlobalDocumentPolicy {
    pub(super) fn new(owner: RequestContracts, clocks: AnchorClocks) -> Self {
        Self {
            owner: Arc::new(owner),
            clocks,
        }
    }
}

impl DocumentPolicy for GlobalDocumentPolicy {
    fn prepare_delivery(
        &self,
        source: &serde_json::Value,
    ) -> Result<Option<Box<dyn traffic_policy_value::PreparedDocumentDelivery>>> {
        delivery::prepare(self, source)
    }

    fn paths(&self, source: &Value) -> Result<Vec<String>> {
        global::policy_paths(source, policy(&self.owner), self.clocks)
    }

    fn prepare_source(&self, source: &Value) -> Result<DocumentPolicyPreparation> {
        self.prepare_projected_source(&LogicalProjection::new(source)?)
    }

    fn prepare_projected_source(
        &self,
        source: &LogicalProjection<'_>,
    ) -> Result<DocumentPolicyPreparation> {
        let prepared = global::prepare_projected_fields(source, policy(&self.owner), self.clocks)?;
        let fields = prepared.selected;
        let comparison = retained_fields(&fields, fields.capacity()).map(|bytes| {
            Box::new(PreparedFields {
                owner: self.owner.clone(),
                clocks: self.clocks,
                fields,
                clock_independent: prepared.clock_independent,
                bytes: size_of::<PreparedFields>() + bytes,
            }) as Box<dyn PreparedDocumentComparison>
        });
        Ok(DocumentPolicyPreparation {
            paths: prepared.paths,
            comparison,
        })
    }

    fn compare(
        &self,
        source: &Value,
        target: &Value,
        fields: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        global::compare_fields(source, target, policy(&self.owner), fields, clocks)
    }

    fn compare_projected(
        &self,
        source: &LogicalProjection<'_>,
        target: &Value,
        fields: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        global::compare_projected_fields(source, target, policy(&self.owner), fields, None, clocks)
    }
}

struct PreparedFields {
    owner: Arc<RequestContracts>,
    clocks: AnchorClocks,
    fields: Vec<SelectedGlobalField>,
    clock_independent: bool,
    bytes: usize,
}

impl PreparedDocumentComparison for PreparedFields {
    fn applies_at(&self, clocks: AnchorClocks) -> bool {
        self.clocks.observation().source == clocks.observation().source
    }

    fn clock_independent(&self) -> bool {
        self.clock_independent
    }

    fn compare(
        &self,
        source: &Value,
        target: &Value,
        fields: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        global::compare_prepared_fields(
            source,
            target,
            policy(&self.owner),
            fields,
            &self.fields,
            clocks,
        )
    }

    fn compare_projected(
        &self,
        source: &LogicalProjection<'_>,
        target: &Value,
        fields: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        global::compare_projected_fields(
            source,
            target,
            policy(&self.owner),
            fields,
            Some(&self.fields),
            clocks,
        )
    }

    fn retained_bytes(&self) -> usize {
        self.bytes
    }
}

fn policy(owner: &RequestContracts) -> &crate::policy::CompiledJsonPolicy {
    owner
        .global_json()
        .expect("prepared global document policy")
}

fn retained_fields(fields: &[SelectedGlobalField], capacity: usize) -> Option<usize> {
    let base = capacity * size_of::<SelectedGlobalField>();
    fields.iter().try_fold(base, |bytes, field| {
        let owned = match &field.contract {
            FieldContract::Exact
            | FieldContract::IdentityAnchor
            | FieldContract::Unordered
            | FieldContract::Duration { .. } => 0,
            FieldContract::Identity { prefix, .. } => prefix.capacity(),
            FieldContract::Time {
                utc_offset,
                clock_group,
                clock_scope,
                ..
            } => {
                let scope = match clock_scope {
                    ClockScope::Entity { relative_pointer } => relative_pointer.capacity(),
                    ClockScope::Shared | ClockScope::ArrayElement => 0,
                };
                scope
                    + utc_offset.as_ref().map_or(0, String::capacity)
                    + clock_group.as_ref().map_or(0, String::capacity)
            }
            // Extension options and predicates do not have a fixed retained layout.
            FieldContract::Policy(_) | FieldContract::Conditional { .. } => return None,
        };
        Some(bytes + field.pattern.capacity() + field.pointer.capacity() + owned)
    })
}
