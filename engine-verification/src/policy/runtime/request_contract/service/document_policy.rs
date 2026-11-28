//! Reuse immutable field applicability across Source and live document comparisons.
use std::{mem::size_of, sync::Arc};

use anyhow::Result;
use traffic_contract::{
    compare::{AnchorClocks, Comparison, Field, LogicalProjection},
    rule::{ClockScope, FieldContract},
};
use traffic_policy_value::{
    DocumentPolicy, DocumentPolicyPreparation, PreparedDocumentComparison,
    PreparedDocumentDelivery,
    fields::{MatchedFormatField, SelectedGlobalField},
    formats::{self, FormatChecks, FormatHost},
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
    fn may_compare_unclaimed(&self) -> bool {
        policy(&self.owner).auth_matcher().is_some()
    }

    fn authenticated_paths(
        &self,
        source: &Value,
        target: &Value,
        clocks: AnchorClocks,
    ) -> Vec<String> {
        policy(&self.owner)
            .auth_matcher()
            .map(|matcher| matcher.matching_string_paths(source, target, clocks))
            .unwrap_or_default()
    }
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
        Ok(self.bind_fields(prepared, None))
    }

    fn prepare_json_source(
        &self,
        source: &LogicalProjection<'_>,
    ) -> Result<DocumentPolicyPreparation> {
        let selected = policy(&self.owner)
            .field_plan()
            .prepare_json_fields(source.logical(), self.clocks)?;
        let checks = formats::checks_at_matches(
            self.owner.clone(),
            |owner: &Arc<RequestContracts>| policy(owner) as &dyn FormatHost,
            source.json(),
            &selected.native,
        )?;
        let prepared =
            traffic_policy_execution::global::bind_prepared_fields(selected.comparison, &checks);
        Ok(self.bind_fields(
            prepared,
            Some(PreparedJson {
                native: selected.native,
                checks,
                delivery_times: selected.delivery_times,
            }),
        ))
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

impl GlobalDocumentPolicy {
    fn bind_fields(
        &self,
        prepared: traffic_policy_execution::global::PreparedGlobalFields,
        json: Option<PreparedJson>,
    ) -> DocumentPolicyPreparation {
        let fields = prepared.selected;
        let bytes = retained_fields(&fields, fields.capacity()).and_then(|bytes| {
            let json = match &json {
                Some(json) => json.retained_bytes()?,
                None => 0,
            };
            Some(size_of::<PreparedFields>() + bytes + json)
        });
        let comparison = bytes.map(|bytes| {
            Box::new(PreparedFields {
                owner: self.owner.clone(),
                clocks: self.clocks,
                fields,
                clock_independent: prepared.clock_independent,
                json,
                bytes,
            }) as Box<dyn PreparedDocumentComparison>
        });
        DocumentPolicyPreparation {
            paths: prepared.paths,
            comparison,
        }
    }
}

struct PreparedJson {
    native: Vec<MatchedFormatField>,
    checks: FormatChecks<'static>,
    delivery_times: Vec<SelectedGlobalField>,
}

impl PreparedJson {
    fn retained_bytes(&self) -> Option<usize> {
        let times = retained_fields(&self.delivery_times, self.delivery_times.capacity())?;
        Some(times + self.checks.retained_bytes() + retained_native_matches(&self.native))
    }
}

fn retained_native_matches(native: &Vec<MatchedFormatField>) -> usize {
    native.capacity() * size_of::<MatchedFormatField>()
        + native
            .iter()
            .map(|field| field.pattern.capacity() + field.pointer.capacity())
            .sum::<usize>()
}

struct PreparedFields {
    owner: Arc<RequestContracts>,
    clocks: AnchorClocks,
    fields: Vec<SelectedGlobalField>,
    clock_independent: bool,
    json: Option<PreparedJson>,
    bytes: usize,
}

impl PreparedDocumentComparison for PreparedFields {
    fn applies_at(&self, clocks: AnchorClocks) -> bool {
        self.clocks.observation().source == clocks.observation().source
    }

    fn clock_independent(&self) -> bool {
        self.clock_independent
    }

    fn prepare_delivery(
        &self,
        source: &serde_json::Value,
        fallback: &dyn DocumentPolicy,
    ) -> Result<Option<Box<dyn PreparedDocumentDelivery>>> {
        let Some(json) = &self.json else {
            return fallback.prepare_delivery(source);
        };
        delivery::prepare_matched(self.owner.clone(), self.clocks, source, &self.fields, json)
    }

    fn compare(
        &self,
        source: &Value,
        target: &Value,
        fields: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        if self.json.is_some() {
            return self.compare_projected(
                &LogicalProjection::new(source)?,
                target,
                fields,
                clocks,
            );
        }
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
        if let Some(json) = &self.json {
            let base = crate::value_contract::execution_context();
            let auth = traffic_policy_value::auth::Metadata::new(
                base.metadata,
                policy(&self.owner).auth_matcher(),
            );
            let context = traffic_policy_execution::ExecutionContext {
                metadata: auth.rules(),
                ..base
            };
            return Ok(traffic_policy_execution::global::compare_selected_fields(
                &context,
                source,
                target,
                fields,
                &self.fields,
                &json.checks,
                clocks,
            ));
        }
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
