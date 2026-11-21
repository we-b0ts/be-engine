//! Shared identity delivery and explicitly authorized time translation.
use crate::identity::IdentityDelivery;
use std::collections::BTreeSet;

use traffic_contract::{
    delivery::{self, TimeField},
    rule::{FieldContract, TimeRelation},
};

use super::*;

pub struct RenderedMessage {
    pub values: BTreeMap<String, bytes::Bytes>,
    pub comparison: Comparison,
}

/// Original bytes of a write that the native owner verified and delivered.
pub struct StoredValue {
    pub(super) write_index: usize,
    pub(super) bytes: bytes::Bytes,
}

impl StoredValue {
    pub fn from_write(write_index: usize, bytes: bytes::Bytes) -> Self {
        Self { write_index, bytes }
    }
}

impl PreparedMessage {
    pub fn render_delivery(
        &self,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        rebase_time: &BTreeSet<String>,
        resolve_identities: impl FnOnce(&[IdentityDelivery<'_>]) -> Result<Vec<Value>>,
    ) -> Result<RenderedMessage> {
        self.render_delivery_with_documents(
            clocks,
            metadata,
            rebase_time,
            resolve_identities,
            |_, _| Ok(()),
        )
    }

    pub fn render_delivery_with_documents(
        &self,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        rebase_time: &BTreeSet<String>,
        resolve_identities: impl FnOnce(&[IdentityDelivery<'_>]) -> Result<Vec<Value>>,
        translate_document: impl Fn(&Value, &mut Value) -> Result<()>,
    ) -> Result<RenderedMessage> {
        self.render_delivery_with_storage(
            clocks,
            metadata,
            rebase_time,
            &BTreeMap::new(),
            resolve_identities,
            translate_document,
        )
    }

    /// Stored slots use the original Target bytes. The write's value policy
    /// already validated them at write time. Explicit response contracts still
    /// compare the delivered value, without deriving a new value for that slot.
    pub fn render_delivery_with_storage(
        &self,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        rebase_time: &BTreeSet<String>,
        delivered_by_protocol: &BTreeMap<String, StoredValue>,
        resolve_identities: impl FnOnce(&[IdentityDelivery<'_>]) -> Result<Vec<Value>>,
        translate_document: impl Fn(&Value, &mut Value) -> Result<()>,
    ) -> Result<RenderedMessage> {
        let mut updates = BTreeMap::new();
        let mut identity_fields = Vec::new();
        let mut identities = Vec::new();
        for (location, bound) in &self.values {
            if delivered_by_protocol.contains_key(location) {
                continue;
            }
            let original = bound.source.view().logical();
            let mut time_fields = Vec::new();
            for field in &bound.fields {
                for pointer in delivery::select(&field.pointer, original)? {
                    let contract = match &field.rule.contract {
                        FieldContract::Conditional { when, contract } => {
                            if !when.active(original, &pointer)? {
                                continue;
                            }
                            contract.as_ref()
                        }
                        contract => contract,
                    };
                    match contract {
                        FieldContract::Identity { prefix, format } => {
                            identity_fields.push((location.clone(), pointer.clone()));
                            identities.push(IdentityDelivery {
                                prefix,
                                format: *format,
                                value: original
                                    .pointer(&pointer)
                                    .context("Source identity disappeared")?,
                            });
                        }
                        contract if rebase_time.contains(&field.rule.id) => {
                            let time = contract
                                .time()
                                .context("delivery time grant requires a time field")?;
                            ensure!(
                                time.relation == TimeRelation::PreserveOffset,
                                "delivery time grant requires preserve_offset"
                            );
                            time_fields.push((field.rule.id.as_str(), pointer, time));
                        }
                        _ => (),
                    }
                }
            }
            let fields = time_fields
                .iter()
                .map(|(rule_id, pointer, contract)| TimeField {
                    rule_id,
                    pointer,
                    contract,
                })
                .collect::<Vec<_>>();
            updates.insert(
                location.clone(),
                delivery::materialize(original, &fields, clocks, metadata)?,
            );
        }
        let values = resolve_identities(&identities)?;
        ensure!(
            values.len() == identity_fields.len(),
            "identity resolver changed field cardinality"
        );
        for ((location, pointer), value) in identity_fields.into_iter().zip(values) {
            *updates
                .get_mut(&location)
                .and_then(|logical| logical.pointer_mut(&pointer))
                .context("derived identity field disappeared")? = value;
        }
        for (location, update) in &mut updates {
            translate_document(self.values[location].source.view().logical(), update)?;
        }
        let (projection, comparison) =
            self.render_projection(&updates, clocks, metadata, delivered_by_protocol)?;
        Ok(RenderedMessage {
            values: projection
                .values
                .into_iter()
                .map(|(location, value)| (location, value.bytes))
                .collect(),
            comparison,
        })
    }
}
