//! Shared identity delivery and explicitly authorized time translation.
use crate::identity::IdentityDelivery;
use std::{borrow::Cow, collections::BTreeSet};

use traffic_contract::{
    delivery::{self, TimeField},
    rule::{FieldContract, TimeRelation},
};

use super::*;

pub struct RenderedMessage {
    pub values: BTreeMap<String, bytes::Bytes>,
    pub comparison: Comparison,
}

pub struct PrefetchedMessage {
    pub rendered: RenderedMessage,
    pub guards: Vec<Box<dyn PreparedDeliveryGuard>>,
}

/// The runtime facts read to prepare one document's delivery.
pub trait PreparedDeliveryGuard: Send + Sync {
    fn retained_bytes(&self) -> usize;
    fn is_current(&self) -> bool;
}

impl RenderedMessage {
    fn from_projection(projection: ProjectedMessage, comparison: Comparison) -> Self {
        Self {
            values: projection
                .values
                .into_iter()
                .map(|(location, value)| (location, value.bytes))
                .collect(),
            comparison,
        }
    }
}

/// Source-only delivery selection. The owner applies it with live state.
pub trait PreparedDocumentDelivery: Send + Sync {
    fn retained_bytes(&self) -> usize;

    /// The plan can run on a tentative state read before the live Target clocks
    /// are known. The caller still checks that the state read is current.
    fn clock_independent(&self) -> bool {
        false
    }

    /// Return false without editing when the plan is inapplicable.
    fn apply(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Cow<'_, Value>,
        clocks: AnchorClocks,
    ) -> Result<bool>;

    /// Apply the plan and retain the runtime facts needed to reuse its output.
    fn prefetch_apply(
        &self,
        _scope: &str,
        _source: &Value,
        _delivered: &mut Cow<'_, Value>,
        _clocks: AnchorClocks,
    ) -> Result<Option<Box<dyn PreparedDeliveryGuard>>> {
        Ok(None)
    }
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
    /// Resolve selectors against the immutable Source before live delivery.
    pub fn prepare_delivery(&mut self) -> Result<()> {
        if let Some(policy) = &self.policy {
            for bound in self.values.values_mut() {
                bound.prepared_delivery = policy.prepare_delivery(bound.source.view().logical())?;
            }
        }
        Ok(())
    }

    pub fn has_prepared_delivery(&self) -> bool {
        self.values
            .values()
            .any(|bound| bound.prepared_delivery.is_some())
    }

    /// Render a response without scoped bindings or live native storage overrides.
    /// Reuse the matching Source comparison for unchanged output. The caller
    /// validates the retained guards before using the result.
    pub fn prefetch_delivery(
        &self,
        scope: &str,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        source_comparison: &mut Comparison,
    ) -> Result<Option<PrefetchedMessage>> {
        if !source_comparison.passed() {
            return Ok(None);
        }
        let mut updates = Vec::new();
        let mut guards = Vec::with_capacity(self.values.len());
        for (location, bound) in &self.values {
            if bound.codec != Codec::Json
                || !bound.fields.is_empty()
                || !bound
                    .prepared_comparison
                    .as_ref()
                    .is_some_and(|comparison| {
                        comparison.clock_independent() && comparison.applies_at(clocks)
                    })
                || !matches!(
                    bound.source.logical_comparison_view(&bound.pointers),
                    Cow::Borrowed(value) if std::ptr::eq(value, bound.source.value())
                )
            {
                return Ok(None);
            }
            let Some(plan) = &bound.prepared_delivery else {
                return Ok(None);
            };
            if !plan.clock_independent() {
                return Ok(None);
            }
            let source = bound.source.view().logical();
            let mut delivered = Cow::Borrowed(source);
            let Some(guard) = plan.prefetch_apply(scope, source, &mut delivered, clocks)? else {
                return Ok(None);
            };
            guards.push(guard);
            if let Cow::Owned(document) = delivered {
                updates.push((location, document));
            }
        }
        let rendered = if updates.is_empty() {
            self.unchanged_delivery(std::mem::take(source_comparison))
        } else {
            let (output, comparison) = self.render_projection(
                updates.iter().map(|(location, value)| (*location, value)),
                clocks,
                metadata,
                &BTreeMap::new(),
            )?;
            RenderedMessage::from_projection(output, comparison)
        };
        Ok(Some(PrefetchedMessage { rendered, guards }))
    }

    fn unchanged_delivery(&self, comparison: Comparison) -> RenderedMessage {
        RenderedMessage {
            values: self
                .projection
                .values
                .iter()
                .map(|(location, value)| (location.clone(), value.bytes.clone()))
                .collect(),
            comparison,
        }
    }

    pub fn render_delivery(
        &self,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        rebase_time: &BTreeSet<String>,
        resolve_identities: impl FnOnce(&[IdentityDelivery<'_>]) -> Result<Vec<Value>>,
    ) -> Result<RenderedMessage> {
        self.render_delivery_with_lazy_documents(
            clocks,
            metadata,
            rebase_time,
            &BTreeMap::new(),
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
        self.render_delivery_with_lazy_documents(
            clocks,
            metadata,
            rebase_time,
            delivered_by_protocol,
            resolve_identities,
            |source, delivered| translate_document(source, delivered.to_mut()),
        )
    }

    /// Translate a delivery document while borrowing the original JSON until
    /// a translation needs an owned value.
    pub fn render_delivery_with_lazy_documents(
        &self,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        rebase_time: &BTreeSet<String>,
        delivered_by_protocol: &BTreeMap<String, StoredValue>,
        resolve_identities: impl FnOnce(&[IdentityDelivery<'_>]) -> Result<Vec<Value>>,
        translate_document: impl Fn(&Value, &mut Cow<'_, Value>) -> Result<()>,
    ) -> Result<RenderedMessage> {
        self.render_delivery_with_prepared_documents(
            clocks,
            metadata,
            rebase_time,
            delivered_by_protocol,
            resolve_identities,
            |source, delivered, _| translate_document(source, delivered),
        )
    }

    pub fn render_delivery_with_prepared_documents(
        &self,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        rebase_time: &BTreeSet<String>,
        delivered_by_protocol: &BTreeMap<String, StoredValue>,
        resolve_identities: impl FnOnce(&[IdentityDelivery<'_>]) -> Result<Vec<Value>>,
        translate_document: impl Fn(
            &Value,
            &mut Cow<'_, Value>,
            Option<&dyn PreparedDocumentDelivery>,
        ) -> Result<()>,
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
            let mut delivered = delivery::materialize_cow(original, &fields, clocks, metadata)?;
            if bound.codec != Codec::Json {
                // Other codecs still own their own delivery serialization.
                delivered = Cow::Owned(delivered.into_owned());
            }
            updates.insert(location.clone(), (bound, delivered));
        }
        let values = resolve_identities(&identities)?;
        ensure!(
            values.len() == identity_fields.len(),
            "identity resolver changed field cardinality"
        );
        for ((location, pointer), value) in identity_fields.into_iter().zip(values) {
            let (_, document) = updates
                .get_mut(&location)
                .context("derived identity field disappeared")?;
            if document.pointer(&pointer) != Some(&value) {
                *document
                    .to_mut()
                    .pointer_mut(&pointer)
                    .context("derived identity field disappeared")? = value;
            }
        }
        for (bound, document) in updates.values_mut() {
            translate_document(
                bound.source.view().logical(),
                document,
                bound.prepared_delivery.as_deref(),
            )?;
        }
        let mut edited = updates
            .iter()
            .filter_map(|(location, (bound, document))| {
                if bound.codec == Codec::Json
                    && std::ptr::eq(bound.source.view().logical(), document.as_ref())
                {
                    None
                } else {
                    Some((location, document.as_ref()))
                }
            })
            .peekable();
        if delivered_by_protocol.is_empty() && edited.peek().is_none() {
            let comparison = self.compare_source(clocks, metadata);
            ensure!(
                comparison.passed(),
                "derived native values violate their field contracts"
            );
            return Ok(self.unchanged_delivery(comparison));
        }
        let (projection, comparison) =
            self.render_projection(edited, clocks, metadata, delivered_by_protocol)?;
        Ok(RenderedMessage::from_projection(projection, comparison))
    }
}
