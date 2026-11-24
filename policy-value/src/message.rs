//! One rule executor for values located by any registered dependency protocol.
use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_contract::{
    codec::{Codec, CodecPlan, DecodedDocument},
    compare::{self, AnchorClocks, Comparison, Field, RuleMetadata},
    comparison::Difference,
    rule::FieldContract,
};
use traffic_protocol::message::{
    ProjectedMessage, ProjectedValue, ProtocolMessage, ScalarEncoding,
};
use traffic_value::codec::CodecRegistry;

mod delivery;
pub use delivery::{RenderedMessage, StoredValue};
mod registry;
pub use registry::{BindingRegistry, MessageSide};

#[derive(Debug, Clone)]
pub struct ValueRule {
    pub id: String,
    pub contract: FieldContract,
}

/// One semantic rule may have several native bindings and content strategies.
#[derive(Clone)]
pub struct RuleBinding {
    pub rule: Arc<ValueRule>,
    pub selector: Value,
    pub codec: Codec,
    pub pointer: String,
}

/// Prepared content rules operate on decoded documents from every native carrier.
pub trait DocumentPolicy: Send + Sync {
    fn paths(&self, source: &traffic_value::Value) -> Result<Vec<String>>;
    fn prepare_source(&self, source: &traffic_value::Value) -> Result<DocumentPolicyPreparation> {
        Ok(DocumentPolicyPreparation {
            paths: self.paths(source)?,
            comparison: None,
        })
    }
    fn compare(
        &self,
        source: &traffic_value::Value,
        target: &traffic_value::Value,
        fields: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison>;
}

pub struct DocumentPolicyPreparation {
    pub paths: Vec<String>,
    pub comparison: Option<Box<dyn PreparedDocumentComparison>>,
}

/// Immutable Source rule selection. The caller still supplies live clocks and
/// the current Target value to evaluate the selected contracts.
pub trait PreparedDocumentComparison: Send + Sync {
    fn applies_at(&self, clocks: AnchorClocks) -> bool;
    fn compare(
        &self,
        source: &traffic_value::Value,
        target: &traffic_value::Value,
        fields: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison>;
    fn retained_bytes(&self) -> usize;
}

struct FieldBinding {
    rule: Arc<ValueRule>,
    pointer: String,
}

struct BoundValue {
    codec: Codec,
    scalar_encoding: ScalarEncoding,
    plan: CodecPlan,
    source: DecodedDocument,
    fields: Vec<FieldBinding>,
    pointers: Vec<String>,
    prepared_comparison: Option<Box<dyn PreparedDocumentComparison>>,
}

/// Prepared once per immutable Source message. Each attempted candidate keeps
/// its own comparison proposals until request admission commits them.
pub struct PreparedMessage {
    projection: ProjectedMessage,
    values: BTreeMap<String, BoundValue>,
    policy: Option<Arc<dyn DocumentPolicy>>,
}

fn json_heap_bytes(value: &Value) -> usize {
    match value {
        Value::String(text) => text.capacity(),
        Value::Array(items) => {
            items.capacity() * std::mem::size_of::<Value>()
                + items.iter().map(json_heap_bytes).sum::<usize>()
        }
        Value::Object(fields) => fields
            .iter()
            .map(|(name, value)| 128 + name.capacity() + json_heap_bytes(value))
            .sum(),
        _ => 0,
    }
}

impl std::fmt::Debug for PreparedMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedMessage")
            .field("values", &self.projection.values.len())
            .field("bound_values", &self.values.len())
            .finish()
    }
}

impl PreparedMessage {
    pub fn structure(&self) -> &Value {
        &self.projection.structure
    }

    pub fn projection(&self) -> &ProjectedMessage {
        &self.projection
    }

    pub fn has_value_rules(&self, location: &str) -> bool {
        self.values.contains_key(location)
    }

    pub fn has_bound_values(&self) -> bool {
        !self.values.is_empty()
    }

    pub fn compile(
        native: &dyn ProtocolMessage,
        bindings: &[RuleBinding],
        codecs: &CodecRegistry,
    ) -> Result<Self> {
        Self::compile_with_policy(native, bindings, None, codecs)
    }

    pub fn compile_with_policy(
        native: &dyn ProtocolMessage,
        bindings: &[RuleBinding],
        policy: Option<Arc<dyn DocumentPolicy>>,
        codecs: &CodecRegistry,
    ) -> Result<Self> {
        let projection = native.project()?;
        let mut values = BTreeMap::<String, BoundValue>::new();
        let mut rules = BTreeMap::<&str, &FieldContract>::new();
        for binding in bindings {
            ensure!(!binding.rule.id.is_empty(), "value rule identity is empty");
            traffic_contract::path::validate_pointer(&binding.pointer, true)?;
            if let Some(contract) = rules.insert(&binding.rule.id, &binding.rule.contract) {
                ensure!(
                    contract == &binding.rule.contract,
                    "one value rule has conflicting semantics"
                );
            }
            for location in native.locate(&binding.selector)? {
                let bytes = projection
                    .values
                    .get(&location)
                    .context("native rule binding refers to an absent value")?;
                if !values.contains_key(&location) {
                    let plan = CodecPlan::compile(&binding.codec, codecs)?;
                    let source = decode(&plan, &binding.codec, bytes)?;
                    values.insert(
                        location.clone(),
                        BoundValue {
                            codec: binding.codec.clone(),
                            scalar_encoding: bytes.scalar_encoding,
                            plan,
                            source,
                            fields: Vec::new(),
                            pointers: Vec::new(),
                            prepared_comparison: None,
                        },
                    );
                }
                let value = values.get_mut(&location).expect("bound value was prepared");
                ensure!(
                    value.codec == binding.codec,
                    "one physical value has conflicting content codecs"
                );
                value.fields.push(FieldBinding {
                    rule: binding.rule.clone(),
                    pointer: binding.pointer.clone(),
                });
                value.pointers.push(binding.pointer.clone());
            }
        }
        if let Some(policy) = &policy {
            for (location, value) in &projection.values {
                if values.contains_key(location) {
                    continue;
                }
                let metadata = serde_json::from_value(serde_json::json!({
                    "native":{"location":location,"structure":projection.structure},
                }))?;
                let Some((plan, decoded)) =
                    CodecPlan::try_recognize_source(&value.bytes, &metadata, codecs)?
                else {
                    continue;
                };
                let codec = plan.declaration()?;
                let source = match decoded {
                    Some(decoded)
                        if codec != Codec::Scalar
                            || value.scalar_encoding != ScalarEncoding::Utf8 =>
                    {
                        decoded
                    }
                    _ => decode(&plan, &codec, value)?,
                };
                let prepared = policy.prepare_source(source.value())?;
                if prepared.paths.is_empty() {
                    continue;
                }
                values.insert(
                    location.clone(),
                    BoundValue {
                        codec,
                        scalar_encoding: value.scalar_encoding,
                        plan,
                        source,
                        fields: Vec::new(),
                        pointers: prepared.paths,
                        prepared_comparison: prepared.comparison,
                    },
                );
            }
            for value in values.values_mut().filter(|value| !value.fields.is_empty()) {
                let prepared = policy.prepare_source(value.source.value())?;
                value.pointers.extend(prepared.paths);
                value.prepared_comparison = prepared.comparison;
            }
        }
        Ok(Self {
            projection,
            values,
            policy,
        })
    }

    pub fn compare(
        &self,
        actual: &dyn ProtocolMessage,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
    ) -> Result<Comparison> {
        let actual = actual.project()?;
        Ok(self.compare_projection(&actual, clocks, metadata, &BTreeMap::new()))
    }

    pub fn compare_source(&self, clocks: AnchorClocks, metadata: &dyn RuleMetadata) -> Comparison {
        self.compare_projection(&self.projection, clocks, metadata, &BTreeMap::new())
    }

    /// Estimate retained Source preparation for codecs with a known layout.
    /// Include projected values whose bytes can be independent of the encoder.
    pub fn prefetch_retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>() + json_heap_bytes(&self.projection.structure);
        for (location, value) in &self.projection.values {
            bytes += 128 + location.capacity() + value.bytes.len();
        }
        for (location, bound) in &self.values {
            if !matches!(bound.codec.id(), "json" | "scalar") {
                return None;
            }
            // The JSON codec retains its logical tree and the projected JSON
            // tree, alongside the original wire bytes.
            bytes += 128
                + location.capacity()
                + bound.source.original_bytes().len()
                + 2 * json_heap_bytes(&bound.source.logical)
                + bound.fields.capacity() * std::mem::size_of::<FieldBinding>()
                + bound
                    .fields
                    .iter()
                    .map(|field| field.pointer.capacity())
                    .sum::<usize>()
                + bound.pointers.capacity() * std::mem::size_of::<String>()
                + bound.pointers.iter().map(String::capacity).sum::<usize>()
                + bound
                    .prepared_comparison
                    .as_ref()
                    .map_or(0, |prepared| prepared.retained_bytes());
        }
        Some(bytes)
    }

    fn compare_projection(
        &self,
        actual: &ProjectedMessage,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        delivered_by_protocol: &BTreeMap<String, StoredValue>,
    ) -> Comparison {
        let mut result = Comparison::default();
        if self.projection.structure != actual.structure {
            result
                .differences
                .push(difference("", "native message structure changed"));
            return result;
        }
        if !self.projection.values.keys().eq(actual.values.keys()) {
            result.differences.push(difference(
                "",
                "native value presence or multiplicity changed",
            ));
            return result;
        }
        for (location, source) in &self.projection.values {
            let stored = delivered_by_protocol.contains_key(location);
            let bound = self.values.get(location);
            if stored && bound.is_none_or(|value| value.fields.is_empty()) {
                continue;
            }
            let target = &actual.values[location];
            if source.scalar_encoding != target.scalar_encoding {
                result
                    .differences
                    .push(difference(location, "native scalar representation changed"));
                continue;
            }
            let Some(bound) = bound else {
                if source.bytes != target.bytes {
                    result
                        .differences
                        .push(difference(location, "unselected native value changed"));
                }
                continue;
            };
            let decoded_target;
            let target = if std::ptr::eq(source.bytes.as_ref(), target.bytes.as_ref()) {
                &bound.source
            } else {
                match decode(&bound.plan, &bound.codec, target) {
                    Ok(target) => {
                        decoded_target = target;
                        &decoded_target
                    }
                    Err(_) => {
                        result.differences.push(difference(
                            location,
                            "Target value violates its content codec",
                        ));
                        continue;
                    }
                }
            };
            let source = bound.source.logical_comparison_view(&bound.pointers);
            let target = target.logical_comparison_view(&bound.pointers);
            let fields = bound
                .fields
                .iter()
                .map(|field| Field {
                    rule_id: &field.rule.id,
                    pointer: &field.pointer,
                    contract: &field.rule.contract,
                })
                .collect::<Vec<_>>();
            let mut comparison = match &self.policy {
                Some(policy) if !stored => {
                    let prepared = bound.prepared_comparison.as_ref().filter(|prepared| {
                        std::ptr::eq(source.as_ref(), bound.source.value())
                            && prepared.applies_at(clocks)
                    });
                    let comparison = match prepared {
                        Some(prepared) => prepared.compare(&source, &target, &fields, clocks),
                        None => policy.compare(&source, &target, &fields, clocks),
                    };
                    match comparison {
                        Ok(comparison) => comparison,
                        Err(error) => {
                            result
                                .differences
                                .push(difference(location, &error.to_string()));
                            continue;
                        }
                    }
                }
                _ => compare::compare_logical_all(
                    &source,
                    &target,
                    &fields,
                    &[],
                    &[],
                    clocks,
                    &[],
                    metadata,
                ),
            };
            comparison.scope_observations(location);
            for difference in &mut comparison.differences {
                difference.pointer = format!("{location}{}", difference.pointer);
            }
            result.merge_and_validate(comparison);
        }
        result
    }

    /// Derived delivery changes pass the same codec's selected-path guard. The
    /// native encoder receives every other physical value with its original bytes.
    pub fn render_values(
        &self,
        updates: &BTreeMap<String, Value>,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
    ) -> Result<BTreeMap<String, bytes::Bytes>> {
        let (rendered, _) = self.render_projection(updates, clocks, metadata, &BTreeMap::new())?;
        Ok(rendered
            .values
            .into_iter()
            .map(|(location, value)| (location, value.bytes))
            .collect())
    }

    fn render_projection<'a>(
        &self,
        updates: impl IntoIterator<Item = (&'a String, &'a Value)>,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
        delivered_by_protocol: &BTreeMap<String, StoredValue>,
    ) -> Result<(ProjectedMessage, Comparison)> {
        let mut values = self.projection.values.clone();
        for (location, value) in delivered_by_protocol {
            values
                .get_mut(location)
                .with_context(|| {
                    format!(
                        "native write {} has no Source response value slot",
                        value.write_index
                    )
                })?
                .bytes = value.bytes.clone();
        }
        for (location, logical) in updates {
            let bound = self
                .values
                .get(location)
                .context("delivery changes an unbound physical value")?;
            if bound.codec == Codec::Json
                && !delivered_by_protocol.contains_key(location)
                && bound.source.view().logical() == logical
            {
                continue;
            }
            let encoded = bound.source.encode(logical, &bound.pointers)?;
            let bytes =
                if bound.codec == Codec::Scalar && bound.scalar_encoding == ScalarEncoding::Utf8 {
                    bytes::Bytes::from(serde_json::from_slice::<String>(&encoded)?)
                } else {
                    bytes::Bytes::from(encoded)
                };
            values.insert(
                location.clone(),
                ProjectedValue {
                    bytes,
                    scalar_encoding: bound.scalar_encoding,
                },
            );
        }
        let rendered = ProjectedMessage {
            structure: self.projection.structure.clone(),
            values,
        };
        let comparison =
            self.compare_projection(&rendered, clocks, metadata, delivered_by_protocol);
        ensure!(
            comparison.passed(),
            "derived native values violate their field contracts"
        );
        Ok((rendered, comparison))
    }
}

fn decode(plan: &CodecPlan, codec: &Codec, value: &ProjectedValue) -> Result<DecodedDocument> {
    if *codec == Codec::Scalar && value.scalar_encoding == ScalarEncoding::Utf8 {
        let scalar = std::str::from_utf8(&value.bytes).context("native scalar is not UTF-8")?;
        plan.decode(&serde_json::to_vec(scalar)?)
    } else {
        plan.decode(&value.bytes)
    }
}

fn difference(location: &str, reason: &str) -> Difference {
    Difference {
        pointer: location.into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests;
