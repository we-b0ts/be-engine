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

mod delivery;
pub use delivery::RenderedMessage;
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
    fn paths(&self, source: &Value) -> Result<Vec<String>>;
    fn compare(
        &self,
        source: &Value,
        target: &Value,
        fields: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison>;
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
}

/// Prepared once per immutable Source message. Each attempted candidate keeps
/// its own comparison proposals until request admission commits them.
pub struct PreparedMessage {
    projection: ProjectedMessage,
    values: BTreeMap<String, BoundValue>,
    policy: Option<Arc<dyn DocumentPolicy>>,
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
    pub(crate) fn structure(&self) -> &Value {
        &self.projection.structure
    }

    pub fn compile(native: &dyn ProtocolMessage, bindings: &[RuleBinding]) -> Result<Self> {
        Self::compile_with_policy(native, bindings, None)
    }

    pub fn compile_with_policy(
        native: &dyn ProtocolMessage,
        bindings: &[RuleBinding],
        policy: Option<Arc<dyn DocumentPolicy>>,
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
                    let plan = CodecPlan::compile(&binding.codec)?;
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
                if value.scalar_encoding != ScalarEncoding::Json || values.contains_key(location) {
                    continue;
                }
                let codec = Codec::Json;
                let plan = CodecPlan::compile(&codec)?;
                let source = decode(&plan, &codec, value)?;
                values.insert(
                    location.clone(),
                    BoundValue {
                        codec,
                        scalar_encoding: value.scalar_encoding,
                        plan,
                        source,
                        fields: Vec::new(),
                        pointers: Vec::new(),
                    },
                );
            }
            for value in values.values_mut() {
                value
                    .pointers
                    .extend(policy.paths(value.source.view().logical())?);
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
        Ok(self.compare_projection(&actual, clocks, metadata))
    }

    fn compare_projection(
        &self,
        actual: &ProjectedMessage,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
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
            let target = &actual.values[location];
            if source.scalar_encoding != target.scalar_encoding {
                result
                    .differences
                    .push(difference(location, "native scalar representation changed"));
                continue;
            }
            let Some(bound) = self.values.get(location) else {
                if source.bytes != target.bytes {
                    result
                        .differences
                        .push(difference(location, "unselected native value changed"));
                }
                continue;
            };
            let target = match decode(&bound.plan, &bound.codec, target) {
                Ok(target) => target,
                Err(_) => {
                    result.differences.push(difference(
                        location,
                        "Target value violates its content codec",
                    ));
                    continue;
                }
            };
            let source = bound.source.comparison_view(&bound.pointers);
            let target = target.comparison_view(&bound.pointers);
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
                Some(policy) => match policy.compare(&source, &target, &fields, clocks) {
                    Ok(comparison) => comparison,
                    Err(error) => {
                        result
                            .differences
                            .push(difference(location, &error.to_string()));
                        continue;
                    }
                },
                None => {
                    compare::compare_all(&source, &target, &fields, &[], &[], clocks, &[], metadata)
                }
            };
            comparison.scope_schema_clocks_in(location);
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
        let (rendered, _) = self.render_projection(updates, clocks, metadata)?;
        Ok(rendered
            .values
            .into_iter()
            .map(|(location, value)| (location, value.bytes))
            .collect())
    }

    fn render_projection(
        &self,
        updates: &BTreeMap<String, Value>,
        clocks: AnchorClocks,
        metadata: &dyn RuleMetadata,
    ) -> Result<(ProjectedMessage, Comparison)> {
        let mut values = self.projection.values.clone();
        for (location, logical) in updates {
            let bound = self
                .values
                .get(location)
                .context("delivery changes an unbound physical value")?;
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
        let comparison = self.compare_projection(&rendered, clocks, metadata);
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
