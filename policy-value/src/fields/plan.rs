//! Select concrete Source fields and their contracts for comparison or delivery.
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use traffic_contract::{
    compare::{AnchorClocks, LogicalProjection},
    rule::{FieldContract, IdentityFormat, TimestampFormat},
};
use traffic_policy::PolicyRegistry;
use traffic_value::Value as LogicalValue;

use super::{
    FieldOrigin, GLOBAL_JSON_ID, GlobalField, SelectedGlobalField, TimePolicy,
    prepared::{PreparedFieldFormats, selection_facts},
    selectors::{self, SelectorTree, SelectorValue},
};

/// Compiled paths are derived from authored declarations and never persisted.
#[derive(Debug, Default)]
pub struct FieldSelectors {
    paths: BTreeMap<String, traffic_contract::delivery::CompiledSelector>,
    tree: SelectorTree,
    formats: PreparedFieldFormats,
}

impl FieldSelectors {
    pub fn compile(fields: &BTreeMap<String, GlobalField>) -> Result<Self> {
        let mut tree = SelectorTree::default();
        let paths = fields
            .keys()
            .map(|pattern| {
                let selector = traffic_contract::delivery::CompiledSelector::new(pattern)?;
                tree.insert(pattern);
                Ok((pattern.clone(), selector))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            paths,
            tree,
            formats: PreparedFieldFormats::default(),
        })
    }

    pub fn compile_with_registry(
        fields: &BTreeMap<String, GlobalField>,
        policies: &PolicyRegistry,
    ) -> Result<Self> {
        let mut selectors = Self::compile(fields)?;
        selectors.formats = PreparedFieldFormats::compile(fields, policies)?;
        Ok(selectors)
    }
}

#[derive(Clone, Copy)]
enum Selection {
    Comparison,
    Delivery,
    Identity,
}

impl Selection {
    fn includes(self, field: &GlobalField) -> bool {
        match self {
            Self::Comparison => true,
            Self::Delivery => !Self::protocol_owned(field),
            Self::Identity => field.is_identity(),
        }
    }

    fn protocol_owned(field: &GlobalField) -> bool {
        matches!(
            field,
            GlobalField::Url { .. } | GlobalField::Template { .. } | GlobalField::Jwt { .. }
        )
    }
}

/// Immutable declarations are borrowed while a host supplies its installed policies.
pub struct FieldPlan<'a> {
    pub fields: &'a BTreeMap<String, GlobalField>,
    pub time: &'a TimePolicy,
    policies: &'a PolicyRegistry,
    selectors: Option<&'a FieldSelectors>,
}

impl<'a> FieldPlan<'a> {
    pub fn new(
        fields: &'a BTreeMap<String, GlobalField>,
        time: &'a TimePolicy,
        policies: &'a PolicyRegistry,
    ) -> Self {
        Self {
            fields,
            time,
            policies,
            selectors: None,
        }
    }

    pub fn with_selectors(mut self, selectors: Option<&'a FieldSelectors>) -> Self {
        self.selectors = selectors;
        self
    }

    pub(crate) fn select_paths(&self, pattern: &str, source: &Value) -> Result<Vec<String>> {
        let mut paths = Vec::new();
        let mut visitor = |pointer: &str, _: &Value| {
            paths.push(pointer.to_owned());
            Ok(())
        };
        match self
            .selectors
            .and_then(|selectors| selectors.paths.get(pattern))
        {
            Some(selector) => selector.visit(source, &mut visitor)?,
            None => traffic_contract::delivery::visit_uncompiled(pattern, source, &mut visitor)?,
        }
        Ok(paths)
    }

    /// Ask installed implementations whether Source has an implicit scalar contract.
    pub fn inferred_contract(&self, source: &Value) -> Result<Option<FieldContract>> {
        let source = source.logical()?;
        self.policies
            .infer(&source, &self.inference_facts()?)?
            .map(crate::inference::contract)
            .transpose()
    }

    pub fn identity_fields(&self, source: &Value) -> Result<Vec<(String, FieldContract)>> {
        Ok(self
            .select_authored_fields(source, None, Selection::Identity, None)?
            .into_iter()
            .map(|field| (field.pointer, field.contract))
            .collect())
    }

    pub fn fields_with_clocks(
        &self,
        source: &Value,
        clocks: AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        Ok(self
            .selected_fields_with_clocks(source, clocks)?
            .into_iter()
            .map(|field| (field.pointer, field.contract))
            .collect())
    }

    /// Standard textual time recognition permits comparison only. Delivery
    /// translation continues to require an authored field declaration.
    pub fn delivery_fields_with_clocks(
        &self,
        source: &Value,
        clocks: AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        Ok(self
            .selected_delivery_fields_with_clocks(source, clocks)?
            .into_iter()
            .map(|field| (field.pointer, field.contract))
            .collect())
    }

    pub fn selected_delivery_fields_with_clocks(
        &self,
        source: &Value,
        clocks: AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        self.select_authored_fields(
            source,
            clocks.observation().source,
            Selection::Delivery,
            None,
        )
    }

    pub fn comparison_fields(
        &self,
        source: &Value,
        _target: &Value,
        clocks: AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        // Equality is checked only after actual array-element pairing. A same
        // index Target hint would be unsafe under an unordered ancestor.
        self.fields_with_clocks(source, clocks)
    }

    pub fn selected_fields_with_clocks(
        &self,
        source: &Value,
        clocks: AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        let logical = source.logical()?;
        self.select_value_fields(&logical, clocks)
    }

    pub fn selected_value_fields_with_clocks(
        &self,
        source: &LogicalValue,
        clocks: AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        self.select_value_fields(source, clocks)
    }

    /// Build the JSON view for callers' native format checks and select fields
    /// directly on the logical Source.
    pub fn project_fields_with_clocks<'source>(
        &self,
        source: &'source LogicalValue,
        clocks: AnchorClocks,
    ) -> Result<(LogicalProjection<'source>, Vec<SelectedGlobalField>)> {
        let fields = self.select_value_fields(source, clocks)?;
        Ok((LogicalProjection::new(source)?, fields))
    }

    pub fn select_projected_fields(
        &self,
        source: &LogicalProjection<'_>,
        clocks: AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        self.select_value_fields(source.logical(), clocks)
    }

    fn inference_facts(&self) -> Result<LogicalValue> {
        Ok(serde_json::from_value(
            serde_json::json!({"settings":{"time":self.time}}),
        )?)
    }

    fn select_value_fields(
        &self,
        source: &LogicalValue,
        clocks: AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        let mut protocol_owned = BTreeSet::new();
        let mut selected = self
            .select_authored_fields(
                source,
                clocks.observation().source,
                Selection::Comparison,
                Some(&mut protocol_owned),
            )?
            .into_iter()
            .map(|field| (field.pointer.clone(), field))
            .collect::<BTreeMap<_, _>>();
        for inferred in crate::inference::fields(self.policies, source, &self.inference_facts()?)? {
            let pointer = inferred.pointer;
            let mut contract = inferred.contract;
            if protocol_owned.contains(&pointer) {
                continue;
            }
            if let Some(authored) = selected.get(&pointer) {
                let numeric_only = matches!(&self.fields[&authored.pattern], GlobalField::Time { formats } if formats.iter().all(|format| matches!(format.format, TimestampFormat::UnixSeconds | TimestampFormat::UnixMilliseconds | TimestampFormat::UnixMicroseconds)));
                if !numeric_only {
                    continue;
                }
            }
            scope_time(&pointer, &mut contract)?;
            selected.insert(
                pointer.clone(),
                SelectedGlobalField {
                    pattern: selectors::pointer_pattern(source, &pointer),
                    pointer,
                    contract,
                    rule_id: inferred.rule_id,
                    origin: FieldOrigin::Inferred,
                },
            );
        }
        Ok(selected.into_values().collect())
    }

    fn select_authored_fields<V: FieldValue>(
        &self,
        source: &V,
        source_clock: Option<chrono::DateTime<chrono::Utc>>,
        selection: Selection,
        mut protocol_owned: Option<&mut BTreeSet<String>>,
    ) -> Result<Vec<SelectedGlobalField>> {
        let mut facts = None;
        let mut fields = Vec::new();
        self.visit_authored(source, selection, |pattern, pointer, field, value| {
            let mut contract = if let GlobalField::Jwt { .. } = field
                && matches!(selection, Selection::Identity)
            {
                let Some(contract) = value.jwt_identity() else {
                    return Ok(());
                };
                contract
            } else if Selection::protocol_owned(field) {
                if let Some(protocol_owned) = protocol_owned.as_mut() {
                    protocol_owned.insert(pointer.to_owned());
                }
                return Ok(());
            } else {
                let facts = match &facts {
                    Some(facts) => facts,
                    None => facts.insert(selection_facts(source_clock)?),
                };
                let prepared = self
                    .selectors
                    .and_then(|selectors| selectors.formats.get(pattern, field));
                field
                    .select_prepared_value_contract(
                        value.logical()?.as_ref(),
                        facts,
                        self.policies,
                        prepared,
                    )
                    .with_context(|| format!("global JSON field {pointer:?}"))?
            };
            if matches!(selection, Selection::Identity)
                && !matches!(
                    contract,
                    FieldContract::Identity { .. } | FieldContract::IdentityAnchor
                )
            {
                return Ok(());
            }
            scope_time(pointer, &mut contract)?;
            fields.push(SelectedGlobalField {
                pattern: pattern.to_owned(),
                pointer: pointer.to_owned(),
                contract,
                rule_id: GLOBAL_JSON_ID,
                origin: FieldOrigin::Declared,
            });
            Ok(())
        })?;
        // A shared wildcard visits all applicable fields for each array element.
        // Preserve declaration order and the original order within each path.
        fields.sort_by(|left, right| left.pattern.cmp(&right.pattern));
        Ok(fields)
    }

    fn visit_authored<'source, V: SelectorValue>(
        &self,
        source: &'source V,
        selection: Selection,
        mut visitor: impl FnMut(&str, &str, &GlobalField, &'source V) -> Result<()>,
    ) -> Result<()> {
        let mut apply = |pattern: &str, pointer: &str, value: &'source V| {
            let field = &self.fields[pattern];
            if selection.includes(field) {
                visitor(pattern, pointer, field, value)?;
            }
            Ok(())
        };
        if let Some(selectors) = self.selectors
            && self.fields.keys().eq(selectors.paths.keys())
        {
            // A shared wildcard visits by array index. On malformed Source,
            // keep the first error in declaration order as before.
            let mut failure: Option<(String, anyhow::Error)> = None;
            selectors.tree.visit(source, |pattern, pointer, value| {
                if failure
                    .as_ref()
                    .is_none_or(|(first, _)| pattern < first.as_str())
                    && let Err(error) = apply(pattern, pointer, value)
                {
                    failure = Some((pattern.to_owned(), error));
                }
                Ok(())
            })?;
            return failure.map_or(Ok(()), |(_, error)| Err(error));
        }
        // Derived views can introduce or remove paths independently of the
        // loaded policy's compiled selectors.
        for (pattern, field) in self.fields {
            if selection.includes(field) {
                traffic_contract::path::validate_pointer(pattern, true)?;
                let mut tree = SelectorTree::default();
                tree.insert(pattern);
                tree.visit(source, &mut apply)?;
            }
        }
        Ok(())
    }
}

trait FieldValue: SelectorValue {
    fn logical(&self) -> Result<Cow<'_, LogicalValue>>;
    fn jwt_identity(&self) -> Option<FieldContract>;
}

impl FieldValue for Value {
    fn logical(&self) -> Result<Cow<'_, LogicalValue>> {
        Ok(Cow::Owned(LogicalValue::deserialize(self)?))
    }

    fn jwt_identity(&self) -> Option<FieldContract> {
        if crate::formats::is_jwt(self) {
            Some(FieldContract::Identity {
                prefix: String::new(),
                format: IdentityFormat::Jwt,
            })
        } else if !(self.is_null() || self.is_array() || self.is_object()) {
            Some(FieldContract::IdentityAnchor)
        } else {
            None
        }
    }
}

impl FieldValue for LogicalValue {
    fn logical(&self) -> Result<Cow<'_, LogicalValue>> {
        Ok(Cow::Borrowed(self))
    }

    fn jwt_identity(&self) -> Option<FieldContract> {
        serde_json::to_value(self).ok()?.jwt_identity()
    }
}

fn scope_time(pointer: &str, contract: &mut FieldContract) -> Result<()> {
    if let FieldContract::Time { clock_group, .. } = contract {
        let digest = digest("traffic-policy/global-json-clock/v1", &pointer)?;
        *clock_group = Some(format!("schema.{}", &digest[7..39]));
    }
    Ok(())
}

fn digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(value)?);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

/// Generalize only Source array coordinates. Numeric object member names keep
/// their exact JSON Pointer spelling and cannot become wildcard permissions.
pub fn pointer_pattern(source: &Value, pointer: &str) -> String {
    selectors::pointer_pattern(source, pointer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_wildcard_preserves_declaration_order_for_source_errors() {
        use traffic_contract::rule::DurationUnit;

        let fields = BTreeMap::from([
            ("/items/*/id".into(), GlobalField::Unordered),
            (
                "/items/*/timestamp".into(),
                GlobalField::Duration {
                    formats: vec![DurationUnit::Seconds],
                },
            ),
        ]);
        let time = TimePolicy::default();
        let registry = PolicyRegistry::default();
        let selectors = FieldSelectors::compile(&fields).unwrap();
        let plan = FieldPlan::new(&fields, &time, &registry).with_selectors(Some(&selectors));
        let source =
            serde_json::json!({"items":[{"id":[],"timestamp":[]},{"id":{},"timestamp":1}]});
        let error = plan
            .selected_delivery_fields_with_clocks(&source, AnchorClocks::default())
            .unwrap_err();
        assert_eq!(error.to_string(), "global JSON field \"/items/1/id\"");
    }
}
