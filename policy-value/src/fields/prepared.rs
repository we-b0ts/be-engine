//! Immutable format options used to select contracts from actual Source values.
use super::{FieldContract, GlobalField, GlobalTimeFormat};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{borrow::Cow, collections::BTreeMap, fmt};
use traffic_policy::{PolicyRegistry, PreparedPolicy, PreparedPolicySelection};
use traffic_value::{Number, Value};

impl GlobalField {
    /// Source alone selects the declared policy applicable to this value.
    pub fn select_contract_with_registry(
        &self,
        source: &serde_json::Value,
        source_clock: Option<chrono::DateTime<chrono::Utc>>,
        policies: &PolicyRegistry,
    ) -> Result<FieldContract> {
        self.select_prepared_value_contract(
            &Value::deserialize(source)?,
            &selection_facts(source_clock)?,
            policies,
            None,
        )
    }

    pub(super) fn select_prepared_value_contract(
        &self,
        source: &Value,
        facts: &Value,
        policies: &PolicyRegistry,
        prepared: Option<&PreparedFieldFormat>,
    ) -> Result<FieldContract> {
        if let Self::Policy(definition) = self {
            let applies = match prepared {
                Some(PreparedFieldFormat::Policy(policy)) => policy.applies(source, facts)?,
                _ => policies
                    .prepare_definition(definition)?
                    .applies(source, facts)?,
            };
            return Ok(if applies {
                FieldContract::Policy(definition.clone())
            } else {
                FieldContract::Exact
            });
        }
        let is_null = matches!(source, Value::Null);
        let is_composite = matches!(source, Value::Array(_) | Value::Bytes(_) | Value::Object(_));
        if is_null && !matches!(self, Self::Unordered) {
            return Ok(FieldContract::Exact);
        }
        match self.select_format(source, facts, policies, prepared) {
            Ok(contract @ FieldContract::Identity { .. }) => Ok(contract),
            Err(error) if is_composite => Err(error),
            Ok(_) | Err(_) if self.is_identity() && !is_null => Ok(FieldContract::IdentityAnchor),
            Ok(contract) => Ok(contract),
            // Unknown scalar formats remain exact and are never translated.
            Err(_) => Ok(FieldContract::Exact),
        }
    }

    fn select_format(
        &self,
        source: &Value,
        facts: &Value,
        policies: &PolicyRegistry,
        prepared: Option<&PreparedFieldFormat>,
    ) -> Result<FieldContract> {
        match self {
            Self::Policy(_) => unreachable!("registered policies select their own applicability"),
            Self::Time { .. } | Self::Identity { .. } => {
                // Built-in declarations historically passed JSON-compatible
                // values to their registered policies, including byte arrays.
                let source = match source {
                    Value::Array(_) | Value::Bytes(_) | Value::Object(_) => {
                        Cow::Owned(serde_json::from_value(serde_json::to_value(source)?)?)
                    }
                    Value::Number(Number::Signed(number)) if *number >= 0 => {
                        Cow::Owned(Value::Number(Number::Unsigned(*number as u64)))
                    }
                    source => Cow::Borrowed(source),
                };
                let (contracts, selected) = match prepared {
                    Some(PreparedFieldFormat::Select {
                        contracts,
                        selection,
                    }) => (Cow::Borrowed(contracts), selection.select(&source, facts)?),
                    _ => {
                        let contracts = format_contracts(self).expect("registered field formats");
                        let selected =
                            policies.select(&definitions(&contracts)?, &source, facts)?;
                        (Cow::Owned(contracts), selected)
                    }
                };
                ensure!(
                    selected.is_some()
                        || !matches!(source.as_ref(), Value::Array(_) | Value::Object(_)),
                    "Source value matches no declared scalar field format"
                );
                Ok(selected.map_or(FieldContract::Exact, |index| contracts[index].clone()))
            }
            Self::Url { .. } | Self::Jwt { .. } | Self::Template { .. } => {
                anyhow::bail!("protocol leaves use the prepared verifier")
            }
            Self::Duration { formats } => {
                ensure!(
                    !matches!(source, Value::Object(_) | Value::Array(_) | Value::Bytes(_)),
                    "duration requires a scalar"
                );
                let unit = *formats
                    .first()
                    .context("duration requires exactly one unit")?;
                Ok(FieldContract::Duration {
                    unit,
                    anchor: super::TimeAnchor::Observation,
                })
            }
            Self::Unordered => {
                ensure!(
                    matches!(source, Value::Array(_) | Value::Bytes(_)),
                    "unordered requires an array"
                );
                Ok(FieldContract::Unordered)
            }
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct PreparedFieldFormats(BTreeMap<String, (GlobalField, PreparedFieldFormat)>);

impl PreparedFieldFormats {
    pub(super) fn compile(
        fields: &BTreeMap<String, GlobalField>,
        policies: &PolicyRegistry,
    ) -> Result<Self> {
        let mut prepared = BTreeMap::new();
        for (path, field) in fields {
            if let Some(format) = PreparedFieldFormat::compile(field, policies)
                .with_context(|| format!("prepare global JSON field {path:?}"))?
            {
                prepared.insert(path.clone(), (field.clone(), format));
            }
        }
        Ok(Self(prepared))
    }

    pub(super) fn get(&self, path: &str, field: &GlobalField) -> Option<&PreparedFieldFormat> {
        let (declaration, prepared) = self.0.get(path)?;
        // Derived policy views can override the declaration at an existing path.
        (declaration == field).then_some(prepared)
    }
}

pub(super) enum PreparedFieldFormat {
    Policy(PreparedPolicy),
    Select {
        contracts: Vec<FieldContract>,
        selection: PreparedPolicySelection,
    },
}

impl fmt::Debug for PreparedFieldFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(policy) => formatter
                .debug_tuple("Policy")
                .field(policy.descriptor())
                .finish(),
            Self::Select { contracts, .. } => {
                formatter.debug_tuple("Select").field(contracts).finish()
            }
        }
    }
}

impl PreparedFieldFormat {
    fn compile(field: &GlobalField, policies: &PolicyRegistry) -> Result<Option<Self>> {
        if let GlobalField::Policy(definition) = field {
            return Ok(Some(Self::Policy(policies.prepare_definition(definition)?)));
        }
        let Some(contracts) = format_contracts(field) else {
            return Ok(None);
        };
        let selection = policies.prepare_selection(definitions(&contracts)?)?;
        Ok(Some(Self::Select {
            contracts,
            selection,
        }))
    }
}

fn format_contracts(field: &GlobalField) -> Option<Vec<FieldContract>> {
    match field {
        GlobalField::Time { formats } => {
            Some(formats.iter().map(GlobalTimeFormat::contract).collect())
        }
        GlobalField::Identity { formats } => Some(
            formats
                .iter()
                .map(|format| FieldContract::Identity {
                    prefix: format.prefix.clone(),
                    format: format.format,
                })
                .collect(),
        ),
        _ => None,
    }
}

fn definitions(contracts: &[FieldContract]) -> Result<Vec<traffic_policy::PolicyDefinition>> {
    contracts
        .iter()
        .map(|contract| {
            contract
                .registered_definition(true)
                .context("field format has no registered implementation")
        })
        .collect()
}

pub(super) fn selection_facts(
    source_clock: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Value> {
    Ok(serde_json::from_value(serde_json::json!({
        "clocks":{"observation":{"source":source_clock,"target":null}}
    }))?)
}
