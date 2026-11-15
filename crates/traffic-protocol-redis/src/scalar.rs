//! Redis scalars retain their Source wire form and use the shared field kernel.
use traffic_contract::compare::{
    self as json, AnchorClocks, Comparison, Field, RuleMetadata, ValueCopyProof,
};
use traffic_policy_value::{
    fields::{FieldPlan, GLOBAL_JSON_ID, GlobalField, TimePolicy},
    formats::FormatHost,
};
pub const GLOBAL_REDIS_ID: &str = "global.redis";
use anyhow::{Context, Result, ensure};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Scalar {
    pub logical: Value,
    original: Vec<u8>,
    pub json: bool,
}

pub fn decode(source: &[u8]) -> Result<Option<Scalar>> {
    ensure!(
        source.len() <= traffic_contract::MAX_VALUE_BYTES,
        "Redis scalar exceeds the 64 MiB value limit"
    );
    if let Some(logical) = traffic_contract::json::parse(source) {
        if logical.is_array() || logical.is_object() {
            return Ok(None);
        }
        return Ok(Some(Scalar {
            logical,
            original: source.to_vec(),
            json: true,
        }));
    }
    let Ok(text) = std::str::from_utf8(source) else {
        return Ok(None);
    };
    Ok(Some(Scalar {
        logical: Value::String(text.into()),
        original: source.to_vec(),
        json: false,
    }))
}

/// A declared string identity wins over an accidental JSON-number spelling.
/// Source alone chooses this interpretation; Target cannot change the codec.
pub fn decode_field(
    source: &[u8],
    field: &GlobalField,
    policies: &traffic_policy::PolicyRegistry,
) -> Result<Option<Scalar>> {
    let Some(mut scalar) = decode(source)? else {
        return Ok(None);
    };
    if scalar.logical.is_number()
        && field.is_identity()
        && !matches!(
            field.select_contract_with_registry(&scalar.logical, None, policies),
            Ok(traffic_contract::rule::FieldContract::Identity { .. })
        )
    {
        let text = std::str::from_utf8(source)?;
        let value = Value::String(text.into());
        if matches!(
            field.select_contract_with_registry(&value, None, policies),
            Ok(traffic_contract::rule::FieldContract::Identity { .. })
        ) {
            scalar.logical = value;
            scalar.json = false;
        }
    }
    Ok(Some(scalar))
}

/// Native text stays native text. Only a Source-selected shared time contract
/// authorizes interpreting an otherwise opaque scalar as a time value.
pub fn decode_automatic(
    source: &[u8],
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
) -> Result<Option<Scalar>> {
    if !(10..=35).contains(&source.len()) {
        return Ok(None);
    }
    let Some(scalar) = decode(source)? else {
        return Ok(None);
    };
    if scalar.json
        || !plan
            .field_plan()
            .inferred_contract(&scalar.logical)
            .ok()
            .flatten()
            .is_some_and(|contract| contract.time().is_some())
        || !plan
            .field_plan()
            .fields_with_clocks(&scalar.logical, clocks)?
            .iter()
            .any(|(_, contract)| contract.time().is_some())
    {
        return Ok(None);
    }
    Ok(Some(scalar))
}

impl Scalar {
    pub fn target(&self, bytes: &[u8]) -> Result<Value> {
        ensure!(
            bytes.len() <= traffic_contract::MAX_VALUE_BYTES,
            "Redis scalar exceeds the 64 MiB value limit"
        );
        if self.json {
            let value = traffic_contract::json::parse(bytes)
                .context("Target changed the Source JSON scalar encoding")?;
            ensure!(
                !value.is_array() && !value.is_object(),
                "Target scalar changed structure"
            );
            Ok(value)
        } else {
            Ok(Value::String(
                std::str::from_utf8(bytes)
                    .context("Target changed the Source text scalar encoding")?
                    .into(),
            ))
        }
    }

    pub fn encode(&self, value: &Value) -> Result<Vec<u8>> {
        if value == &self.logical {
            return Ok(self.original.clone());
        }
        ensure!(
            std::mem::discriminant(value) == std::mem::discriminant(&self.logical),
            "Redis scalar delivery changed type"
        );
        if self.json {
            Ok(serde_json::to_vec(value)?)
        } else {
            Ok(value
                .as_str()
                .context("Redis text scalar delivery requires a string")?
                .as_bytes()
                .to_vec())
        }
    }
}

pub fn compare(
    metadata: &dyn RuleMetadata,
    source: &[u8],
    target: &[u8],
    field: &GlobalField,
    settings: &TimePolicy,
    clocks: AnchorClocks,
    copies: &[&dyn ValueCopyProof],
) -> Result<Comparison> {
    let Some(source) = decode_field(source, field, metadata.policies())? else {
        ensure!(
            source == target,
            "opaque or structured Redis scalar bytes changed"
        );
        return Ok(Comparison::default());
    };
    let target = source.target(target)?;
    let fields = std::collections::BTreeMap::from([(String::new(), field.clone())]);
    let selected = FieldPlan::new(&fields, settings, metadata.policies())
        .selected_fields_with_clocks(&source.logical, clocks)?;
    if source.logical == target && !field.is_identity() {
        let mut result = Comparison::default();
        result.evaluated.extend(selected.iter().map(|field| {
            if field.rule_id == GLOBAL_JSON_ID {
                GLOBAL_REDIS_ID
            } else {
                field.rule_id
            }
            .to_owned()
        }));
        return Ok(result);
    }
    let fields = selected
        .iter()
        .map(|selected| Field {
            rule_id: if selected.rule_id == GLOBAL_JSON_ID {
                GLOBAL_REDIS_ID
            } else {
                selected.rule_id
            },
            pointer: &selected.pointer,
            contract: &selected.contract,
        })
        .collect::<Vec<_>>();
    Ok(json::compare_all(
        &source.logical,
        &target,
        &fields,
        &[],
        &[],
        clocks,
        copies,
        metadata,
    ))
}
