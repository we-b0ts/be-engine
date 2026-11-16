//! Source-selected scalar decoding and comparison, shared by physical carriers.
use crate::{
    ExecutionContext,
    fields::{FieldPlan, GLOBAL_JSON_ID, GlobalField, TimePolicy},
    formats::FormatHost,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::sync::Arc;
use traffic_contract::compare::{
    self as comparison, AnchorClocks, Comparison, Field, ValueCopyProof,
};
use traffic_value::codec::{CodecRegistry, PreparedCodec, ValueDocument};

#[derive(Clone, Debug)]
pub struct ScalarDecoder(PreparedCodec);

impl ScalarDecoder {
    pub fn decode(&self, bytes: &[u8]) -> Result<Value> {
        ensure!(
            bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "scalar exceeds the 64 MiB value limit"
        );
        let document = self
            .0
            .decode(bytes)
            .context("Target changed the Source scalar encoding")?;
        scalar_value(document.value()).context("Target scalar changed structure")
    }
}

#[derive(Clone)]
pub struct Scalar {
    pub logical: Value,
    decoder: ScalarDecoder,
    document: Arc<dyn ValueDocument>,
}

impl std::fmt::Debug for Scalar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scalar")
            .field("decoder", &self.decoder)
            .finish_non_exhaustive()
    }
}

fn scalar_value(value: &traffic_value::Value) -> Option<Value> {
    match value {
        traffic_value::Value::Null
        | traffic_value::Value::Bool(_)
        | traffic_value::Value::Number(_)
        | traffic_value::Value::String(_) => serde_json::to_value(value).ok(),
        _ => None,
    }
}

pub fn decode(source: &[u8], codecs: &CodecRegistry) -> Result<Option<Scalar>> {
    ensure!(
        source.len() <= traffic_value::MAX_VALUE_BYTES,
        "scalar exceeds the 64 MiB value limit"
    );
    let Some(codec) = codecs.try_recognize(source, &traffic_value::Value::Null)? else {
        return Ok(None);
    };
    decode_with(codec, source)
}

fn decode_with(codec: PreparedCodec, source: &[u8]) -> Result<Option<Scalar>> {
    let document = codec.decode(source)?;
    Ok(scalar_value(document.value()).map(|logical| Scalar {
        logical,
        decoder: ScalarDecoder(codec),
        document,
    }))
}

/// A declared native string identity can select literal text from a numeric spelling.
pub fn decode_field(
    source: &[u8],
    field: &GlobalField,
    context: &ExecutionContext<'_>,
) -> Result<Option<Scalar>> {
    let Some(mut scalar) = decode(source, context.codecs)? else {
        return Ok(None);
    };
    let policies = context.metadata.policies();
    if scalar.logical.is_number()
        && field.is_identity()
        && !matches!(
            field.select_contract_with_registry(&scalar.logical, None, policies),
            Ok(traffic_contract::rule::FieldContract::Identity { .. })
        )
    {
        let text = context
            .codecs
            .prepare("string", &traffic_value::Value::Null)?;
        let text =
            decode_with(text, source)?.context("native string codec did not produce a scalar")?;
        if matches!(
            field.select_contract_with_registry(&text.logical, None, policies),
            Ok(traffic_contract::rule::FieldContract::Identity { .. })
        ) {
            scalar = text;
        }
    }
    Ok(Some(scalar))
}

/// Inferred native text contracts use the installed policies' Source applicability.
pub fn decode_inferred(
    source: &[u8],
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
    codecs: &CodecRegistry,
) -> Result<Option<Scalar>> {
    let Some(scalar) = decode(source, codecs)? else {
        return Ok(None);
    };
    if !scalar.is_literal_text()
        || plan
            .field_plan()
            .inferred_contract(&scalar.logical)?
            .is_none()
        || plan
            .field_plan()
            .fields_with_clocks(&scalar.logical, clocks)?
            .is_empty()
    {
        return Ok(None);
    }
    Ok(Some(scalar))
}

impl Scalar {
    pub fn is_literal_text(&self) -> bool {
        self.logical
            .as_str()
            .is_some_and(|text| text.as_bytes() == self.document.original_bytes())
    }

    pub fn decoder(&self) -> ScalarDecoder {
        self.decoder.clone()
    }

    pub fn target(&self, bytes: &[u8]) -> Result<Value> {
        self.decoder.decode(bytes)
    }

    pub fn encode(&self, value: &Value) -> Result<Vec<u8>> {
        if value == &self.logical {
            return Ok(self.document.original_bytes().into());
        }
        ensure!(
            std::mem::discriminant(value) == std::mem::discriminant(&self.logical),
            "scalar delivery changed type"
        );
        let bytes = self.document.encode(
            &traffic_contract::codec::restore_projection(self.document.value(), value)?,
            &[String::new()],
        )?;
        ensure!(
            bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "derived scalar exceeds the 64 MiB value limit"
        );
        Ok(bytes)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn compare(
    context: &ExecutionContext<'_>,
    rule_id: &str,
    source: &[u8],
    target: &[u8],
    field: &GlobalField,
    settings: &TimePolicy,
    clocks: AnchorClocks,
    copies: &[&dyn ValueCopyProof],
) -> Result<Comparison> {
    let Some(source) = decode_field(source, field, context)? else {
        ensure!(
            source == target,
            "opaque or structured scalar bytes changed"
        );
        return Ok(Comparison::default());
    };
    let target = source.target(target)?;
    let fields = std::collections::BTreeMap::from([(String::new(), field.clone())]);
    let selected = FieldPlan::new(&fields, settings, context.metadata.policies())
        .selected_fields_with_clocks(&source.logical, clocks)?;
    let effective_id = |id| if id == GLOBAL_JSON_ID { rule_id } else { id };
    let fields = selected
        .iter()
        .map(|selected| Field {
            rule_id: effective_id(selected.rule_id),
            pointer: &selected.pointer,
            contract: &selected.contract,
        })
        .collect::<Vec<_>>();
    Ok(comparison::compare_all(
        &source.logical,
        &target,
        &fields,
        &[],
        &[],
        clocks,
        copies,
        context.metadata,
    ))
}

#[cfg(test)]
mod tests;
