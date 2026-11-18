//! Bounded Source selection using registered policy-owned inference.
use anyhow::{Result, ensure};
use traffic_contract::rule::FieldContract;
use traffic_policy::{PolicyInference, PolicyRegistry};
use traffic_value::Value;

const MAX_NODES: usize = 16_384;
const MAX_DEPTH: usize = 128;
const MAX_FIELDS: usize = 4096;

pub struct InferredField {
    pub pointer: String,
    pub rule_id: &'static str,
    pub contract: FieldContract,
}

pub fn contract(inferred: PolicyInference) -> Result<FieldContract> {
    let Some(declaration) = inferred.declaration else {
        return Ok(FieldContract::Policy(inferred.definition));
    };
    let contract: FieldContract = serde_json::from_value(serde_json::to_value(declaration)?)?;
    ensure!(
        contract.registered_definition(true).as_ref() == Some(&inferred.definition),
        "inferred declaration differs from its registered policy definition"
    );
    Ok(contract)
}

pub fn fields(
    registry: &PolicyRegistry,
    source: &Value,
    facts: &Value,
) -> Result<Vec<InferredField>> {
    let mut output = Vec::new();
    let mut remaining = MAX_NODES;
    let complete = visit(registry, source, facts, "", 0, &mut remaining, &mut output)?;
    ensure!(
        complete || output.is_empty(),
        "policy inference exceeds its bounded Source inventory"
    );
    Ok(output)
}

fn visit(
    registry: &PolicyRegistry,
    source: &Value,
    facts: &Value,
    pointer: &str,
    depth: usize,
    remaining: &mut usize,
    output: &mut Vec<InferredField>,
) -> Result<bool> {
    let inferred = registry.infer(source, facts)?;
    if inferred.is_none() && !matches!(source, Value::Object(_) | Value::Array(_)) {
        return Ok(true);
    }
    if depth > MAX_DEPTH || *remaining == 0 {
        return Ok(false);
    }
    *remaining -= 1;
    if let Some(inferred) = inferred {
        ensure!(
            output.len() < MAX_FIELDS,
            "inferred value-field inventory exceeds its bound"
        );
        let rule_id = inferred.rule_id;
        output.push(InferredField {
            pointer: pointer.into(),
            rule_id,
            contract: contract(inferred)?,
        });
        return Ok(true);
    }
    match source {
        Value::Object(values) => {
            for (key, value) in values {
                if key == "\0protobuf" {
                    continue;
                }
                let key = traffic_value::path::escape(key);
                if !visit(
                    registry,
                    value,
                    facts,
                    &format!("{pointer}/{key}"),
                    depth + 1,
                    remaining,
                    output,
                )? {
                    return Ok(false);
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if !visit(
                    registry,
                    value,
                    facts,
                    &format!("{pointer}/{index}"),
                    depth + 1,
                    remaining,
                    output,
                )? {
                    return Ok(false);
                }
            }
        }
        _ => (),
    }
    Ok(true)
}
