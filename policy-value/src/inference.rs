//! Bounded Source selection using registered policy-owned inference.
use std::fmt::Write;

use anyhow::{Result, ensure};
use traffic_contract::rule::FieldContract;
use traffic_policy::{PolicyInference, PolicyRegistry};
use traffic_value::{Value, path};

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
    let mut pointer = String::new();
    let complete = visit(
        registry,
        source,
        facts,
        &mut pointer,
        0,
        &mut remaining,
        &mut output,
    )?;
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
    pointer: &mut String,
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
            pointer: pointer.clone(),
            rule_id,
            contract: contract(inferred)?,
        });
        return Ok(true);
    }
    let prefix_len = pointer.len();
    match source {
        Value::Object(values) => {
            for (key, value) in values {
                if key == "\0protobuf" {
                    continue;
                }
                path::push_segment(pointer, key);
                let complete = visit(
                    registry,
                    value,
                    facts,
                    pointer,
                    depth + 1,
                    remaining,
                    output,
                )?;
                pointer.truncate(prefix_len);
                if !complete {
                    return Ok(false);
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                write!(pointer, "/{index}").expect("writing to a String cannot fail");
                let complete = visit(
                    registry,
                    value,
                    facts,
                    pointer,
                    depth + 1,
                    remaining,
                    output,
                )?;
                pointer.truncate(prefix_len);
                if !complete {
                    return Ok(false);
                }
            }
        }
        _ => (),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inferred_pointers_preserve_escaped_keys_and_sibling_paths() {
        let source: Value = serde_json::from_str(
            r#"{"a/~":[{"time":"2026-01-01"},"2026-01-02"],"z":"2026-01-03"}"#,
        )
        .unwrap();
        let selected = fields(traffic_extensions::policies(), &source, &Value::Null).unwrap();
        let pointers = selected
            .iter()
            .map(|field| field.pointer.as_str())
            .collect::<Vec<_>>();
        assert_eq!(pointers, ["/a~1~0/0/time", "/a~1~0/1", "/z"]);
    }
}
