//! Native contextual relationships reuse the strategy owned by a physical field.
//! Traversal is restricted to typed contract sites; business literals are untouched.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde_yaml::{Mapping, Value};

use crate::policy::{
    ColumnDeclaration, FieldContract, FieldReference, FieldReferenceUse, ResourceDeclaration,
};

pub(super) fn expand(
    rule: &mut Value,
    resources: &BTreeMap<String, ResourceDeclaration>,
) -> Result<Vec<FieldReferenceUse>> {
    let mut references = Vec::new();
    sites(rule, &mut |node, path| {
        let node = unwrapped(node);
        let Some(reference) = node.get("field_ref") else {
            return Ok(());
        };
        let reference: FieldReference = serde_yaml::from_value(reference.clone())?;
        let map = node.as_mapping().context("field_ref requires a mapping")?;
        ensure!(
            map.keys()
                .all(|key| matches!(key.as_str(), Some("field_ref" | "clock_group" | "proof"))),
            "field_ref permits only a contextual clock_group and local proof"
        );
        let clock_group = map
            .get("clock_group")
            .map(|group| {
                group
                    .as_str()
                    .map(str::to_owned)
                    .context("clock_group must be a string")
            })
            .transpose()?;
        let usage = FieldReferenceUse {
            path: path.to_vec(),
            reference,
            clock_group,
        };
        replace(node, &usage, resources)?;
        references.push(usage);
        Ok(())
    })?;
    Ok(references)
}

pub(super) fn refresh(
    rule: &mut Value,
    references: &[FieldReferenceUse],
    resources: &BTreeMap<String, ResourceDeclaration>,
) -> Result<()> {
    for reference in references {
        let node = locate(rule, &reference.path)?;
        replace(node, reference, resources)?;
    }
    Ok(())
}

pub(super) fn restore(rule: &mut Value, references: &[FieldReferenceUse]) -> Result<()> {
    for reference in references {
        let node = locate(rule, &reference.path)?;
        let proof = node.as_mapping_mut().and_then(|map| map.remove("proof"));
        let mut value = Mapping::new();
        value.insert(
            "field_ref".into(),
            serde_yaml::to_value(&reference.reference)?,
        );
        if let Some(group) = &reference.clock_group {
            value.insert("clock_group".into(), group.clone().into());
        }
        if let Some(proof) = proof {
            value.insert("proof".into(), proof);
        }
        *node = Value::Mapping(value);
    }
    Ok(())
}

fn replace(
    node: &mut Value,
    usage: &FieldReferenceUse,
    resources: &BTreeMap<String, ResourceDeclaration>,
) -> Result<()> {
    let field = resolve(&usage.reference, resources)?;
    let field = match field {
        FieldContract::Conditional { when, contract }
            if when.relative_pointer == "."
                && matches!(contract.as_ref(), FieldContract::Time { .. }) =>
        {
            contract.as_ref()
        }
        field => field,
    };
    let mut value = serde_yaml::to_value(field)?;
    super::transform_field(&mut value, true)?;
    if let Some(group) = &usage.clock_group {
        ensure!(
            matches!(field, FieldContract::Time { .. }),
            "clock_group override requires a timestamp field"
        );
        value
            .as_mapping_mut()
            .context("timestamp contract requires a mapping")?
            .insert("clock_group".into(), group.clone().into());
    }
    if let Some(proof) = node.as_mapping_mut().and_then(|map| map.remove("proof")) {
        value
            .as_mapping_mut()
            .context("a referenced contract with local proof requires a mapping")?
            .insert("proof".into(), proof);
    }
    *node = value;
    Ok(())
}

fn resolve<'a>(
    reference: &FieldReference,
    resources: &'a BTreeMap<String, ResourceDeclaration>,
) -> Result<&'a FieldContract> {
    let resource = resources
        .get(&reference.resource)
        .with_context(|| format!("unknown field_ref resource {:?}", reference.resource))?;
    match (&reference.table, &reference.column, reference.key) {
        (Some(table), Some(column), None) => {
            let table = resource
                .tables
                .get(table)
                .context("unknown field_ref table declaration")?;
            let field = table
                .fields
                .get(column)
                .context("unknown field_ref column")?;
            match field {
                ColumnDeclaration::Scalar { field, .. } => {
                    ensure!(
                        reference.pointer.as_deref().is_none_or(str::is_empty),
                        "scalar field_ref cannot select a JSON pointer"
                    );
                    Ok(&field.contract)
                }
                ColumnDeclaration::Decoded(payload) => payload
                    .fields
                    .get(reference.pointer.as_deref().unwrap_or(""))
                    .map(|field| &field.contract)
                    .context("unknown field_ref decoded field pointer"),
            }
        }
        (None, None, Some(index)) => resource
            .keys
            .get(index)
            .context("unknown field_ref key declaration index")?
            .value
            .fields
            .get(
                reference
                    .pointer
                    .as_deref()
                    .context("Redis field_ref requires a pointer")?,
            )
            .map(|field| &field.contract)
            .context("unknown field_ref value pointer"),
        _ => anyhow::bail!("field_ref requires table+column or one Redis key index"),
    }
}

fn unwrapped(value: &mut Value) -> &mut Value {
    if value.as_mapping().is_some_and(|map| {
        map.contains_key("contract")
            && map
                .keys()
                .all(|key| matches!(key.as_str(), Some("contract" | "proof")))
    }) {
        value.get_mut("contract").expect("checked")
    } else {
        value
    }
}

fn locate<'a>(mut value: &'a mut Value, path: &[String]) -> Result<&'a mut Value> {
    for segment in path {
        value = unwrapped(value);
        value = if value.is_sequence() {
            value
                .as_sequence_mut()
                .expect("checked")
                .get_mut(segment.parse::<usize>()?)
        } else {
            let map = value
                .as_mapping_mut()
                .context("field_ref path no longer selects a mapping")?;
            let key = Value::String(segment.clone());
            if map.contains_key(&key) {
                map.get_mut(&key)
            } else {
                segment
                    .parse::<u64>()
                    .ok()
                    .and_then(|index| map.get_mut(Value::Number(index.into())))
            }
        }
        .context("field_ref path no longer exists; edit the declared relationship explicitly")?;
    }
    Ok(unwrapped(value))
}

type Visit<'a> = dyn FnMut(&mut Value, &[String]) -> Result<()> + 'a;

fn map_sites(
    value: &mut Value,
    key: &str,
    path: &[String],
    visit: &mut Visit<'_>,
    json_children: bool,
) -> Result<()> {
    let Some(fields) = value.get_mut(key) else {
        return Ok(());
    };
    let fields = fields
        .as_mapping_mut()
        .with_context(|| format!("{key} requires a contract map"))?;
    for (name, node) in fields {
        let name = match name {
            Value::String(name) => name.clone(),
            Value::Number(index) => index.to_string(),
            _ => anyhow::bail!("contract selector must be a string or index"),
        };
        let mut path = path.to_vec();
        path.push(key.into());
        path.push(name);
        visit(node, &path)?;
        if json_children {
            let node = unwrapped(node);
            map_sites(node, "fields", &path, visit, false)?;
        }
    }
    Ok(())
}

fn sites(rule: &mut Value, visit: &mut Visit<'_>) -> Result<()> {
    let Some(effect) = rule.get_mut("effect") else {
        return Ok(());
    };
    let root = vec!["effect".into()];
    match effect.get("kind").and_then(Value::as_str).unwrap_or("") {
        "mysql_values" => {
            map_sites(effect, "values", &root, visit, true)?;
            if let Some(fields) = effect
                .get_mut("response_time")
                .and_then(Value::as_mapping_mut)
            {
                for (column, node) in fields {
                    let column = column
                        .as_str()
                        .context("response column must be a string")?;
                    if let Some(time) = unwrapped(node).get_mut("time") {
                        visit(
                            time,
                            &[
                                "effect".into(),
                                "response_time".into(),
                                column.into(),
                                "time".into(),
                            ],
                        )?;
                    }
                }
            }
        }
        "redis_sequence" => {
            if let Some(commands) = effect.get_mut("commands").and_then(Value::as_sequence_mut) {
                for (index, command) in commands.iter_mut().enumerate() {
                    map_sites(
                        command,
                        "arguments",
                        &["effect".into(), "commands".into(), index.to_string()],
                        visit,
                        true,
                    )?;
                }
            }
        }
        "finite_sharing" => map_sites(effect, "response_time", &root, visit, false)?,
        _ => (),
    }
    Ok(())
}
