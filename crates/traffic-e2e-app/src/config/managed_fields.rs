use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_yaml::{Mapping, Value};

pub(super) fn reject_inline(path: &Path, raw: &str) -> Result<()> {
    let document: Value = serde_yaml::from_str(raw)
        .with_context(|| format!("failed to parse config {}", path.display()))?;
    let root = document
        .as_mapping()
        .with_context(|| format!("config {} must be a YAML mapping", path.display()))?;
    let recorder = value(root, "recorder")
        .and_then(Value::as_mapping)
        .unwrap_or(root);

    reject_key(
        recorder,
        "process_owned_dependencies",
        "process_owned_dependencies",
    )?;
    if let Some(recording) = value(recorder, "recording").and_then(Value::as_mapping) {
        reject_key(
            recording,
            "process_owned_dependencies",
            "recording.process_owned_dependencies",
        )?;
    }
    reject_key(recorder, "async_api", "async_api")?;
    reject_http_fields(recorder)?;
    reject_breeze_fields(recorder)
}

fn reject_http_fields(recorder: &Mapping) -> Result<()> {
    let Some(http_gateway) = value(recorder, "http_gateway").and_then(Value::as_mapping) else {
        return Ok(());
    };
    for field in ["case_path_patterns", "allowed_unused_http_hosts"] {
        reject_key(http_gateway, field, &format!("http_gateway.{field}"))?;
    }
    for collection in ["rules", "exclude_rules"] {
        let Some(entries) = value(http_gateway, collection).and_then(Value::as_sequence) else {
            continue;
        };
        for (index, entry) in entries.iter().enumerate() {
            let Some(entry) = entry.as_mapping() else {
                continue;
            };
            for field in ["case_path_patterns", "allowed_unused_http_hosts"] {
                reject_key(
                    entry,
                    field,
                    &format!("http_gateway.{collection}[{index}].{field}"),
                )?;
            }
        }
    }
    Ok(())
}

fn reject_breeze_fields(recorder: &Mapping) -> Result<()> {
    let Some(strategies) = value(recorder, "dns_mock")
        .and_then(Value::as_mapping)
        .and_then(|dns| value(dns, "bypass_strategies"))
        .and_then(Value::as_sequence)
    else {
        return Ok(());
    };
    for (index, strategy) in strategies.iter().enumerate() {
        let Some(strategy) = strategy.as_mapping() else {
            continue;
        };
        reject_key(
            strategy,
            "capture_resources",
            &format!("dns_mock.bypass_strategies[{index}].capture_resources"),
        )?;
    }
    Ok(())
}

fn value<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_string()))
}

fn reject_key(mapping: &Mapping, key: &str, qualified: &str) -> Result<()> {
    ensure!(
        !mapping.contains_key(Value::String(key.to_string())),
        "{qualified} is coordinator-managed and must be declared as a Source effect in project.policy"
    );
    Ok(())
}
