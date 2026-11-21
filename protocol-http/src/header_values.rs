//! Selected HTTP header occurrences reuse the global scalar comparison kernel.
use traffic_contract::compare::{AnchorClocks, Comparison, Field, RuleMetadata};
use traffic_contract::rule::TimestampFormat;
use traffic_policy_value::fields::{FieldPlan, GLOBAL_JSON_ID, GlobalField, TimePolicy};
pub const GLOBAL_HTTP_ID: &str = "global.http";
use anyhow::{Result, ensure};
use serde_json::Value;
use std::collections::BTreeMap;
pub type HeaderSnapshot = BTreeMap<String, Vec<String>>;

pub fn canonical(headers: &HeaderSnapshot) -> Result<HeaderSnapshot> {
    let mut result = BTreeMap::new();
    for (name, values) in headers {
        let name = hyper::header::HeaderName::from_bytes(name.as_bytes())?
            .as_str()
            .to_owned();
        ensure!(
            result.insert(name, values.clone()).is_none(),
            "ambiguous case-variant HTTP header capture"
        );
    }
    Ok(result)
}

pub fn compare(
    metadata: &dyn RuleMetadata,
    source: &HeaderSnapshot,
    target: &HeaderSnapshot,
    declarations: &BTreeMap<String, GlobalField>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let source = canonical(source)?;
    let target = canonical(target)?;
    let mut before = serde_json::Map::new();
    let mut after = serde_json::Map::new();
    let mut fields = BTreeMap::new();
    for (name, field) in declarations {
        let name = name.to_ascii_lowercase();
        let pointer = format!("/{}/{}", name.replace('~', "~0").replace('/', "~1"), "*");
        fields.insert(pointer, field.clone());
        let values = source.get(&name);
        if let Some(values) = values {
            before.insert(
                name.clone(),
                Value::Array(values.iter().map(|value| scalar(value, field)).collect()),
            );
        }
        if let Some(values) = target.get(&name) {
            after.insert(
                name.clone(),
                Value::Array(
                    values
                        .iter()
                        .enumerate()
                        .map(|(index, value)| {
                            if source
                                .get(&name)
                                .and_then(|values| values.get(index))
                                .is_some_and(|source| numeric_source(source, field))
                            {
                                serde_json::from_str::<Value>(value)
                                    .ok()
                                    .filter(Value::is_number)
                                    .unwrap_or_else(|| Value::String(value.clone()))
                            } else {
                                Value::String(value.clone())
                            }
                        })
                        .collect(),
                ),
            );
        }
    }
    let before = Value::Object(before);
    let after = Value::Object(after);
    let settings = TimePolicy::default();
    traffic_policy_value::fields::validate_fields(&fields, &settings, metadata.policies())?;
    let plan = FieldPlan::new(&fields, &settings, metadata.policies());
    let mut selected = plan.comparison_fields(&before, &after, clocks)?;
    // Capture placeholders are not observed identities or format evidence.
    // Without a selected contract the same leaf retains exact comparison.
    selected.retain(|(pointer, _)| {
        !before
            .pointer(pointer)
            .and_then(Value::as_str)
            .is_some_and(|value| {
                matches!(value, "<redacted>" | "<encrypted>" | "<unavailable>")
                    || value.starts_with("traffic-e2e:enc:v1:")
            })
    });
    for (pointer, contract) in &mut selected {
        if let traffic_contract::rule::FieldContract::Time { clock_group, .. } = contract {
            let digest = traffic_contract::fingerprint::digest(
                "traffic-policy/http-header-clock/v1",
                pointer,
            )?;
            *clock_group = Some(format!("schema.{}", &digest[7..39]));
        }
    }
    let selected = selected
        .iter()
        .map(|(pointer, contract)| Field {
            rule_id: GLOBAL_HTTP_ID,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    let mut comparison = traffic_contract::compare::compare_all(
        &before,
        &after,
        &selected,
        &[],
        &[],
        clocks,
        &[],
        metadata,
    );
    // Missing header additions/deletions and empty captures do not need a
    // selected leaf to remain strict, and do not create positive coverage.
    comparison.evaluated.remove(GLOBAL_JSON_ID);
    Ok(comparison)
}
fn numeric_source(value: &str, field: &GlobalField) -> bool {
    let numeric = match field {
        GlobalField::Time { formats } => formats.iter().any(|format| {
            matches!(
                format.format,
                TimestampFormat::UnixSeconds
                    | TimestampFormat::UnixMilliseconds
                    | TimestampFormat::UnixMicroseconds
            )
        }),
        GlobalField::Duration { .. } => true,
        _ => false,
    };
    numeric && serde_json::from_str::<Value>(value).is_ok_and(|value| value.is_number())
}
pub fn scalar(value: &str, field: &GlobalField) -> Value {
    if numeric_source(value, field) {
        serde_json::from_str(value).expect("checked numeric header")
    } else {
        Value::String(value.into())
    }
}

/// Call after successful comparison. Only declared values are masked for the
/// remaining native header owner; all other Target values stay available.
pub fn mask(
    source: &HeaderSnapshot,
    target: &HeaderSnapshot,
    declarations: &BTreeMap<String, GlobalField>,
) -> Result<HeaderSnapshot> {
    let source = canonical(source)?;
    let mut target = canonical(target)?;
    for name in declarations.keys() {
        let name = name.to_ascii_lowercase();
        if let Some(values) = source.get(&name) {
            target.insert(name, values.clone());
        } else {
            target.remove(&name);
        }
    }
    Ok(target)
}
