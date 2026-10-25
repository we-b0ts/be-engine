//! Selected response header copies share body formats and staged identities.
use super::*;
use crate::value_contract::http_headers::{self, HeaderSnapshot};

pub(super) fn materialize(
    owner: &crate::replay::policy::request_contract::RequestContracts,
    case: &str,
    source: Option<&HeaderSnapshot>,
    target: &mut hyper::HeaderMap,
    clocks: AnchorClocks,
    delivered_at: chrono::DateTime<Utc>,
) -> Result<Option<crate::replay::policy::request_contract::Decision>> {
    let Some(policy) = owner
        .compiled_rules()
        .and_then(|policy| policy.http.as_ref())
    else {
        return Ok(None);
    };
    let source = http_headers::canonical(&source.cloned().unwrap_or_default())?;
    let mut fields = std::collections::BTreeMap::new();
    let mut values = serde_json::Map::new();
    for (name, field) in &policy.headers {
        if let Some(captured) = source.get(name) {
            for (index, value) in captured.iter().enumerate() {
                if matches!(
                    value.as_str(),
                    "<redacted>" | "<encrypted>" | "<unavailable>"
                ) || value.starts_with("traffic-e2e:enc:v1:")
                {
                    continue;
                }
                fields.insert(
                    format!("/{}/{index}", name.replace('~', "~0").replace('/', "~1")),
                    field.clone(),
                );
            }
            values.insert(
                name.clone(),
                Value::Array(
                    captured
                        .iter()
                        .map(|value| http_headers::scalar(value, field))
                        .collect(),
                ),
            );
        }
    }
    let plan = crate::policy::JsonPolicy { fields }.compile()?;
    let delivery = crate::replay::contract_value::Delivery::prepare_global(
        &serde_json::to_vec(&values)?,
        &plan,
        clocks,
    )?;
    let (rendered, identity) = delivery.render_with_identities(delivered_at, owner, case)?;
    let rendered: std::collections::BTreeMap<String, Vec<Value>> =
        serde_json::from_slice(&rendered)?;
    for (name, values) in rendered {
        let name = hyper::header::HeaderName::from_bytes(name.as_bytes())?;
        target.remove(&name);
        for value in values {
            let value = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            target.append(name.clone(), hyper::header::HeaderValue::from_str(&value)?);
        }
    }
    let comparison =
        http_headers::compare(&source, &request_headers::capture(target), policy, clocks)?;
    anyhow::ensure!(comparison.passed(), "derived HTTP header formats differ");
    let mut decision =
        crate::replay::policy::request_contract::Decision::from_value_comparison(comparison);
    decision.identity = Some(identity);
    Ok(Some(decision))
}

/// Validate the native framing against its normal rendered headers, while the
/// original Target header values remain in the protected delivery witness.
pub(super) fn native_validation_target(
    target: &Value,
    native: &HeaderSnapshot,
    owner: &crate::replay::policy::request_contract::RequestContracts,
) -> Result<Value> {
    let mut validation = target.clone();
    if let Some(policy) = owner
        .compiled_rules()
        .and_then(|policy| policy.http.as_ref())
    {
        let actual: HeaderSnapshot = serde_json::from_value(target["response_headers"].clone())?;
        validation["response_headers"] =
            serde_json::to_value(http_headers::mask(native, &actual, policy)?)?;
    }
    Ok(validation)
}
