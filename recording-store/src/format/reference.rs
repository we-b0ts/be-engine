//! Common references reuse the protocol and native identity fields in the row.
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};

pub(super) fn project(
    capture: &mut Map<String, Value>,
    native: &Map<String, Value>,
    protocol: Option<&str>,
) -> Option<&'static str> {
    let reference = capture.get("protocol_ref")?.as_object()?;
    if reference.get("protocol").and_then(Value::as_str) != protocol || protocol.is_none() {
        return None;
    }
    let equal = |fields: &Map<String, Value>, key: &str, native_key: &str| {
        fields
            .get(key)
            .is_some_and(|value| !value.is_null() && native.get(native_key) == Some(value))
    };
    let form = match reference.len() {
        2 if equal(reference, "exchange_id", "id") => "e",
        3 if equal(reference, "connection_id", "connection_id")
            && equal(reference, "sequence", "sequence") =>
        {
            "s"
        }
        3 if equal(reference, "connection_id", "connection_id")
            && equal(reference, "sequence", "query_sequence") =>
        {
            "q"
        }
        3 if equal(reference, "exchange_id", "id")
            && reference
                .get("after")
                .and_then(Value::as_object)
                .is_some_and(|after| {
                    after.len() == 3
                        && after.get("protocol") == reference.get("protocol")
                        && equal(after, "connection_id", "connection_id")
                        && equal(after, "sequence", "subscription_sequence")
                }) =>
        {
            "p"
        }
        _ => return None,
    };
    capture.remove("protocol_ref");
    Some(form)
}

pub(super) fn restore(
    capture: &mut Map<String, Value>,
    native: &Map<String, Value>,
    protocol: &str,
    form: &str,
) -> Result<()> {
    let field = |name| {
        native
            .get(name)
            .filter(|value| !value.is_null())
            .with_context(|| format!("missing reference field {name}"))
    };
    let reference = match form {
        "e" => json!({"protocol":protocol,"exchange_id":field("id")?}),
        "s" | "q" => json!({
            "protocol":protocol,"connection_id":field("connection_id")?,
            "sequence":field(if form == "q" { "query_sequence" } else { "sequence" })?
        }),
        "p" => json!({"protocol":protocol,"exchange_id":field("id")?,"after":{
            "protocol":protocol,"connection_id":field("connection_id")?,
            "sequence":field("subscription_sequence")?
        }}),
        _ => anyhow::bail!("invalid dependency reference form {form:?}"),
    };
    ensure!(
        capture.insert("protocol_ref".into(), reference).is_none(),
        "duplicate protocol reference"
    );
    Ok(())
}
