use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use url::form_urlencoded;

use super::RewriteInput;

mod cache_config;
mod naming;

pub(super) use cache_config::{CacheConfig, ResponsePlan as CacheConfigResponsePlan};
pub(super) use naming::{Naming, ResponsePlan as NamingResponsePlan};

fn query(input: &RewriteInput<'_>) -> BTreeMap<String, String> {
    form_urlencoded::parse(input.uri.query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

fn required_query<'a>(query: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    query
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Vintage request has no {name} query parameter"))
}

fn parse_outer(body: &[u8]) -> Result<Value> {
    let outer: Value =
        serde_json::from_slice(body).context("Vintage response body is not valid JSON")?;
    if !outer.is_object() {
        bail!("Vintage response root is not an object");
    }
    Ok(outer)
}

fn application_error_code(outer: &Value) -> Result<Option<String>> {
    match outer.get("code") {
        Some(Value::String(code)) if code == "200" => Ok(None),
        Some(Value::Number(code)) if code.as_u64() == Some(200) => Ok(None),
        Some(Value::String(code)) if !code.is_empty() => Ok(Some(code.clone())),
        Some(Value::Number(code)) => Ok(Some(code.to_string())),
        Some(_) => bail!("Vintage response application code is not a string or number"),
        None => bail!("Vintage response has no application code"),
    }
}

fn alias_for_ip(ip: Ipv4Addr) -> String {
    format!("fake-node-{}.trp.test", ip.to_string().replace('.', "-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_identify_fake_nodes_without_claiming_vintage_ownership() {
        assert_eq!(
            alias_for_ip(Ipv4Addr::new(10, 2, 29, 229)),
            "fake-node-10-2-29-229.trp.test"
        );
    }
}
