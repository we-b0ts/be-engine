//! Integrated authoring regressions use application-composed registries and admission.
use crate::policy::native::*;
use crate::policy::*;
use anyhow::Result;
use serde_yaml::{Mapping, Value};
use std::collections::BTreeMap;
pub use traffic_policy_document::authoring::http::*;
fn expand(
    value: Option<HttpDocument>,
    resources: &BTreeMap<String, ResourceDeclaration>,
) -> Result<(Option<HttpPolicy>, Vec<Value>)> {
    let (headers, rules) =
        traffic_policy_document::authoring::http::expand(value, resources, &super::context())?;
    Ok((
        headers.map(|value| HttpPolicy {
            headers: value.headers,
            request_metadata: value.request_metadata,
            request_sigv4: value.request_sigv4,
        }),
        rules,
    ))
}
fn compact(
    rule: &PolicyRule,
    resources: &BTreeMap<String, ResourceDeclaration>,
    output: &mut Mapping,
) -> Result<bool> {
    traffic_policy_document::authoring::http::compact(rule, resources, output, &super::context())
}

mod tests;
