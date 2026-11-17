//! Integrated authoring regressions use application-composed registries and admission.
use crate::policy::native::*;
use crate::policy::*;
use anyhow::Result;
use serde_yaml::{Mapping, Value};
use std::collections::BTreeMap;
pub use traffic_policy_document::authoring::signatures::*;
fn expand(
    value: Option<ApiDefinitions>,
    definitions: &BTreeMap<String, SignatureDefinition>,
) -> Result<Vec<Value>> {
    traffic_policy_document::authoring::signatures::expand(value, definitions, &super::context())
}
fn compact(
    rule: &PolicyRule,
    definitions: &BTreeMap<String, SignatureDefinition>,
    output: &mut Mapping,
) -> Result<bool> {
    traffic_policy_document::authoring::signatures::compact(
        rule,
        definitions,
        output,
        &super::context(),
    )
}

mod tests;
