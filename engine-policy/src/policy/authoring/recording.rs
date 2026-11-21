//! Integrated authoring regressions use application-composed registries and admission.
use crate::policy::native::*;
use crate::policy::*;
use anyhow::Result;
use serde_yaml::{Mapping, Value};
pub use traffic_policy_document::authoring::recording::*;
fn expand(value: Option<Declaration>, revision: Option<&str>) -> Result<Vec<Value>> {
    traffic_policy_document::authoring::recording::expand(value, revision, &super::context())
}
fn compact(rule: &PolicyRule, revision: Option<&str>, output: &mut Mapping) -> Result<bool> {
    traffic_policy_document::authoring::recording::compact(
        rule,
        revision,
        output,
        &super::context(),
    )
}

mod async_api_tests;
mod tests;
