//! Bind selected native header occurrences to the installed field services.
use super::json::{AnchorClocks, Comparison};
use crate::policy::HttpPolicy;
use anyhow::Result;
pub(crate) use native::{HeaderSnapshot, canonical, scalar};
use traffic_protocol_http::header_values as native;
pub(crate) fn compare(
    source: &HeaderSnapshot,
    target: &HeaderSnapshot,
    policy: &HttpPolicy,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    native::compare(
        &super::json::PolicyMetadata,
        source,
        target,
        &policy.headers,
        clocks,
    )
}
pub(crate) fn mask(
    source: &HeaderSnapshot,
    target: &HeaderSnapshot,
    policy: &HttpPolicy,
) -> Result<HeaderSnapshot> {
    native::mask(source, target, &policy.headers)
}
#[cfg(test)]
use crate::policy::{GLOBAL_HTTP_ID, JsonPolicy};
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
mod tests;
