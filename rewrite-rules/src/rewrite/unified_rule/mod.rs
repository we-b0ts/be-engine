//! Immutable rule preparation, witness validation and bounded discovery.
use crate::policy::{PolicyRule, TrafficPolicy, compile_policy};
use crate::rewrite::model::RewriteState;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};
pub use traffic_rewrite_model::rewrite::unified_rule::UnifiedRulePlanRecord;
pub use traffic_rewrite_model::rewrite::unified_rule::source_proof;

pub mod attribution;
pub mod batch;
pub mod change;
pub mod declaration_changes;
pub mod declarations;
pub mod discovery;
pub mod manifest;
pub mod preflight;
pub mod proposal;
pub mod proposal_context;

pub fn parse_proposal(input: &str) -> Result<TrafficPolicy> {
    let value: serde_yaml::Value = serde_yaml::from_str(input)
        .context("expected a rule, rule list, or traffic-policy/v3 document")?;
    let document = if value.get("rules").is_some()
        || value.get("format").is_some()
        || value.get("time").is_some()
        || value.get("json").is_some()
        || value.get("mysql").is_some()
        || value.get("redis").is_some()
        || value.get("http").is_some()
        || value.get("recording").is_some()
        || value.get("async_api").is_some()
    {
        serde_yaml::from_value::<TrafficPolicy>(value)
            .context("invalid traffic-policy/v3 proposal")?
    } else {
        let rules = if value.is_sequence() {
            serde_yaml::from_value::<Vec<PolicyRule>>(value)
                .context("invalid rule list proposal")?
        } else {
            vec![
                serde_yaml::from_value::<PolicyRule>(value)
                    .context("invalid self-contained rule proposal")?,
            ]
        };
        TrafficPolicy {
            format: crate::policy::POLICY_FORMAT.into(),
            source_revision: None,
            rules,
            ..Default::default()
        }
    };
    compile_policy(&document)?;
    Ok(document)
}

pub mod impact;

pub mod ownership;
pub mod planning;
pub mod record;

#[cfg(test)]
mod source_proof_tests;
