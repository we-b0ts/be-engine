//! Validate complete Source scope and independently observed Target payloads.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::manifest::Bundle;
use crate::{
    policy::{CompiledPolicy, NativeEffect, Protocol, Surface},
    policy_evidence::{TargetRole, WitnessManifest},
    rewrite::model::RewriteState,
    value_contract::json::AnchorClocks,
};

mod api;
mod async_api;
mod candidate_pairs;
pub(super) mod dependency;
mod global_values;
mod identities;
mod input_retiming;
mod payload;
mod resource;
mod response;
mod session;
mod source;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Preflight {
    pub capture_scopes: BTreeMap<String, String>,
    pub source_validations: usize,
    pub independent_target_validations: usize,
    pub derived_delivery_validations: usize,
    pub missing_target_witnesses: usize,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub target_comparison_failures: BTreeSet<TargetComparisonFailure>,
    #[serde(default)]
    pub unvalidated_target_witnesses: BTreeSet<response::UnvalidatedTargetWitness>,
    #[serde(default)]
    pub unvalidated_retimed_witnesses: BTreeSet<input_retiming::UnvalidatedWitness>,
    #[serde(default)]
    pub unavailable_source_values: usize,
    pub rules: BTreeMap<String, usize>,
    #[serde(default)]
    pub obligations: BTreeSet<crate::config::native_policy::SourceObligation>,
    #[serde(default)]
    pub pending_effect_evidence: BTreeSet<String>,
    #[serde(default)]
    pub stateful_target_obligations: BTreeSet<String>,
    #[serde(default)]
    source_scope: Option<source::SourceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource_scope: Option<resource::ResourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TargetComparisonFailure {
    case_id: String,
    surface: Surface,
    witness_id: Option<String>,
}

impl Preflight {
    fn defer_target_comparison(&mut self, case: &str, surface: Surface, witness: Option<&str>) {
        self.target_comparison_failures
            .insert(TargetComparisonFailure {
                case_id: case.into(),
                surface,
                witness_id: witness.map(str::to_owned),
            });
    }

    pub(super) fn status(&self) -> &'static str {
        if self.needs_recording() {
            "planned_needs_recording"
        } else if self.missing_target_witnesses > 0
            || !self.target_comparison_failures.is_empty()
            || !self.unvalidated_target_witnesses.is_empty()
            || !self.unvalidated_retimed_witnesses.is_empty()
            || !self.stateful_target_obligations.is_empty()
        {
            "planned_needs_replay"
        } else {
            "preflight_validated_requires_replay"
        }
    }

    pub(super) fn needs_recording(&self) -> bool {
        !self.capture_scopes.is_empty() || source::needs_recording(&self.obligations)
    }

    pub(super) fn ensure_current(
        &self,
        root: &Path,
        policy: &CompiledPolicy,
        validation: Option<std::time::SystemTime>,
    ) -> Result<()> {
        if let Some(record) = &self.source_scope {
            record.ensure_current(root, policy, validation)?;
        }
        if let Some(record) = &self.resource_scope {
            record.ensure_current(root, validation)?;
        }
        Ok(())
    }
}

pub(super) fn verify(
    root: &Path,
    state: &RewriteState,
    bundle: &mut Bundle,
    previous: &CompiledPolicy,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
) -> Result<Preflight> {
    source::validate_project(root, policy)?;
    if let Some(global) = &policy.global_json {
        global.signatures.prepare(root)?;
        for key in global.signatures.resolved_keys() {
            for (path, digest) in key.witnesses() {
                bundle.freeze(path)?;
                ensure!(
                    bundle.artifacts[path].sha256 == *digest,
                    "JWT startup input changed while freezing plan evidence"
                );
            }
            key.ensure_current()?;
        }
    }
    let mut result = Preflight::default();
    let pending_recording = state.recording_refresh.is_some();
    if pending_recording {
        result
            .obligations
            .insert(crate::config::native_policy::SourceObligation::FreshRecording);
    }
    identities::require_replay(policy, selected, &mut result);
    source::verify(root, state, bundle, previous, policy, selected, &mut result)?;
    let mut validation_ids = selected.clone();
    if previous.global_json != policy.global_json {
        // Built-in interpretation changes still validate complete Source/Target
        // evidence, but never become authored permissions or Source proofs.
        validation_ids.insert(crate::value_contract::time::automatic::RULE_ID.into());
    }
    let (scope, mut foreign) = resource::prepare(root, state, bundle, policy, &validation_ids)?;
    global_values::verify(root, bundle, previous, policy, &validation_ids, &mut result)?;
    global_values::global_trace(state, bundle, policy, &validation_ids, &mut result)?;
    payload::verify(root, bundle, policy, selected, &mut result)?;
    let resource_ids = resource::selected(policy, &validation_ids);
    for other in &mut foreign {
        global_values::verify(root, other, previous, policy, &resource_ids, &mut result)?;
        payload::verify(root, other, policy, &resource_ids, &mut result)?;
        bundle.cases.append(&mut other.cases);
        bundle.artifacts.append(&mut other.artifacts);
    }
    result.resource_scope = scope;
    async_api::verify(
        state,
        bundle,
        policy,
        selected,
        pending_recording || previous.async_api != policy.async_api,
        &mut result,
    )?;

    session::verify(root, bundle, policy, selected, &mut result)?;
    for id in selected {
        let cleared_global = id == crate::policy::GLOBAL_JSON_ID
            && policy
                .global_json
                .as_ref()
                .is_some_and(|json| json.fields.is_empty())
            || id == "global.mysql"
                && policy
                    .mysql
                    .as_ref()
                    .is_some_and(|mysql| mysql.tables.is_empty())
            || id == "global.redis"
                && policy
                    .redis
                    .as_ref()
                    .is_some_and(|redis| redis.keys.is_empty())
            || id == crate::policy::GLOBAL_HTTP_ID
                && policy
                    .http
                    .as_ref()
                    .is_some_and(|http| http.headers.is_empty())
            || id == crate::policy::ASYNC_API_ID && policy.async_api.is_empty();
        ensure!(
            result.rules.get(id).is_some_and(|n| *n > 0) || cleared_global,
            "rule {id:?} selects no complete Source witness in this attempt"
        );
    }
    Ok(result)
}

/// This path authorizes ownership declarations before any Target execution.
/// Its proposal/change allowlist excludes value, sharing and delivery effects.
pub(super) fn verify_attribution(
    root: &Path,
    state: &RewriteState,
    bundle: &mut Bundle,
    previous: &CompiledPolicy,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
) -> Result<Preflight> {
    source::validate_project(root, policy)?;
    let mut result = Preflight::default();
    source::verify(root, state, bundle, previous, policy, selected, &mut result)?;
    async_api::verify(state, bundle, policy, selected, true, &mut result)?;
    Ok(result)
}

pub(super) fn capture(value: &Value) -> Result<Vec<u8>> {
    ensure!(value["truncated"] != true, "Source capture is truncated");
    ensure!(
        value["decode_error"].is_null(),
        "captured payload decoding failed"
    );
    let data = value["data"]
        .as_str()
        .context("captured payload unavailable")?;
    match value["encoding"].as_str() {
        Some("utf8") => Ok(data.as_bytes().to_vec()),
        Some("base64") => STANDARD.decode(data).context("invalid capture base64"),
        _ => anyhow::bail!("unsupported capture encoding"),
    }
}

fn timestamp(value: &Value) -> Option<DateTime<Utc>> {
    value.as_str()?.parse().ok()
}
