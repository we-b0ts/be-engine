//! Validate complete Source scope and independently observed Target payloads.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
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
pub(super) mod dependency;
mod global_values;
mod identities;
mod mysql_candidates;
mod payload;
mod resource;
mod session;
mod source;
mod time_copies;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Preflight {
    pub source_validations: usize,
    pub independent_target_validations: usize,
    pub derived_delivery_validations: usize,
    pub missing_target_witnesses: usize,
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

impl Preflight {
    pub(super) fn status(&self) -> &'static str {
        if self.needs_recording() {
            "planned_needs_recording"
        } else if self.missing_target_witnesses > 0 || !self.stateful_target_obligations.is_empty()
        {
            "planned_needs_replay"
        } else {
            "preflight_validated_requires_replay"
        }
    }

    pub(super) fn needs_recording(&self) -> bool {
        source::needs_recording(&self.obligations)
    }

    pub(super) fn ensure_current(&self, root: &Path, policy: &CompiledPolicy) -> Result<()> {
        if let Some(record) = &self.source_scope {
            record.ensure_current(root, policy)?;
        }
        if let Some(record) = &self.resource_scope {
            record.ensure_current(root)?;
        }
        Ok(())
    }
}

pub(super) fn verify(
    root: &Path,
    state: &RewriteState,
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
) -> Result<Preflight> {
    source::validate_project(root, policy)?;
    let mut result = Preflight::default();
    identities::require_replay(policy, selected, &mut result);
    source::verify(root, state, bundle, policy, selected, &mut result)?;
    let (scope, mut foreign) = resource::prepare(root, state, bundle, policy, selected)?;
    global_values::verify(root, bundle, policy, selected, &mut result)?;
    global_values::global_trace(state, bundle, policy, selected, &mut result)?;
    payload::verify(root, bundle, policy, selected, &mut result)?;
    let resource_ids = resource::selected(policy, selected);
    for other in &mut foreign {
        global_values::verify(root, other, policy, &resource_ids, &mut result)?;
        payload::verify(root, other, policy, &resource_ids, &mut result)?;
        bundle.cases.append(&mut other.cases);
        bundle.artifacts.append(&mut other.artifacts);
    }
    result.resource_scope = scope;
    async_api::verify(bundle, policy, selected, &mut result)?;

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

fn redis_payload(surface: Surface, event: &Value, raw: &[u8]) -> Result<Vec<u8>> {
    if surface == Surface::DependencyRequest {
        let args: Vec<Vec<u8>> = serde_json::from_slice(raw)?;
        let index = value_index(event, args.len())?;
        Ok(args.get(index).context("Redis value slot missing")?.clone())
    } else {
        crate::replay::redis_bulk_payload(raw)?.context("Redis response has no encoded value")
    }
}

fn value_index(event: &Value, length: usize) -> Result<usize> {
    match (event["command"].as_str(), length) {
        (Some("SET"), 2..) | (Some("PUBLISH"), 2) => Ok(1),
        (Some("SETEX" | "PSETEX"), 3) => Ok(2),
        _ => anyhow::bail!("unsupported Redis value slot or argument shape"),
    }
}

fn arguments(event: &Value) -> Result<Vec<Vec<u8>>> {
    event["args"]
        .as_array()
        .context("Source Redis arguments unavailable")?
        .iter()
        .map(capture)
        .collect()
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
