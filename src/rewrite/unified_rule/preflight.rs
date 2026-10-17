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
    policy::{CompiledPolicy, CompiledRule, NativeEffect, Protocol, Surface},
    policy_evidence::{TargetRole, WitnessManifest},
    rewrite::model::RewriteState,
    value_contract::json::AnchorClocks,
};

mod api;
pub(super) mod dependency;
mod mysql_candidates;
mod session;
mod source;

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
    let mut result = Preflight::default();
    let mut mysql_candidates = mysql_candidates::Candidates::default();
    source::verify(root, state, bundle, policy, selected, &mut result)?;
    let manifest = bundle
        .replay
        .get("policy_witnesses")
        .cloned()
        .map(serde_json::from_value::<WitnessManifest>)
        .transpose()?;
    let private = if let Some(manifest) = &manifest {
        if manifest.complete && manifest.sealed {
            let path = crate::policy_evidence::verify(&bundle.replay_path, manifest)?;
            for artifact in manifest.artifact_paths(&bundle.replay_path)? {
                bundle.freeze(&artifact)?;
            }
            Some(path)
        } else {
            None
        }
    } else {
        None
    };
    let witness_index = manifest
        .as_ref()
        .filter(|_| private.is_some())
        .map(WitnessManifest::source_index)
        .transpose()?;
    for (case_id, directory) in bundle.cases.clone() {
        let request = bundle.json(&directory.join("request.json"))?;
        let method = request["method"]
            .as_str()
            .context("Source request method unavailable")?;
        let uri = request["uri"]
            .as_str()
            .context("Source request URI unavailable")?;
        let path = uri
            .parse::<hyper::Uri>()
            .context("invalid Source URI")?
            .path()
            .to_string();
        let mut applicable = Vec::new();
        for rule in policy
            .rules
            .iter()
            .filter(|r| r.rule.selector.matches_api(method, &path))
        {
            if let Some(condition) = &rule.rule.when {
                let body = crate::json_value::parse(&capture(&request["body"])?).context(
                    "Source condition requires complete unique-member JSON request evidence",
                )?;
                if !condition.matches_body(&body) {
                    continue;
                }
            }
            applicable.push(rule);
        }
        let response_rules = applicable
            .iter()
            .copied()
            .filter(|r| r.rule.surface == Surface::ApiResponse)
            .collect::<Vec<_>>();
        let source_body = capture(&request["body"])
            .ok()
            .and_then(|bytes| crate::json_value::parse(&bytes));
        let native_applicable =
            crate::replay::native_response_selected(policy, method, &path, source_body.as_ref());
        let native_response = native_applicable
            .iter()
            .copied()
            .filter(|rule| api::is_response(rule))
            .collect::<Vec<_>>();
        if response_rules.iter().any(|r| selected.contains(&r.rule.id))
            || native_response
                .iter()
                .any(|r| selected.contains(&r.rule.id))
        {
            api::verify(
                root,
                bundle,
                &case_id,
                &directory,
                &request,
                &response_rules,
                &native_response,
                &mut result,
            )?;
        }
        let file = fs::File::open(directory.join("dependencies.jsonl"))?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            ensure!(
                line.len() <= 16 * 1024 * 1024,
                "recorded exchange exceeds the supported evidence bound"
            );
            if line.trim().is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(&line)?;
            for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
                let mut rules = Vec::new();
                for rule in applicable
                    .iter()
                    .copied()
                    .filter(|r| r.rule.surface == surface)
                {
                    if dependency::selects(rule, &event)? {
                        rules.push(rule);
                    }
                }
                let mut native_sql = Vec::new();
                if surface == Surface::DependencyRequest
                    && dependency::protocol(&event) == Some(Protocol::Mysql)
                {
                    for rule in native_applicable
                        .iter()
                        .copied()
                        .filter(|rule| matches!(&rule.rule.effect, NativeEffect::MysqlValues(_)))
                    {
                        if dependency::selects_native_sql(rule, &event)? {
                            native_sql.push(rule);
                        }
                    }
                }
                if !rules.iter().any(|r| selected.contains(&r.rule.id))
                    && !native_sql.iter().any(|r| selected.contains(&r.rule.id))
                {
                    continue;
                }
                ensure!(
                    event["replay_safe"] != false
                        && event["global_dependency_reason"].is_null()
                        && event["cache_snapshot_rule"].is_null(),
                    "value rule requires complete ordinary Case evidence; it does not authorize ownership or snapshots"
                );
                let raw = dependency::source_witness(surface, &event, &directory)?;
                let source_time = timestamp(&request["timestamp"]);
                let completed = timestamp(&event["timestamp"]);
                let started = timestamp(&event["request_started_at"]).or_else(|| {
                    completed
                        .zip(event["duration_ms"].as_u64())
                        .and_then(|(t, n)| {
                            t.checked_sub_signed(chrono::TimeDelta::milliseconds(
                                i64::try_from(n).ok()?,
                            ))
                        })
                });
                let source_clocks = AnchorClocks {
                    case: crate::value_contract::time::ClockPair {
                        source: source_time,
                        target: source_time,
                    },
                    dependency: crate::value_contract::time::ClockPair {
                        source: started,
                        target: started,
                    },
                    delivery: crate::value_contract::time::ClockPair {
                        source: completed,
                        target: completed,
                    },
                };
                let checked = dependency::compare_source(
                    surface,
                    &event,
                    &raw,
                    &rules,
                    &native_sql,
                    source_clocks,
                )?;
                if checked.is_empty() {
                    result.unavailable_source_values += 1;
                    continue;
                }
                result.source_validations += 1;
                for id in checked {
                    *result.rules.entry(id).or_default() += 1;
                }
                let Some(_manifest) = manifest.as_ref().filter(|_| private.is_some()) else {
                    result.missing_target_witnesses += 1;
                    continue;
                };
                let source_sha256 = crate::policy_evidence::digest(&raw);
                let mut found = false;
                let mut observations = BTreeSet::new();
                let http = dependency::protocol(&event) == Some(Protocol::Http);
                let identity = crate::policy_evidence::SourceIdentity {
                    case_id: case_id.clone(),
                    exchange_id: if http {
                        event["id"].as_str().map(str::to_owned)
                    } else {
                        None
                    },
                    connection_id: if http {
                        None
                    } else {
                        event["connection_id"].as_str().map(str::to_owned)
                    },
                    sequence: if http {
                        None
                    } else {
                        event[if dependency::protocol(&event) == Some(Protocol::Mysql) {
                            "query_sequence"
                        } else {
                            "sequence"
                        }]
                        .as_u64()
                    },
                };
                for entry in witness_index
                    .as_ref()
                    .unwrap()
                    .for_source(surface, &identity)
                {
                    let metadata = entry.metadata();
                    let matches = metadata.surface == surface
                        && metadata.source.case_id == case_id
                        && (dependency::protocol(&event) == Some(Protocol::Http)
                            || event["connection_id"].is_string()
                                && if dependency::protocol(&event) == Some(Protocol::Mysql) {
                                    event["query_sequence"].is_u64()
                                } else {
                                    event["sequence"].is_u64()
                                })
                        && metadata.source.connection_id.as_deref()
                            == event["connection_id"].as_str()
                        && metadata.source.sequence
                            == if dependency::protocol(&event) == Some(Protocol::Mysql) {
                                event["query_sequence"].as_u64()
                            } else {
                                event["sequence"].as_u64()
                            }
                        && (dependency::protocol(&event) != Some(Protocol::Http)
                            || event["id"].is_string())
                        && metadata.source.exchange_id.as_deref()
                            == if dependency::protocol(&event) == Some(Protocol::Http) {
                                event["id"].as_str()
                            } else {
                                None
                            }
                        && entry.source_sha256()? == source_sha256
                        && entry.has_target();
                    if !matches {
                        continue;
                    }
                    let witness = entry.expand()?;
                    let witness = witness.as_ref();
                    crate::policy_evidence::verify_case_clock(witness, &bundle.replay)?;
                    dependency::validate_metadata(witness, &event)?;
                    let clocks = witness.metadata.clocks.comparison();
                    ensure!(
                        clocks.case.source == source_clocks.case.source
                            && clocks
                                .dependency
                                .source
                                .is_none_or(|time| Some(time) == source_clocks.dependency.source)
                            && clocks
                                .delivery
                                .source
                                .is_none_or(|time| Some(time) == source_clocks.delivery.source),
                        "protected witness Source anchors differ from the immutable exchange"
                    );
                    let (retained, target) = crate::policy_evidence::read(
                        private.as_ref().unwrap(),
                        witness,
                        &directory,
                    )?;
                    ensure!(
                        retained == raw,
                        "protected Source witness differs from immutable recording"
                    );
                    let target = target.context("Target payload witness is unavailable")?;
                    let stateful = native_sql.iter().filter(|rule|
                        matches!(&rule.rule.effect, NativeEffect::MysqlValues(effect) if !effect.params.is_empty()))
                        .map(|rule| rule.rule.id.clone()).collect::<BTreeSet<_>>();
                    if !stateful.is_empty() {
                        // Scalar masks prove neither a case binding nor its later references.
                        // Preserve the complete observation without claiming Target validation.
                        result.stateful_target_obligations.extend(stateful);
                        found = true;
                        continue;
                    }
                    let comparison = dependency::compare_pair(
                        surface,
                        &event,
                        &raw,
                        &target,
                        &rules,
                        &native_sql,
                        clocks,
                    )
                    .with_context(|| {
                        let rules = rules.iter().map(|r| r.rule.id.as_str())
                            .chain(native_sql.iter().map(|r| r.rule.id.as_str())).collect::<Vec<_>>();
                        format!("dependency preflight failed for rules {rules:?}, Case {case_id}, Source connection {:?} sequence {:?}, Target observation {:?}",
                            witness.metadata.source.connection_id, witness.metadata.source.sequence,
                            witness.target_observation_id.as_deref().unwrap_or(&witness.id))
                    });
                    let evaluated = if surface == Surface::DependencyRequest
                        && dependency::protocol(&event) == Some(Protocol::Mysql)
                    {
                        mysql_candidates.observe(witness, comparison)?
                    } else {
                        comparison?
                    };
                    if evaluated == 0 {
                        continue;
                    }
                    found = true;
                    // One physical observation may be recorded once per SQL slot.
                    // Validate every protected envelope, then count the observation once.
                    if !observations.insert((
                        witness
                            .target_observation_id
                            .clone()
                            .or_else(|| witness.target_sha256.clone()),
                        serde_json::to_string(&witness.metadata.target_role)?,
                    )) {
                        continue;
                    }
                    match witness.metadata.target_role {
                        TargetRole::IndependentTargetObservation => {
                            result.independent_target_validations += 1
                        }
                        TargetRole::DerivedDelivery => result.derived_delivery_validations += 1,
                        TargetRole::Unavailable => {
                            anyhow::bail!("Target witness has no independent or derived role")
                        }
                    }
                }
                if !found {
                    result.missing_target_witnesses += 1;
                }
            }
        }
    }
    mysql_candidates.finish()?;
    session::verify(root, bundle, policy, selected, &mut result)?;
    for id in selected {
        ensure!(
            result.rules.get(id).is_some_and(|n| *n > 0),
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
