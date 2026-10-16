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
    policy::{CompiledPolicy, CompiledRule, Protocol, Surface},
    policy_evidence::{TargetRole, WitnessManifest, WitnessRef},
    value_contract::json::{self, AnchorClocks, Field},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Preflight {
    pub source_validations: usize,
    pub independent_target_validations: usize,
    pub derived_delivery_validations: usize,
    pub missing_target_witnesses: usize,
    pub rules: BTreeMap<String, usize>,
}

impl Preflight {
    pub(super) fn status(&self) -> &'static str {
        if self.missing_target_witnesses > 0 {
            "planned_needs_replay"
        } else {
            "preflight_validated_requires_replay"
        }
    }
}

pub(super) fn verify(
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
) -> Result<Preflight> {
    let mut result = Preflight::default();
    let manifest = bundle
        .replay
        .get("policy_witnesses")
        .cloned()
        .map(serde_json::from_value::<WitnessManifest>)
        .transpose()?;
    let private = if let Some(manifest) = &manifest {
        if manifest.complete && manifest.sealed {
            let path = crate::policy_evidence::verify(&bundle.replay_path, manifest)?;
            bundle.freeze(&path)?;
            Some(path)
        } else {
            None
        }
    } else {
        None
    };
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
        if response_rules.iter().any(|r| selected.contains(&r.rule.id)) {
            api_response(
                bundle,
                &case_id,
                &directory,
                &request,
                &response_rules,
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
                    if redis_selects(rule, &event)? {
                        rules.push(rule);
                    }
                }
                if !rules.iter().any(|r| selected.contains(&r.rule.id)) {
                    continue;
                }
                ensure!(
                    event["replay_safe"] == true
                        && event["outcome"].as_str().is_none_or(|s| s == "response")
                        && event["global_dependency_reason"].is_null()
                        && event["cache_snapshot_rule"].is_null(),
                    "value rule requires complete ordinary Case evidence; it does not authorize ownership or snapshots"
                );
                let raw = if surface == Surface::DependencyRequest {
                    serde_json::to_vec(&arguments(&event)?)?
                } else {
                    capture(&event["response"])?
                };
                let source = payload(surface, &event, &raw)?;
                let source_time = timestamp(&request["timestamp"]);
                let mut source_clocks = AnchorClocks::default();
                source_clocks.case = crate::value_contract::time::ClockPair {
                    source: source_time,
                    target: source_time,
                };
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
                source_clocks.dependency = crate::value_contract::time::ClockPair {
                    source: started,
                    target: started,
                };
                source_clocks.delivery = crate::value_contract::time::ClockPair {
                    source: completed,
                    target: completed,
                };
                compare(&source, &source, &rules, source_clocks)?;
                result.source_validations += 1;
                for rule in &rules {
                    *result.rules.entry(rule.rule.id.clone()).or_default() += 1;
                }
                let refs = manifest
                    .as_ref()
                    .map(|m| {
                        m.witnesses
                            .iter()
                            .filter(|w| {
                                w.metadata.surface == surface
                                    && w.metadata.source.case_id == case_id
                                    && w.metadata.source.connection_id.as_deref()
                                        == event["connection_id"].as_str()
                                    && w.metadata.source.sequence == event["sequence"].as_u64()
                                    && w.source_sha256 == crate::policy_evidence::digest(&raw)
                                    && w.target_sha256.is_some()
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if refs.is_empty() || private.is_none() {
                    result.missing_target_witnesses += 1;
                    continue;
                }
                for witness in refs {
                    validate_metadata(witness, &event)?;
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
                    if surface == Surface::DependencyRequest {
                        let expected = arguments(&event)?;
                        let actual: Vec<Vec<u8>> = serde_json::from_slice(&target)?;
                        let value_index = value_index(&event)?;
                        ensure!(
                            expected.len() == actual.len()
                                && expected
                                    .iter()
                                    .zip(&actual)
                                    .enumerate()
                                    .all(|(i, (a, b))| i == value_index || a == b),
                            "unselected Redis key/options/arguments differ"
                        );
                    }
                    compare(&source, &payload(surface, &event, &target)?, &rules, clocks)?;
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
            }
        }
    }
    for id in selected {
        ensure!(
            result.rules.get(id).is_some_and(|n| *n > 0),
            "rule {id:?} selects no complete Source witness in this attempt"
        );
    }
    Ok(result)
}

fn compare(
    source: &Value,
    target: &Value,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<()> {
    let fields = rules
        .iter()
        .flat_map(|rule| {
            rule.rule
                .contract
                .iter()
                .map(move |(pointer, contract)| Field {
                    rule_id: &rule.rule.id,
                    pointer,
                    contract,
                })
        })
        .collect::<Vec<_>>();
    let report = json::compare(source, target, &fields, clocks);
    ensure!(
        report.passed(),
        "unified contract preflight failed: {}",
        serde_json::to_string(&report.differences)?
    );
    Ok(())
}

fn redis_selects(rule: &CompiledRule, event: &Value) -> Result<bool> {
    let resource = rule
        .rule
        .selector
        .resource
        .as_ref()
        .context("dependency rule lacks resource")?;
    ensure!(
        resource.protocol == Protocol::Redis,
        "P1 dependency preflight supports Redis JSON; other protocols require their P2 adapter"
    );
    if event["event_type"] != "redis_exchange"
        || !event["target_host"]
            .as_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(&resource.endpoint.host))
        || event["target_port"].as_u64() != Some(u64::from(resource.endpoint.port))
        || resource
            .database
            .as_ref()
            .is_some_and(|d| d.index() != event["database"].as_i64())
        || resource
            .username
            .as_ref()
            .is_some_and(|u| event["username"].as_str() != Some(u))
        || rule
            .rule
            .selector
            .operation
            .as_ref()
            .is_some_and(|c| event["command"] != *c)
    {
        return Ok(false);
    }
    let args = arguments(event)?;
    Ok(args
        .first()
        .is_some_and(|k| rule.rule.selector.key.as_ref().is_none_or(|s| s.matches(k))))
}

fn validate_metadata(witness: &WitnessRef, event: &Value) -> Result<()> {
    let resource = witness
        .metadata
        .resource
        .as_ref()
        .context("witness has no protocol identity")?;
    ensure!(
        resource.protocol == Protocol::Redis
            && event["target_host"]
                .as_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&resource.endpoint.host))
            && event["target_port"].as_u64() == Some(u64::from(resource.endpoint.port))
            && resource.database.as_ref().and_then(|d| d.index()) == event["database"].as_i64()
            && resource.username.as_deref() == event["username"].as_str()
            && event["command"] == witness.metadata.operation,
        "Target witness protocol identity differs from the selected immutable Source exchange"
    );
    Ok(())
}

pub(super) fn payload(surface: Surface, event: &Value, raw: &[u8]) -> Result<Value> {
    if surface == Surface::DependencyRequest {
        let args: Vec<Vec<u8>> = serde_json::from_slice(raw)?;
        let index = value_index(event)?;
        ensure!(
            event["command"] != "RPUSH" || args.len() == 2,
            "P1 RPUSH preflight requires one explicitly selected element"
        );
        crate::json_value::parse(args.get(index).context("Redis value slot missing")?)
            .context("selected Redis value is not complete unique-member JSON")
    } else {
        let bytes = bytes::Bytes::copy_from_slice(raw);
        let (frame, consumed) = redis_protocol::resp2::decode::decode_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid Redis response envelope: {e}"))?
            .context("incomplete Redis response")?;
        ensure!(consumed == bytes.len(), "Redis response has trailing bytes");
        let redis_protocol::resp2::types::BytesFrame::BulkString(value) = frame else {
            anyhow::bail!("JSON read requires one successful bulk-string response");
        };
        crate::json_value::parse(&value)
            .context("selected Redis response is not complete unique-member JSON")
    }
}

fn value_index(event: &Value) -> Result<usize> {
    match event["command"].as_str() {
        Some("SET" | "RPUSH" | "PUBLISH") => Ok(1),
        Some("SETEX" | "PSETEX" | "HSET") => Ok(2),
        _ => anyhow::bail!("unsupported P1 Redis value slot"),
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

fn api_response(
    bundle: &mut Bundle,
    case: &str,
    directory: &Path,
    request: &Value,
    rules: &[&CompiledRule],
    result: &mut Preflight,
) -> Result<()> {
    let summary = bundle.assertions["cases"]
        .as_array()
        .and_then(|items| items.iter().find(|c| c["case_id"] == case))
        .map(|c| c["response"].clone())
        .unwrap_or(Value::Null);
    let expected = summary["expected_response"]
        .as_str()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| directory.join("expected-response.json"));
    let source_document = bundle.json(&expected)?;
    let immutable = bundle.json(&directory.join("expected-response.json"))?;
    ensure!(
        source_document == immutable,
        "primary Source response does not match the prepared immutable case"
    );
    let source = crate::json_value::parse(&capture(&source_document["body"])?)
        .context("Source primary JSON response unavailable")?;
    let source_time = timestamp(&request["timestamp"]);
    let clocks = AnchorClocks {
        case: crate::value_contract::time::ClockPair {
            source: source_time,
            target: source_time,
        },
        ..Default::default()
    };
    compare(&source, &source, rules, clocks)?;
    result.source_validations += 1;
    for rule in rules {
        *result.rules.entry(rule.rule.id.clone()).or_default() += 1;
    }
    let Some(actual) = summary["actual_response"].as_str() else {
        result.missing_target_witnesses += 1;
        return Ok(());
    };
    let detail_path = summary["detail_report"]
        .as_str()
        .context("Target response has no runner-owned assertion detail")?;
    let detail = bundle.json(Path::new(detail_path))?;
    ensure!(
        crate::verification_progress::fingerprint(&fs::read(detail_path)?)
            == summary["detail_fingerprint"]
                .as_str()
                .context("assertion detail fingerprint missing")?
            && detail["case_id"] == case
            && detail["expected_response_path"] == expected.to_string_lossy().as_ref()
            && detail["actual_response_path"] == actual,
        "response assertion detail identity changed after publication"
    );
    let target_document = bundle.json(Path::new(actual))?;
    for (path, field) in [
        (expected.as_path(), "expected_response_fingerprint"),
        (Path::new(actual), "actual_response_fingerprint"),
    ] {
        ensure!(
            detail[field].as_str()
                == Some(crate::verification_progress::fingerprint(&fs::read(path)?).as_str()),
            "primary response bytes changed after assertion publication"
        );
    }
    let target = crate::json_value::parse(&capture(&target_document["body"])?)
        .context("Target primary JSON response unavailable")?;
    compare(
        &source,
        &target,
        rules,
        AnchorClocks {
            case: crate::value_contract::time::ClockPair {
                source: source_time,
                target: timestamp(&target_document["request_sent_at"]),
            },
            ..Default::default()
        },
    )?;
    result.independent_target_validations += 1;
    Ok(())
}
