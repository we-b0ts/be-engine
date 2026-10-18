//! Bounded, mechanism-based drafts. Source provenance remains an author obligation.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::super::model::RewriteState;
use crate::{
    policy::{Codec, CompiledPolicy, FieldContract, Protocol},
    policy_evidence::{TargetRole, WitnessManifest},
    value_contract::json::{AnchorClocks, Field},
};

const LIMIT: usize = 20;
const OBSERVATION_LIMIT: usize = 256;
const NODE_LIMIT: usize = 8192;
const SOURCE_CACHE_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Default)]
struct Drafts {
    values: Vec<Value>,
    seen: BTreeSet<String>,
    examined: usize,
    observations: usize,
    limited: bool,
    entries: Vec<Value>,
    entry_ids: BTreeSet<String>,
}

pub(in crate::rewrite) fn facts(root: &Path, state: &RewriteState) -> Result<Value> {
    let evidence = crate::resolve_e2e_response_rule_evidence(
        crate::E2eRunContext {
            target_root: root.into(),
            case_source: state
                .case_source
                .clone()
                .context("recording evidence unavailable")?,
            run_key: None,
        },
        state.group_id.as_deref().context("API group unavailable")?,
    )?;
    let report: Value = serde_json::from_slice(&fs::read(&evidence.replay)?)?;
    let manifest = report
        .get("policy_witnesses")
        .cloned()
        .map(serde_json::from_value::<WitnessManifest>)
        .transpose()?;
    let mut drafts = Drafts::default();
    let mut source_events = BTreeMap::new();
    let mut source_bytes = 0_u64;
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    let schemas = crate::policy::parse_policy(&fs::read_to_string(project.replay_policy)?)
        .ok()
        .map(|policy| crate::policy::compile_policy(&policy))
        .transpose()?;
    if let Some(manifest) = &manifest
        && manifest.complete
        && manifest.sealed
    {
        let private = crate::policy_evidence::verify(&evidence.replay, manifest)?;
        for entry in manifest.witness_entries()? {
            if drafts.observations >= OBSERVATION_LIMIT {
                drafts.limited = true;
                break;
            }
            let witness = entry?.expand()?;
            let witness = witness.as_ref();
            drafts.observations += 1;
            let case = report["cases"].as_array().and_then(|items| {
                items
                    .iter()
                    .find(|c| c["case_id"] == witness.metadata.source.case_id)
            });
            let Some(directory) = case.and_then(|c| c["case_dir"].as_str()) else {
                continue;
            };
            crate::policy_evidence::verify_case_clock(witness, &report)?;
            let (source, target) =
                crate::policy_evidence::read(&private, witness, Path::new(directory))?;
            let Some(resource) = &witness.metadata.resource else {
                continue;
            };
            if !source_events.contains_key(directory) {
                let path = Path::new(directory).join("dependencies.jsonl");
                let size = fs::metadata(&path)?.len();
                let events = if size <= 16 * 1024 * 1024
                    && source_bytes.saturating_add(size) <= SOURCE_CACHE_LIMIT
                {
                    source_bytes += size;
                    BufReader::new(fs::File::open(path)?)
                        .lines()
                        .map(|line| -> Result<Option<Value>> {
                            let line = line?;
                            if line.trim().is_empty() {
                                Ok(None)
                            } else {
                                Ok(Some(serde_json::from_str(&line)?))
                            }
                        })
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .flatten()
                        .collect()
                } else {
                    drafts.limited = true;
                    Vec::new()
                };
                source_events.insert(directory.to_owned(), events);
            }
            let identity_present = if resource.protocol == Protocol::Http {
                witness.metadata.source.exchange_id.is_some()
            } else {
                witness.metadata.source.connection_id.is_some()
                    && witness.metadata.source.sequence.is_some()
            };
            let event = source_events[directory].iter().find(|event| {
                super::preflight::dependency::protocol(event) == Some(resource.protocol)
                    && if let Some(id) = &witness.metadata.source.exchange_id {
                        event["id"] == *id
                    } else {
                        event["connection_id"].as_str()
                            == witness.metadata.source.connection_id.as_deref()
                            && (if resource.protocol == Protocol::Mysql {
                                event["query_sequence"].as_u64()
                            } else {
                                event["sequence"].as_u64()
                            }) == witness.metadata.source.sequence
                    }
                    && super::preflight::dependency::source_witness(
                        witness.metadata.surface,
                        event,
                        Path::new(directory),
                    )
                    .is_ok_and(|bytes| {
                        crate::policy_evidence::digest(&bytes) == witness.source_sha256
                    })
            });
            let Some(event) = event else {
                continue;
            };
            let independent = identity_present
                && witness.metadata.target_role == TargetRole::IndependentTargetObservation;
            if witness
                .metadata
                .resource
                .as_ref()
                .is_some_and(|r| r.protocol == Protocol::Mysql)
            {
                drafts.sql_entry(
                    event,
                    &source,
                    target.as_deref().filter(|_| independent),
                    witness,
                    state,
                    schemas.as_ref(),
                )?;
                continue;
            }
            let values =
                super::preflight::dependency::values(witness.metadata.surface, event, &source);
            let Ok(values) = values else {
                continue;
            };
            let actual = if independent {
                target.as_ref().and_then(|target| {
                    super::preflight::dependency::values(witness.metadata.surface, event, target)
                        .ok()
                })
            } else {
                None
            };
            for (index, (key, value)) in values.into_iter().enumerate() {
                let Some(key) = std::str::from_utf8(&key).ok() else {
                    continue;
                };
                let mut base = json!({"surface":witness.metadata.surface,"match":{"api":state.api,
                    "resource":witness.metadata.resource,"operation":witness.metadata.operation},"slot":witness.metadata.slot});
                if witness
                    .metadata
                    .resource
                    .as_ref()
                    .is_some_and(|r| r.protocol == Protocol::Http)
                {
                    base["match"]["path"] = json!(
                        event["uri"]
                            .as_str()
                            .and_then(|uri| uri.parse::<hyper::Uri>().ok())
                            .map(|uri| uri.path().to_owned())
                            .unwrap_or_default()
                    );
                } else {
                    base["match"]["key"] = json!({"exact":key});
                }
                drafts.observe(
                    &value,
                    actual
                        .as_ref()
                        .and_then(|a| a.get(index))
                        .map(|(_, v)| v.as_slice()),
                    base,
                    &witness.id,
                    witness.metadata.clocks.comparison(),
                    schemas.as_ref(),
                )?;
            }
        }
    }
    let assertions: Value = serde_json::from_slice(&fs::read(&evidence.assertions)?)?;
    for case in assertions["cases"].as_array().into_iter().flatten() {
        if drafts.observations >= OBSERVATION_LIMIT {
            drafts.limited = true;
            break;
        }
        drafts.observations += 1;
        let summary = &case["response"];
        let (Some(expected), Some(request)) = (
            summary["expected_response"].as_str(),
            summary["request"].as_str(),
        ) else {
            continue;
        };
        let actual = summary["actual_response"].as_str();
        if [Some(expected), actual, Some(request)]
            .into_iter()
            .flatten()
            .any(|path| fs::metadata(path).map_or(true, |m| m.len() > 4 * 1024 * 1024))
        {
            drafts.limited = true;
            continue;
        }
        let expected: Value = serde_json::from_slice(&fs::read(expected)?)?;
        let actual: Option<Value> = actual
            .map(|path| -> Result<Value> { Ok(serde_json::from_slice(&fs::read(path)?)?) })
            .transpose()?;
        let request: Value = serde_json::from_slice(&fs::read(request)?)?;
        let Ok(source_pair) = crate::replay::response_payload_pair(&request, &expected, None)
        else {
            continue;
        };
        let source = source_pair.source;
        let target = actual
            .as_ref()
            .and_then(|actual| {
                crate::replay::response_payload_pair(&request, &expected, Some(actual)).ok()
            })
            .and_then(|pair| pair.target);
        let base = json!({"surface":"api.response","match":{"api":state.api},"slot":"body"});
        let clocks = AnchorClocks {
            case: crate::value_contract::time::ClockPair {
                source: request["timestamp"].as_str().and_then(|s| s.parse().ok()),
                target: actual
                    .as_ref()
                    .and_then(|value| value["request_sent_at"].as_str())
                    .and_then(|s| s.parse().ok()),
            },
            ..Default::default()
        };
        drafts.observe(
            &source,
            target.as_deref(),
            base,
            case["case_id"].as_str().unwrap_or("api-response"),
            clocks,
            schemas.as_ref(),
        )?;
    }
    let total = drafts.seen.len();
    Ok(
        json!({"format":"traffic-policy/v1","api":state.api,"candidates":drafts.values,
        "observations_examined":drafts.observations,"json_nodes_examined":drafts.examined,"candidate_count":total,"summary_omitted":total.saturating_sub(LIMIT),
        "bounded_analysis":{"limited":drafts.limited,"observation_limit":OBSERVATION_LIMIT,"node_limit":NODE_LIMIT,"payload_limit_bytes":4 * 1024 * 1024,"source_cache_limit_bytes":SOURCE_CACHE_LIMIT,"complete_coverage":false},
        "coverage":manifest.as_ref().map(|m| json!({"sealed":m.sealed,"complete":m.complete,"omitted":m.omitted,"recorded":m.recorded})),
        "source_entry":{"bindings":drafts.entries,"requires":["an explicit surface and resource/operation/value slot", "a typed logical pointer (PB requires explicit numeric wire path and field type)", "Source file:line and the proven ordering or time relation"],
            "instruction":"A Source-proven field may be proposed directly even when no observed mechanism draft is available. Draft discovery is bounded and never coverage."},
        "plan":super::super::action::command(root,vec!["rule".into(),"plan".into(),"--file".into(),"<rule.yaml>".into(),"--evidence".into(),"<evidence-id>".into()],vec![]),
        "requires_genuine_replay":true,"does_not_prove":"Observed permutations or timestamp shifts do not prove Source intent, ownership, sharing, or successful Replay. Complete Source inventory and all selected fields are checked by plan."}),
    )
}

impl Drafts {
    #[allow(clippy::too_many_arguments)] // The bounded observation retains its evidence and decoding context.
    fn observe(
        &mut self,
        source: &[u8],
        target: Option<&[u8]>,
        mut base: Value,
        witness: &str,
        clocks: AnchorClocks,
        schemas: Option<&CompiledPolicy>,
    ) -> Result<()> {
        let configured = schemas
            .into_iter()
            .flat_map(|p| &p.rules)
            .filter(|rule| {
                serde_json::to_value(rule.rule.surface).ok().as_ref() == Some(&base["surface"])
                    && serde_json::to_value(&rule.rule.slot).ok().as_ref() == Some(&base["slot"])
                    && serde_json::to_value(&rule.rule.selector.resource)
                        .ok()
                        .as_ref()
                        == Some(&base["match"]["resource"])
                    && rule.rule.selector.operation.as_deref()
                        == base["match"]["operation"].as_str()
                    && rule.rule.selector.sql.as_deref() == base["match"]["sql"].as_str()
                    && rule.rule.selector.path.as_ref().is_none_or(|path| {
                        base["match"]["path"].as_str().is_some_and(|actual| {
                            actual == path
                                || crate::path_pattern::matches_path_pattern(path, actual)
                        })
                    })
                    && rule.rule.when.is_none()
                    && base["match"]["api"]
                        .as_str()
                        .and_then(|api| api.split_once(' '))
                        .is_some_and(|(method, path)| rule.rule.selector.matches_api(method, path))
                    && rule.rule.selector.key.as_ref().is_none_or(|s| {
                        base["match"]["key"]["exact"]
                            .as_str()
                            .is_some_and(|key| s.matches(key.as_bytes()))
                    })
            })
            .collect::<Vec<_>>();
        let codec = if !configured.is_empty() {
            Some(crate::value_contract::encoded::merged_codec(&configured)?)
        } else if crate::json_value::parse(source).is_some() {
            Some(Codec::Json)
        } else {
            None
        };
        if let Some(codec) = &codec {
            base["codec"] = serde_json::to_value(codec)?;
        }
        let identity = serde_json::to_string(&base)?;
        if self.entry_ids.insert(identity) && self.entries.len() < LIMIT {
            self.entries.push(json!({"binding":base,"witness_id":witness,"needs_schema":codec.is_none(),"source_intent_required":true,
                "instruction":if codec.is_none(){"Encoded bytes do not identify a codec. Trace Source encoding; for PB provide explicit field_path, field_type and repeated before planning."}else{"Schema supplies decoding only. Choose a field and contract from Source behavior; proof is required for this binding."}}));
        }
        let (Some(codec), Some(target)) = (codec, target) else {
            return Ok(());
        };
        let (Ok(source), Ok(target)) = (
            crate::value_codec::CodecView::decode(&codec, source),
            crate::value_codec::CodecView::decode(&codec, target),
        ) else {
            return Ok(());
        };
        let paths = match &codec {
            Codec::Json => Vec::new(),
            Codec::Protobuf(codec) => codec.fields.keys().cloned().collect(),
        };
        self.collect(
            &source.comparison_value(&paths),
            &target.comparison_value(&paths),
            "",
            &base,
            witness,
            clocks,
            0,
        )
    }
    #[allow(clippy::too_many_arguments)] // SQL bindings require the Source template; metadata slots are only placeholders.
    fn sql_entry(
        &mut self,
        event: &Value,
        source: &[u8],
        target: Option<&[u8]>,
        witness: &crate::policy_evidence::WitnessRef,
        state: &RewriteState,
        schemas: Option<&CompiledPolicy>,
    ) -> Result<()> {
        let mut rules = Vec::new();
        for rule in schemas.into_iter().flat_map(|policy| &policy.rules) {
            if rule.rule.surface == witness.metadata.surface
                && rule
                    .rule
                    .selector
                    .resource
                    .as_ref()
                    .is_some_and(|r| r.protocol == Protocol::Mysql)
                && super::preflight::dependency::selects(rule, event)?
            {
                rules.push(rule);
            }
        }
        if rules.is_empty() {
            let base = json!({"surface":witness.metadata.surface,"match":{"api":state.api,
                "resource":witness.metadata.resource,"operation":witness.metadata.operation}});
            let identity = serde_json::to_string(&base)?;
            if self.entry_ids.insert(identity) && self.entries.len() < LIMIT {
                self.entries.push(json!({"binding":base,"witness_id":witness.id,
                    "needs_sql_template":true,"needs_slot":true,"needs_schema":true,"source_intent_required":true,
                    "instruction":"Trace Source SQL construction and declare match.sql plus sql_value (template parameter ordinal) or sql_column. Metadata placeholders do not identify the value slot. Supply an explicit codec and fresh Source proof."}));
            }
            return Ok(());
        }
        for rule in rules {
            let source_values =
                crate::replay::mysql_witness_values(source, witness.metadata.surface, rule)?;
            let target_values = target
                .map(|bytes| {
                    crate::replay::mysql_witness_values(bytes, witness.metadata.surface, rule)
                })
                .transpose()?;
            let mut base = json!({"surface":rule.rule.surface,"match":rule.rule.selector,"slot":rule.rule.slot});
            base["match"]["api"] = json!(state.api);
            for (key, value) in source_values {
                let actual = target_values
                    .as_ref()
                    .and_then(|values| values.iter().find(|(other, _)| other == &key))
                    .map(|(_, value)| value.as_slice());
                self.observe(
                    &value,
                    actual,
                    base.clone(),
                    &witness.id,
                    witness.metadata.clocks.comparison(),
                    schemas,
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // A recursive walk retains one immutable observation context.
    fn collect(
        &mut self,
        source: &Value,
        target: &Value,
        pointer: &str,
        base: &Value,
        witness: &str,
        clocks: AnchorClocks,
        depth: usize,
    ) -> Result<()> {
        if depth > 32 || self.examined >= NODE_LIMIT {
            self.limited = true;
            return Ok(());
        }
        if source == target {
            return Ok(());
        }
        self.examined += 1;
        if let (Some(a), Some(b)) = (source.as_array(), target.as_array()) {
            let sorted = |items: &[Value]| {
                let mut values = items.iter().map(Value::to_string).collect::<Vec<_>>();
                values.sort();
                values
            };
            if sorted(a) == sorted(b) {
                self.push(base, pointer, json!({"kind":"unordered"}), witness)?;
                return Ok(());
            }
        }
        let formats = if source.is_number() && target.is_number() {
            let value = source.as_i64().unwrap_or(0);
            if value >= 946_684_800_000_000 {
                vec!["unix_microseconds"]
            } else if value >= 946_684_800_000 {
                vec!["unix_milliseconds"]
            } else if value >= 946_684_800 {
                vec!["unix_seconds"]
            } else {
                vec![]
            }
        } else if source.is_string() && target.is_string() {
            vec!["rfc3339"]
        } else {
            vec![]
        };
        for format in formats {
            let contract = json!({"kind":"time","format":format,"relation":"preserve_offset"});
            let typed: FieldContract = serde_json::from_value(contract.clone())?;
            let observed = if base["surface"] == "api.response" {
                AnchorClocks {
                    dependency: clocks.case,
                    ..clocks
                }
            } else {
                clocks
            };
            if crate::value_contract::json::compare(
                source,
                target,
                &[Field {
                    rule_id: "draft",
                    pointer: "",
                    contract: &typed,
                }],
                observed,
            )
            .passed()
            {
                self.push(base, pointer, contract, witness)?;
                return Ok(());
            }
        }
        if let (Some(a), Some(b)) = (source.as_object(), target.as_object()) {
            for (key, value) in a {
                if key.contains('\0') {
                    continue;
                }
                if let Some(other) = b.get(key) {
                    self.collect(
                        value,
                        other,
                        &format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
                        base,
                        witness,
                        clocks,
                        depth + 1,
                    )?;
                }
            }
        } else if let (Some(a), Some(b)) = (source.as_array(), target.as_array())
            && a.len() == b.len()
        {
            for (index, (value, other)) in a.iter().zip(b).enumerate() {
                self.collect(
                    value,
                    other,
                    &format!("{pointer}/{index}"),
                    base,
                    witness,
                    clocks,
                    depth + 1,
                )?;
            }
        }
        Ok(())
    }

    fn push(&mut self, base: &Value, pointer: &str, contract: Value, witness: &str) -> Result<()> {
        let identity = serde_json::to_string(&(base, pointer, &contract))?;
        if !self.seen.insert(identity.clone()) || self.values.len() >= LIMIT {
            return Ok(());
        }
        let id = format!(
            "draft-{}",
            super::super::fingerprint::id(&[&identity]).trim_start_matches("fnv1a64:")
        );
        let mut rule = base.clone();
        rule["id"] = json!(id);
        rule["contract"] = json!({pointer:contract});
        rule["proof"] = json!({"source":"","fact":""});
        self.values.push(
            json!({"candidate_id":id,"witness_id":witness,"mechanism":contract["kind"],
            "draft_rule":rule,"source_proof_required":true,"plan_ready":false}),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protobuf_discovery_reuses_only_an_explicit_matching_schema_and_never_its_proof() {
        let document = serde_json::json!({"format":"traffic-policy/v1","rules":[{
            "id":"known-schema","surface":"api.response","match":{"api":"GET /api"},"slot":"body",
            "codec":{"kind":"protobuf","fields":{"/members":{"field_path":[1],"field_type":"string","repeated":true}}},
            "contract":{"/members":{"kind":"unordered"}},
            "proof":{"source":"src/original.rs:4","fact":"Original binding proof"}}]});
        let schemas =
            crate::policy::compile_policy(&serde_json::from_value(document).unwrap()).unwrap();
        let source = b"\x0a\x03one\x0a\x03two\x12\x05exact";
        let target = b"\x0a\x03two\x0a\x03one\x12\x05wrong";
        for (api, expected) in [("GET /api", 1), ("GET /other", 0)] {
            let mut drafts = Drafts::default();
            drafts
                .observe(
                    source,
                    Some(target),
                    json!({"surface":"api.response","match":{"api":api},"slot":"body"}),
                    "witness",
                    AnchorClocks::default(),
                    Some(&schemas),
                )
                .unwrap();
            assert_eq!(drafts.values.len(), expected);
            assert_eq!(drafts.entries[0]["needs_schema"], expected == 0);
            if expected > 0 {
                assert_eq!(
                    drafts.values[0]["draft_rule"]["contract"]["/members"]["kind"],
                    "unordered"
                );
                assert_eq!(drafts.values[0]["draft_rule"]["proof"]["source"], "");
                assert_eq!(drafts.values[0]["draft_rule"]["proof"]["fact"], "");
            }
        }
    }

    #[test]
    fn only_observed_mechanisms_become_drafts() {
        let mut drafts = Drafts::default();
        drafts
            .collect(
                &json!({"members":[1,2,2],"business":"source"}),
                &json!({"members":[2,1,2],"business":"wrong"}),
                "",
                &json!({}),
                "witness",
                AnchorClocks::default(),
                0,
            )
            .unwrap();
        assert_eq!(drafts.values.len(), 1);
        assert_eq!(
            drafts.values[0]["draft_rule"]["contract"]["/members"]["kind"],
            "unordered"
        );
        assert_eq!(drafts.values[0]["plan_ready"], false);
        assert_eq!(drafts.values[0]["draft_rule"]["proof"]["source"], "");
    }
}
