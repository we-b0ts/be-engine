//! Bounded, mechanism-based drafts. Source provenance remains an author obligation.
use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::super::model::RewriteState;
use crate::{
    policy::{FieldContract, Surface},
    policy_evidence::{TargetRole, WitnessManifest},
    value_contract::json::{AnchorClocks, Field},
};

const LIMIT: usize = 20;
const OBSERVATION_LIMIT: usize = 256;
const NODE_LIMIT: usize = 8192;

#[derive(Default)]
struct Drafts {
    values: Vec<Value>,
    seen: BTreeSet<String>,
    examined: usize,
    observations: usize,
    limited: bool,
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
    if let Some(manifest) = &manifest
        && manifest.complete
        && manifest.sealed
    {
        let private = crate::policy_evidence::verify(&evidence.replay, manifest)?;
        for witness in manifest.witnesses.iter().filter(|w| {
            w.metadata.surface == Surface::DependencyRequest
                && w.metadata.target_role == TargetRole::IndependentTargetObservation
                && w.target_sha256.is_some()
        }) {
            if drafts.observations >= OBSERVATION_LIMIT {
                drafts.limited = true;
                break;
            }
            drafts.observations += 1;
            let case = report["cases"].as_array().and_then(|items| {
                items
                    .iter()
                    .find(|c| c["case_id"] == witness.metadata.source.case_id)
            });
            let Some(directory) = case.and_then(|c| c["case_dir"].as_str()) else {
                continue;
            };
            let (source, Some(target)) =
                crate::policy_evidence::read(&private, witness, Path::new(directory))?
            else {
                continue;
            };
            let event = json!({"command":witness.metadata.operation});
            let (Ok(source_value), Ok(target_value)) = (
                super::preflight::payload(witness.metadata.surface, &event, &source),
                super::preflight::payload(witness.metadata.surface, &event, &target),
            ) else {
                continue;
            };
            let arguments: Vec<Vec<u8>> = serde_json::from_slice(&source)?;
            let key = arguments
                .first()
                .and_then(|key| std::str::from_utf8(key).ok());
            let Some(key) = key else {
                continue;
            };
            let base = json!({"surface":witness.metadata.surface,"match":{"api":state.api,
                "resource":witness.metadata.resource,"operation":witness.metadata.operation,"key":{"exact":key}},
                "slot":witness.metadata.slot,"codec":"json"});
            drafts.collect(
                &source_value,
                &target_value,
                "",
                &base,
                &witness.id,
                witness.metadata.clocks.comparison(),
                0,
            )?;
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
        let (Some(expected), Some(actual), Some(request)) = (
            summary["expected_response"].as_str(),
            summary["actual_response"].as_str(),
            summary["request"].as_str(),
        ) else {
            continue;
        };
        if [expected, actual, request]
            .iter()
            .any(|path| fs::metadata(path).map_or(true, |m| m.len() > 4 * 1024 * 1024))
        {
            drafts.limited = true;
            continue;
        }
        let expected: Value = serde_json::from_slice(&fs::read(expected)?)?;
        let actual: Value = serde_json::from_slice(&fs::read(actual)?)?;
        let request: Value = serde_json::from_slice(&fs::read(request)?)?;
        let (Ok(source), Ok(target)) = (
            super::preflight::capture(&expected["body"]),
            super::preflight::capture(&actual["body"]),
        ) else {
            continue;
        };
        let (Some(source), Some(target)) = (
            crate::json_value::parse(&source),
            crate::json_value::parse(&target),
        ) else {
            continue;
        };
        let base = json!({"surface":"api.response","match":{"api":state.api},"slot":"body","codec":"json"});
        let clocks = AnchorClocks {
            case: crate::value_contract::time::ClockPair {
                source: request["timestamp"].as_str().and_then(|s| s.parse().ok()),
                target: actual["request_sent_at"]
                    .as_str()
                    .and_then(|s| s.parse().ok()),
            },
            ..Default::default()
        };
        drafts.collect(
            &source,
            &target,
            "",
            &base,
            case["case_id"].as_str().unwrap_or("api-response"),
            clocks,
            0,
        )?;
    }
    let total = drafts.seen.len();
    Ok(
        json!({"format":"traffic-policy/v1","api":state.api,"candidates":drafts.values,
        "observations_examined":drafts.observations,"json_nodes_examined":drafts.examined,"candidate_count":total,"summary_omitted":total.saturating_sub(LIMIT),
        "bounded_analysis":{"limited":drafts.limited,"observation_limit":OBSERVATION_LIMIT,"node_limit":NODE_LIMIT,"payload_limit_bytes":4 * 1024 * 1024,"complete_coverage":false},
        "coverage":manifest.as_ref().map(|m| json!({"sealed":m.sealed,"complete":m.complete,"omitted":m.omitted,"recorded":m.recorded})),
        "source_entry":{"requires":["an explicit surface and resource/operation/value slot", "a typed JSON pointer", "Source file:line and the proven ordering or time relation"],
            "instruction":"A Source-proven field may be proposed directly even when no observed mechanism draft is available. Draft discovery is bounded and never coverage."},
        "plan":super::super::action::command(root,vec!["rule".into(),"plan".into(),"--file".into(),"<rule.yaml>".into(),"--evidence".into(),"<evidence-id>".into()],vec![]),
        "requires_genuine_replay":true,"does_not_prove":"Observed permutations or timestamp shifts do not prove Source intent, ownership, sharing, or successful Replay. Complete Source inventory and all selected fields are checked by plan."}),
    )
}

impl Drafts {
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
            for anchor in ["case.request_start", "dependency.request_start"] {
                let contract = json!({"kind":"time","format":format,"relation":"preserve_offset","anchor":anchor});
                let typed: FieldContract = serde_json::from_value(contract.clone())?;
                if crate::value_contract::json::compare(
                    source,
                    target,
                    &[Field {
                        rule_id: "draft",
                        pointer: "",
                        contract: &typed,
                    }],
                    clocks,
                )
                .passed()
                {
                    self.push(base, pointer, contract, witness)?;
                    return Ok(());
                }
            }
        }
        if let (Some(a), Some(b)) = (source.as_object(), target.as_object()) {
            for (key, value) in a {
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
