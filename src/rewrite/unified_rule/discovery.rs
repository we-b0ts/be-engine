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
mod dependency;
mod interaction;
mod page;
mod primary;
pub(in crate::rewrite) use page::Cursor;

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
    summary_offset: usize,
    nonresumable_limits: BTreeSet<&'static str>,
}

pub(in crate::rewrite) fn facts(
    root: &Path,
    state: &RewriteState,
    cursor: Cursor,
) -> Result<Value> {
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
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    let schemas = crate::policy::parse_policy(&fs::read_to_string(project.replay_policy)?)
        .ok()
        .map(|policy| crate::policy::compile_policy(&policy))
        .transpose()?;
    let mut next = cursor;
    let mut drafts = Drafts {
        summary_offset: cursor.summary,
        ..Default::default()
    };
    let (primary_done, dependency_done) = if cursor.primary_first {
        let primary_done = primary::observe(
            &mut drafts,
            &evidence.assertions,
            state,
            schemas.as_ref(),
            &mut next,
        )?;
        let dependency_done = dependency::observe(
            &mut drafts,
            &evidence.replay,
            &report,
            manifest.as_ref(),
            state,
            schemas.as_ref(),
            &mut next,
        )?;
        (primary_done, dependency_done)
    } else {
        let dependency_done = dependency::observe(
            &mut drafts,
            &evidence.replay,
            &report,
            manifest.as_ref(),
            state,
            schemas.as_ref(),
            &mut next,
        )?;
        let primary_done = primary::observe(
            &mut drafts,
            &evidence.assertions,
            state,
            schemas.as_ref(),
            &mut next,
        )?;
        (primary_done, dependency_done)
    };
    let next_page = drafts.has_summary_page().then(|| {
        Cursor {
            summary: cursor.summary + LIMIT,
            ..cursor
        }
        .encode()
    });
    let next_scan = (!primary_done || !dependency_done).then(|| {
        next.summary = 0;
        next.primary_first = !cursor.primary_first;
        next.encode()
    });
    let total = drafts.seen.len();
    Ok(
        json!({"format":"traffic-policy/v1","api":state.api,"candidates":drafts.values,
        "observations_examined":drafts.observations,"json_nodes_examined":drafts.examined,"candidate_count":total,"summary_omitted":total.saturating_sub(drafts.values.len()),
        "pagination":{"scope":"bounded_scan_window","summary_offset":cursor.summary,"summary_limit":LIMIT,"scan_remaining":!primary_done || !dependency_done,"next_page_cursor":next_page,"next_scan_cursor":next_scan},
        "bounded_analysis":{"scan_order":if cursor.primary_first { ["api.response", "dependency"] } else { ["dependency", "api.response"] },"limited":drafts.limited || drafts.summary_limited(),"summary_limited":drafts.summary_limited(),"observation_limit":OBSERVATION_LIMIT,"node_limit":NODE_LIMIT,"payload_limit_bytes":4 * 1024 * 1024,"source_cache_limit_bytes":SOURCE_CACHE_LIMIT,"complete_coverage":false,"nonresumable_limits":drafts.nonresumable_limits},
        "coverage":manifest.as_ref().map(|m| json!({"sealed":m.sealed,"complete":m.complete,"omitted":m.omitted,"recorded":m.recorded})),
        "source_entry":{"binding_count":drafts.entry_ids.len(),"summary_omitted":drafts.entry_ids.len().saturating_sub(drafts.entries.len()),"bindings":drafts.entries,"requires":["an explicit surface and resource/operation/value slot", "a typed logical pointer (PB requires explicit numeric wire path and field type)", "Source file:line and the proven ordering or time relation"],
            "instruction":"A Source-proven field may be proposed directly even when no observed mechanism draft is available. Draft discovery is bounded and never coverage."},
        "plan":super::super::action::command(root,vec!["rule".into(),"plan".into(),"--file".into(),"<rule.yaml>".into(),"--evidence".into(),"<evidence-id>".into()],vec![]),
        "requires_genuine_replay":true,"does_not_prove":"Observed permutations or timestamp shifts do not prove Source intent, ownership, sharing, or successful Replay. Complete Source inventory and all selected fields are checked by plan."}),
    )
}

impl Drafts {
    fn limit(&mut self, reason: &'static str) {
        self.limited = true;
        self.nonresumable_limits.insert(reason);
    }
    #[allow(clippy::too_many_arguments)] // The bounded observation retains its evidence and decoding context.
    fn observe(
        &mut self,
        source: &[u8],
        target: Option<&[u8]>,
        mut base: Value,
        witness: &str,
        clocks: AnchorClocks,
        schemas: Option<&CompiledPolicy>,
        sql_scope: Option<&BTreeSet<&str>>,
    ) -> Result<()> {
        let configured = schemas
            .into_iter()
            .flat_map(|p| &p.rules)
            .filter(|rule| {
                sql_scope.is_none_or(|ids| ids.contains(rule.rule.id.as_str()))
                    && serde_json::to_value(rule.rule.surface).ok().as_ref()
                        == Some(&base["surface"])
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
        self.add_entry(identity, json!({"binding":base,"witness_id":witness,"needs_schema":codec.is_none(),"source_intent_required":true,
                "instruction":if codec.is_none(){"Encoded bytes do not identify a codec. Trace Source encoding; for PB provide explicit field_path, field_type and repeated before planning."}else if base["slot"].get("sse_data").is_some(){"Pointers address the SSE data JSON for this exact event/type. Trace Source time generation for request_time/relative_time; a generated identity needs an explicit prefix/format and shared binding across every referring event/pointer, including terminal output. Differences alone do not prove identity permission. Event presence/order and unselected text stay strict. See docs/sse-value-contracts.md."}else{"Schema supplies decoding only. Choose a field and contract from Source behavior; proof is required for this binding."}}));
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
        let target = if witness.metadata.surface == crate::policy::Surface::DependencyRequest {
            match target {
                Some(target) if crate::replay::mysql_request_witnesses_related(source, target)? => {
                    Some(target)
                }
                _ => None,
            }
        } else {
            target
        };
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
            let identity = serde_json::to_string(&(&base, &event["response"]["status"]))?;
            self.add_entry(identity, json!({"binding":base,"witness_id":witness.id,
                    "source_response_kind":event["response"]["status"],
                    "needs_sql_template":true,"needs_slot":true,"needs_schema":true,"source_intent_required":true,
                    "instruction":"Trace Source SQL construction and declare match.sql plus sql_value (template parameter ordinal) or sql_column. Metadata placeholders do not identify the value slot. Supply an explicit codec and fresh Source proof."}));
            return Ok(());
        }
        let scope = rules
            .iter()
            .map(|rule| rule.rule.id.as_str())
            .collect::<BTreeSet<_>>();
        for rule in &rules {
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
                    Some(&scope),
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
            self.limit(if depth > 32 {
                "json_depth"
            } else {
                "json_nodes"
            });
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
                if self.examined >= NODE_LIMIT {
                    self.limit("json_nodes");
                    break;
                }
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
                if self.examined >= NODE_LIMIT {
                    self.limit("json_nodes");
                    break;
                }
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
        if !self.seen.insert(identity.clone())
            || self.seen.len() <= self.summary_offset
            || self.values.len() >= LIMIT
        {
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
    fn sql_value_table_discovery_uses_only_the_selected_physical_table_schemas() {
        let mut first = json!({"id":"json","surface":"dependency.request","match":{"api":"GET /api","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY","sql":"UPDATE {{table}} SET payload=? WHERE id=?","table_series":{"prefix":"tasks_","start":1,"end":1,"width":4}},"slot":{"sql_value":0},"codec":"json","contract":{"/members":"unordered"},"proof":{"source":"store.py:write","fact":"The first physical table stores a JSON membership set"}});
        let mut second = first.clone();
        second["id"] = json!("protobuf");
        second["match"]["table_series"]["start"] = json!(2);
        second["match"]["table_series"]["end"] = json!(2);
        second["codec"] = json!({"kind":"protobuf","fields":{"/members":{"field_path":[1],"field_type":"string","repeated":true}}});
        let schemas = crate::policy::parse_and_compile_policy(
            &json!({"format":"traffic-policy/v1","rules":[first.clone(),second]}).to_string(),
        )
        .unwrap();
        let mut drafts = Drafts::default();
        let scope = BTreeSet::from(["json"]);
        first.as_object_mut().unwrap().remove("id");
        first.as_object_mut().unwrap().remove("contract");
        first.as_object_mut().unwrap().remove("proof");
        drafts
            .observe(
                br#"{"members":["a","b"]}"#,
                Some(br#"{"members":["b","a"]}"#),
                first,
                "witness",
                AnchorClocks::default(),
                Some(&schemas),
                Some(&scope),
            )
            .unwrap();
        assert_eq!(drafts.values.len(), 1);
        assert_eq!(drafts.entries[0]["binding"]["codec"], "json");
    }

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
                    None,
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
