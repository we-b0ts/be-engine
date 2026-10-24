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
mod sql_fields;
mod values;
pub(in crate::rewrite) use page::Cursor;

const LIMIT: usize = 20;
const OBSERVATION_LIMIT: usize = 256;
const NODE_LIMIT: usize = 8192;
const SOURCE_CACHE_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Default)]
struct Drafts {
    values: Vec<Value>,
    seen: BTreeSet<String>,
    candidate_bindings: BTreeMap<String, BTreeSet<(String, String)>>,
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
    let candidates = drafts.candidates();
    Ok(
        json!({"format":"traffic-policy/v2","api":state.api,"candidates":candidates,
        "observations_examined":drafts.observations,"json_nodes_examined":drafts.examined,"candidate_count":total,"summary_omitted":total.saturating_sub(candidates.len()),
        "pagination":{"scope":"bounded_scan_window","summary_offset":cursor.summary,"summary_limit":LIMIT,"scan_remaining":!primary_done || !dependency_done,"next_page_cursor":next_page,"next_scan_cursor":next_scan},
        "bounded_analysis":{"scan_order":if cursor.primary_first { ["api.response", "dependency"] } else { ["dependency", "api.response"] },"limited":drafts.limited || drafts.summary_limited(),"summary_limited":drafts.summary_limited(),"observation_limit":OBSERVATION_LIMIT,"node_limit":NODE_LIMIT,"payload_limit_bytes":4 * 1024 * 1024,"source_cache_limit_bytes":SOURCE_CACHE_LIMIT,"complete_coverage":false,"nonresumable_limits":drafts.nonresumable_limits},
        "coverage":manifest.as_ref().map(|m| json!({"sealed":m.sealed,"complete":m.complete,"omitted":m.omitted,"recorded":m.recorded})),
        "source_entry":{"binding_count":drafts.entry_ids.len(),"summary_omitted":drafts.entry_ids.len().saturating_sub(drafts.entries.len()),"bindings":drafts.entries,"requires":["an owning resource and physical data position; response outputs retain their API/envelope selector", "a codec and logical pointer (PB requires explicit numeric wire path and field type)", "Source file:line proving time format/relation, duration unit/branch, unordered consumer semantics or identity variability", "existing declaration reuse, Source-proven table/key families and exact null/empty/sentinel branches"],
            "identity_inventory":{"scope":"case","relationship":"bijective_renaming","requires":["one shared binding and consistent format", "all eligible MySQL/Redis/response locations together", "Source proof that these positions permit renaming rather than fixed/external business values", "explicit guards or a retained narrow native owner when eligibility varies"],"observations_define_relations":true,"automatic_permission":false},
            "instruction":"Inspect existing declarations and propose Source-proven physical fields directly even without a mechanism draft. Request an identity's complete location inventory at its first mismatch; a generator-first capture rule is not required. Native rules add only extra contextual relationships, derivation or protocol/stateful behavior. Draft discovery is bounded and never coverage."},
        "plan":super::super::action::command(root,vec!["rule".into(),"plan".into(),"--file".into(),"<rule.yaml>".into(),"--evidence".into(),"<evidence-id>".into()],vec![]),
        "requires_genuine_replay":true,"does_not_prove":"Observed permutations, timestamp shifts or ID equality do not prove Source intent, eligibility, ownership, sharing or successful Replay. Complete Source inventory and all selected fields are checked by plan."}),
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
        // The API above locates historical schemas; it is not an authored
        // dependency permission. Public bindings and drafts select resources.
        if base["surface"] != "api.response"
            && let Some(selector) = base["match"].as_object_mut()
        {
            selector.remove("api");
        }
        let identity = serde_json::to_string(&base)?;
        self.add_entry(identity, json!({"binding":base,"witness_id":witness,"needs_schema":codec.is_none(),"source_intent_required":true,
                "instruction":if codec.is_none(){"Encoded bytes do not identify a codec. Trace Source encoding; for PB provide explicit field_path, field_type and repeated before planning. Then choose Source-proven field semantics; the missing draft is not a capability verdict."}else if base["slot"].get("sse_data").is_some(){"Pointers address the SSE data JSON for this exact event/type. Declare output fields under responses. Prove time/duration/ordering semantics, or inventory an identity's eligible MySQL/Redis/response locations with one case-local binding and explicit prefix/format, including terminal output. Observed Source values define equality and distinctness only after Source authorizes those positions. Fixed inputs remain anchored. Event presence/order and unselected text stay strict. See docs/sse-value-contracts.md."}else{"Schema supplies decoding only. Reuse or extend the owning resources/responses field declaration from Source behavior: time format/relation, duration unit/branch, unordered consumer semantics or a proven eligible identity domain. Inventory all identity locations together; proof is required for each location. Native contextual effects retain their extra relationship or protocol behavior."}}));
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
            Codec::Scalar => vec![String::new()],
            Codec::Protobuf(codec) => codec.fields.keys().cloned().collect(),
        };
        self.collect(
            &source.comparison_value(&paths),
            &target.comparison_value(&paths),
            &values::JsonLocation::default(),
            &base,
            witness,
            clocks,
            0,
        )
    }
    #[allow(clippy::too_many_arguments)] // Native witnesses and physical-field suggestions share immutable context.
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
            let base = json!({"surface":witness.metadata.surface,"match":{
                "resource":witness.metadata.resource}});
            let physical = sql_fields::observed(event, witness.metadata.surface);
            let unavailable = physical["fields"].as_array().is_none_or(Vec::is_empty);
            let identity =
                serde_json::to_string(&(&base, &physical, &event["response"]["status"]))?;
            self.add_entry(identity, json!({"binding":base,"witness_id":witness.id,
                    "source_response_kind":event["response"]["status"],"physical_fields":physical,
                    "needs_sql_template":false,"needs_physical_binding":unavailable,"needs_slot":true,"needs_schema":true,"source_intent_required":true,
                    "instruction":"Inspect existing resource declarations, then declare physical database/table/column fields and an explicit scalar or JSON/PB codec from Source behavior. Choose time, duration, unordered or identity semantics where supported; no match.api, match.sql or value ordinal repeats the same field strategy. For identity, collect every eligible MySQL/Redis/response position and common case-local binding together. Mixed fixed/external IDs need expressible eligibility guards; otherwise retain the narrow native owner. Observed positions and physical tables are suggestions, not generation, codec or table-family proof; prove bounded table_series from Source construction. Unknown or ambiguous origins grant no permission. Use an explicit SQL template and field_ref only for additional native contextual relationships. Supply fresh Source proof."}));
            return Ok(());
        }
        let scope = rules
            .iter()
            .map(|rule| rule.rule.id.as_str())
            .collect::<BTreeSet<_>>();
        let database = witness
            .metadata
            .resource
            .as_ref()
            .and_then(|resource| resource.database.as_ref())
            .and_then(|database| database.name());
        for rule in &rules {
            let source_values = crate::replay::mysql_witness_values(
                source,
                witness.metadata.surface,
                rule,
                database,
            )?;
            let target_values = target
                .map(|bytes| {
                    crate::replay::mysql_witness_values(
                        bytes,
                        witness.metadata.surface,
                        rule,
                        database,
                    )
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
            &json!({"format":"traffic-policy/v2","rules":[first.clone(),second]}).to_string(),
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
        let document = serde_json::json!({"format":"traffic-policy/v2","rules":[{
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
                &values::JsonLocation::default(),
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
