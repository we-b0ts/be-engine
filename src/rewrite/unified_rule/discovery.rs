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
mod headers;
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
        "source_entry":{"location_count":drafts.entry_ids.len(),"summary_omitted":drafts.entry_ids.len().saturating_sub(drafts.entries.len()),"locations":drafts.entries,"requires":["one global json.fields declaration per logical pointer, independent of its API or storage carrier", "Source-proven time/identity formats or unordered semantics; JSON payloads are recognized automatically", "mysql.tables scalar declarations only when native type inference is insufficient; PB requires a known numeric schema", "exact null/empty/sentinel behavior and additional native relationships where needed"],
            "identity_inventory":{"scope":"case","relationship":"bijective_renaming","requires":["identity formats at global JSON pointers or explicit MySQL scalar columns", "Source-equal complete typed IDs must remain Target-equal across supported carriers", "different Source IDs cannot collapse into one Target ID", "fixed inputs and successful read delivery retain their anchors"],"observations_define_relations":true,"automatic_permission":false},
            "instruction":"Inspect root json.fields for JSON values, http.headers for headers, mysql.tables for native scalar columns and redis.keys for scalar cache values. Declare formats once without API-scoped duplicates. The engine infers complete typed identity correspondence internally. Native rules retain additional causal relationships and protocol/stateful behavior. Draft discovery is bounded and never coverage."},
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
        _schemas: Option<&CompiledPolicy>,
        _sql_scope: Option<&BTreeSet<&str>>,
    ) -> Result<()> {
        let codec = crate::json_value::parse(source)
            .is_some()
            .then_some(Codec::Json);
        if let Some(codec) = &codec {
            base["codec"] = serde_json::to_value(codec)?;
        }
        // Observation positions locate immutable evidence. They do not scope
        // the authored global content format.
        if base["surface"] != "api.response"
            && let Some(selector) = base["match"].as_object_mut()
        {
            selector.remove("api");
        }
        let identity = serde_json::to_string(&base)?;
        self.add_entry(identity, json!({"location":base,"witness_id":witness,"needs_schema":codec.is_none(),"source_intent_required":true,
                "instruction":if codec.is_none(){"Unrecognized Source encoding compares exact bytes. A missing codec draft does not require a new protocol declaration. Known PB schemas can expose typed fields through explicit numeric paths and types when semantic comparison is needed; unknown wire data stays exact."}else if base["slot"].get("sse_data").is_some(){"Pointers address the SSE data JSON. Declare their formats once under global json.fields, shared with ordinary responses and storage payloads. The engine preserves equal complete typed Source IDs as equal Target IDs internally; rules only declare identity formats. Fixed inputs remain anchored. Event presence/order, envelopes and unselected text stay strict. See docs/sse-value-contracts.md."}else{"Decoding alone does not authorize content changes. Reuse or extend global json.fields with Source-proven time or identity formats and unordered semantics. JSON carriers need no repeated codec declaration. Identity correspondence follows complete typed Source values internally. Native contextual effects retain additional relationships and protocol behavior."}}));
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
        let _ = (source, target, state, schemas);
        let base = json!({"surface":witness.metadata.surface,"match":{
            "resource":witness.metadata.resource}});
        let physical = sql_fields::observed(event, witness.metadata.surface);
        let unavailable = physical["fields"].as_array().is_none_or(Vec::is_empty);
        let identity = serde_json::to_string(&(&base, &physical, &event["response"]["status"]))?;
        self.add_entry(identity,json!({"location":base,"witness_id":witness.id,
            "source_response_kind":event["response"]["status"],"physical_fields":physical,
            "needs_sql_template":false,"needs_physical_location":unavailable,"needs_schema":false,
            "source_intent_required":true,
            "instruction":"MySQL JSON payloads use root json.fields automatically. Native DATE/DATETIME/TIMESTAMP metadata is inferred when mysql is enabled; historical and invalid scalar inputs stay exact unless a valid differing value is proved. mysql.tables declares remaining scalar formats across databases; recorded and Target physical connection identities must still match. Table patterns contain table names, without a database prefix. No JSON column codec or SQL statement template is needed. Unknown physical origins grant no scalar permission."}));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_wire_encoding_has_no_legacy_schema_draft() {
        let mut drafts = Drafts::default();
        drafts
            .observe(
                b"opaque",
                Some(b"different"),
                json!({"surface":"api.response","slot":"body"}),
                "witness",
                AnchorClocks::default(),
                None,
                None,
            )
            .unwrap();
        assert!(drafts.values.is_empty());
        assert_eq!(drafts.entries[0]["needs_schema"], true);
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
            drafts.values[0]["draft_policy"]["json"]["fields"]["/members"]["kind"],
            "unordered"
        );
        assert_eq!(drafts.values[0]["plan_ready"], false);
        assert_eq!(
            drafts.values[0]["draft_policy"]["format"],
            "traffic-policy/v2"
        );
    }
}
