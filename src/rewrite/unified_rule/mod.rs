//! Source-proven new-format rule transactions under the existing coordinator.
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    RewriteContext, action, evidence, fingerprint, inventory,
    model::{RewriteIssueKind, RewriteRulePlanRecord, RewriteRuleReport, RewriteState},
    store::RewriteStore,
};
use crate::policy::{PolicyRule, TrafficPolicy, compile_policy, parse_policy};

pub(in crate::rewrite) mod attribution;
pub(super) mod batch;
mod change;
mod declaration_changes;
mod declarations;
pub(super) mod discovery;
mod manifest;
mod preflight;
pub(super) use preflight::dependency::{
    source_witness as dependency_source_witness, values as dependency_witness_values,
};
mod impact;
mod proposal;
mod proposal_context;
mod source_proof;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct RewriteUnifiedRulePlanOptions {
    pub file: PathBuf,
    pub evidence_id: String,
}

fn parse_proposal(input: &str) -> Result<TrafficPolicy> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedRulePlanRecord {
    #[serde(default)]
    apply_started: bool,
    policy: PathBuf,
    original: String,
    updated: String,
    identity: manifest::ExecutionIdentity,
    artifacts: Vec<manifest::Artifact>,
    preflight: preflight::Preflight,
    rule_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    replaced_rules: Vec<PolicyRule>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    replace_sections: BTreeSet<String>,
    source_proofs: source_proof::SourceProofSnapshot,
    #[serde(default)]
    target_replay_drift_at_plan: bool,
}

pub fn plan_rewrite_unified_rule(
    context: RewriteContext,
    options: RewriteUnifiedRulePlanOptions,
) -> Result<RewriteRuleReport> {
    if attribution::matches(&options.evidence_id) {
        return attribution::plan(context, options);
    }
    if batch::matches(&options.evidence_id) {
        return batch::plan(context, options);
    }
    let (root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_rule_evidence_id(&root, &state, &options.evidence_id)?;
    let _scope = super::rule_plans::events::lock_api(&root, &api)?;
    super::rule_plans::events::ensure_not_replaying(&root, &api)?;
    // Planning publishes an independent event, never a replacement of the
    // coordinator's in-flight snapshot. Other APIs may keep replaying.
    let expected = inventory::scoped(&state, Some(&api.parse()?))?;
    let report =
        inventory::with_slice_mut(&mut state, &api, |state| plan(&root, state, options, false))?;
    let record = inventory::scoped(&state, Some(&api.parse()?))?
        .rule_plan
        .clone()
        .context("planner did not produce a rule plan")?;
    super::rule_plans::events::publish(&root, &expected, record)?;
    Ok(report)
}

fn plan(
    root: &Path,
    state: &mut RewriteState,
    options: RewriteUnifiedRulePlanOptions,
    batch_scope: bool,
) -> Result<RewriteRuleReport> {
    let attribution_scope = attribution::matches(&options.evidence_id);
    let issue_id = if batch_scope || attribution_scope {
        options.evidence_id.clone()
    } else {
        let issue = state
            .active_issue
            .as_ref()
            .context("rule plan requires an active issue")?;
        ensure!(
            matches!(
                issue.kind,
                RewriteIssueKind::Response
                    | RewriteIssueKind::Dependency
                    | RewriteIssueKind::Replay
            ),
            "unified value rules require response or dependency evidence"
        );
        let evidence = evidence::report_for_id(root, state, &options.evidence_id)
            .context("rule evidence is stale or unavailable")?;
        evidence::policy_freshness::ensure_plannable(&evidence)?;
        issue.id.clone()
    };
    if let Some(record) = state.rule_plan.as_ref().and_then(|p| p.unified.as_ref()) {
        record.ensure_current(root, state)?;
    }
    let proposal = manifest::Artifact::capture(&options.file)?;
    ensure!(
        proposal.length <= 1024 * 1024,
        "rule proposal exceeds 1 MiB"
    );
    let input = fs::read_to_string(&options.file)?;
    ensure!(
        crate::policy_evidence::digest(input.as_bytes()) == proposal.sha256,
        "rule proposal changed while loading"
    );
    let (_, config) = crate::e2e_run::resolve_project(root)?;
    let original = fs::read_to_string(&config.replay_policy)?;
    let mut document = parse_policy(&original).context(
        "unified authoring requires a traffic-policy/v3 policy; no legacy fallback is used",
    )?;
    let resolved = if attribution_scope {
        attribution::proposal_context(&input, &document, state)?
    } else {
        proposal_context::resolve(&input, &document)?
    };
    source_proof::validate_proposal(&resolved.input)?;
    let mut change = change::parse(&resolved.input)?;
    ensure!(
        !attribution_scope || !change.explicit_time,
        "Source attribution evidence cannot change time settings"
    );
    ensure!(
        !change.explicit_time
            || change.replace_sections.contains("time")
            || change.policy.time == document.time,
        "changing time settings requires an explicit replace_sections: [time] proposal"
    );
    crate::policy::require_source_proofs(&change.policy)?;
    let proposed = &mut change.policy;
    ensure!(
        !proposed.rules.is_empty()
            || change.explicit_time
            || resolved.explicit_resources && !proposed.resources.is_empty()
            || proposed.json.is_some()
            || proposed.mysql.is_some()
            || proposed.redis.is_some()
            || proposed.http.is_some()
            || proposed.async_api.is_some(),
        "policy proposal must contain time settings, JSON/MySQL/Redis/HTTP formats, async capture, endpoint aliases or native rules"
    );
    let before = compile_policy(&document)?;
    if attribution_scope {
        attribution::validate_proposal(proposed)?;
    } else if batch_scope {
        batch::validate_proposal(proposed)?;
    } else {
        proposal::prepare_scopes(proposed, &document, &state.api)?;
    }
    if attribution_scope {
        ensure!(
            proposed.source_revision.as_deref() == state.source_revision.as_deref(),
            "Source ownership proposal belongs to another workflow Source revision"
        );
    } else if let Some(revision) = &document.source_revision {
        ensure!(
            proposed
                .source_revision
                .as_ref()
                .is_none_or(|r| r == revision),
            "proposal Source revision conflicts with the active policy"
        );
        proposed.source_revision = Some(revision.clone());
        *proposed = crate::policy::expand_policy(proposed)?;
    }
    let mut rule_ids = crate::policy::effective_rules(proposed)?
        .iter()
        .map(|r| r.id().to_owned())
        .collect::<BTreeSet<_>>();
    if proposed.json.is_some() {
        rule_ids.insert(crate::policy::GLOBAL_JSON_ID.into());
    }
    if proposed.mysql.is_some() {
        rule_ids.insert("global.mysql".into());
    }
    if proposed.redis.is_some() {
        rule_ids.insert("global.redis".into());
    }
    if proposed.http.is_some() {
        rule_ids.insert(crate::policy::GLOBAL_HTTP_ID.into());
    }
    if proposed.async_api.is_some() {
        rule_ids.insert(crate::policy::ASYNC_API_ID.into());
    }
    let source_proofs = source_proof::SourceProofSnapshot::capture(proposed)?;
    let replaced_rules = change.remove_from(&mut document, &state.api)?;
    let declarations_changed = declarations::merge_with_replacements(
        &mut document,
        &change.policy,
        &change.replace_sections,
    )?;
    let rules_changed = proposal::merge(&mut document, change.policy.rules)?;
    let changed = declarations_changed || rules_changed || !replaced_rules.is_empty();
    let compiled = compile_policy(&document)?;
    if attribution_scope {
        attribution::validate_change(&before, &compiled)?;
    }
    rule_ids.extend(
        compiled
            .rules
            .iter()
            .filter(|rule| !before.rules.iter().any(|old| old == *rule))
            .map(|rule| rule.rule.id.clone()),
    );
    rule_ids.extend(
        compiled
            .native
            .iter()
            .filter(|rule| !before.native.iter().any(|old| old == *rule))
            .map(|rule| rule.rule.id.clone()),
    );
    if compiled.async_api != before.async_api {
        rule_ids.insert(crate::policy::ASYNC_API_ID.into());
    }
    for (id, unchanged) in [
        (
            crate::policy::GLOBAL_JSON_ID,
            compiled.global_json == before.global_json,
        ),
        ("global.mysql", compiled.mysql == before.mysql),
        ("global.redis", compiled.redis == before.redis),
        (crate::policy::GLOBAL_HTTP_ID, compiled.http == before.http),
        (
            crate::policy::ASYNC_API_ID,
            compiled.async_api == before.async_api,
        ),
    ] {
        if unchanged {
            rule_ids.remove(id);
        }
    }
    let current = crate::validate_replay_policy(&config.replay_policy)?;
    let allows_target_drift = !batch_scope && !attribution_scope;
    let target_replay_drift_at_plan = allows_target_drift
        && state.replay_identity.as_ref() != Some(&fingerprint::replay_identity(root)?);
    let identity = if attribution_scope {
        manifest::ExecutionIdentity::Attribution(attribution::Identity::current(state)?)
    } else if batch_scope {
        manifest::ExecutionIdentity::batch_current(root, state)?
    } else {
        manifest::ExecutionIdentity::current(root, state, allows_target_drift)?
    };
    let mut bundle = match &identity {
        manifest::ExecutionIdentity::Attribution(actual) => {
            manifest::Bundle::load_attribution(&actual.case_source)?
        }
        manifest::ExecutionIdentity::Batch(actual) => {
            manifest::Bundle::load_batch(&actual.evidence, &current.fingerprint)?
        }
        _ => manifest::Bundle::load(root, state, &current.fingerprint, &before, &compiled)?,
    };
    let preflight = if attribution_scope {
        preflight::verify_attribution(root, state, &mut bundle, &before, &compiled, &rule_ids)?
    } else {
        preflight::verify(root, state, &mut bundle, &before, &compiled, &rule_ids)?
    };
    ensure!(
        !batch_scope || !preflight.needs_recording() || !preflight.capture_scopes.is_empty(),
        "unsupported batch capture change without a proven origin capture scope; provide an exact supported origin capture declaration instead of borrowing the API transaction anchor"
    );
    bundle.artifacts.insert(proposal.path.clone(), proposal);
    let updated = if changed {
        crate::policy::render_policy(&document)?
    } else {
        original.clone()
    };
    let record = UnifiedRulePlanRecord {
        apply_started: false,
        policy: config.replay_policy,
        original,
        updated,
        identity,
        artifacts: bundle.artifacts.into_values().collect(),
        preflight,
        rule_ids,
        replaced_rules,
        replace_sections: change.replace_sections,
        source_proofs,
        target_replay_drift_at_plan,
    };
    let id = format!(
        "plan-{}",
        fingerprint::id(&[
            &state.workflow_id,
            &issue_id,
            &options.evidence_id,
            &serde_json::to_string(&record)?
        ])
        .trim_start_matches("fnv1a64:")
    );
    let traffic_e2e_report = record.report(false);
    let outer: RewriteRulePlanRecord = serde_json::from_value(json!({
        "id":id, "issue_id":issue_id, "kind":"unified", "json_pointer":"",
        "evidence_id":options.evidence_id, "unified":record,
    }))?;
    state.rule_plan = Some(outer);
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: id.clone(),
        issue_id,
        traffic_e2e_report,
        next_command: action::rule_apply_command(root, &id),
    })
}

impl UnifiedRulePlanRecord {
    pub(in crate::rewrite) fn is_batch(&self) -> bool {
        self.identity.is_batch()
    }
    pub(in crate::rewrite) fn is_api_issue(&self) -> bool {
        self.identity.method_api().is_some()
    }
    pub(super) fn applying(&self) -> bool {
        self.apply_started
    }

    pub(super) fn changed(&self) -> bool {
        self.original != self.updated
    }

    pub(super) fn ensure_policy_current(&self) -> Result<()> {
        let current = fs::read_to_string(&self.policy)?;
        ensure!(
            current == self.original || self.apply_started && current == self.updated,
            "policy changed after planning; recover the plan and run fresh Replay"
        );
        Ok(())
    }

    pub(super) fn ensure_policy_baseline(&self, root: &Path) -> Result<()> {
        ensure!(
            fingerprint::policy_file(root)? == self.policy,
            "configured policy path changed after planning"
        );
        self.ensure_policy_current()
    }

    fn ensure_current(&self, root: &Path, state: &RewriteState) -> Result<()> {
        self.ensure_policy_baseline(root)?;
        ensure!(
            self.identity.revalidate(root, state)? == self.identity,
            "Target/Source/engine/attempt identity changed after planning"
        );
        for artifact in &self.artifacts {
            if artifact.path != self.policy {
                artifact.verify()?;
            }
        }
        let compiled = compile_policy(&parse_policy(&self.updated)?)?;
        self.source_proofs.verify(&compiled)?;
        self.preflight.ensure_current(root, &compiled)?;
        Ok(())
    }

    fn report(&self, applied: bool) -> serde_json::Value {
        let replay_required = self.changed()
            && self.identity.method_api().is_none_or(|api| {
                impact::affects_api(&self.original, &self.updated, api).unwrap_or(true)
            });
        let attribution_required = self.changed()
            && self
                .preflight
                .obligations
                .contains(&crate::config::native_policy::SourceObligation::AttributionReview);
        let updated = parse_policy(&self.updated).ok();
        let expanded = updated
            .as_ref()
            .and_then(|policy| compile_policy(policy).ok());
        let rules = updated
            .as_ref()
            .and_then(|policy| crate::policy::effective_rules(policy).ok())
            .map(|rules| {
                rules
                    .into_iter()
                    .filter(|r| self.rule_ids.contains(r.id()))
                    .collect::<Vec<_>>()
            });
        let declaration_changes = parse_policy(&self.original)
            .ok()
            .zip(updated.as_ref())
            .map(|(before, after)| {
                declaration_changes::summarize(&before, after, &self.replace_sections)
            })
            .unwrap_or_else(|| json!({}));
        json!({"kind":"unified", "status":if !self.changed() && applied {"applied_no_change"} else if !self.changed() {"planned_no_change"} else if applied && self.preflight.needs_recording() {"applied_pending_recording"} else if applied && replay_required {"applied_pending_replay"} else if applied && attribution_required {"applied_pending_attribution"} else if applied {"applied_pending_scoped_verification"} else if attribution_required && !replay_required {"planned_requires_attribution_review"} else {self.preflight.status()},
            "applied":applied, "changed":self.original != self.updated,
            "rule_ids":self.rule_ids, "replaced_rules":self.replaced_rules, "preflight":self.preflight,
            "replace_sections":self.replace_sections,
            "requires_fresh_replay":replay_required, "replay_scope":if self.is_batch(){json!({"kind":"complete_source_run"})}else if !self.is_api_issue(){json!({"kind":"affected_owner_scopes"})}else{json!(self.identity.method_api())},
            "evidence_scope":self.identity,
            "target_replay_drift_at_plan":self.target_replay_drift_at_plan,
            "requires_attribution_review":attribution_required,
            "requires_fresh_recording":self.changed() && self.preflight.needs_recording(), "verified":false,
            "policy":self.policy, "evidence_artifacts":self.artifacts.len(), "source_proofs":self.source_proofs,
            "expanded_rules":rules, "time":updated.as_ref().map(|p| &p.time), "json":expanded.as_ref().and_then(|p| p.global_json.as_ref()), "mysql":expanded.as_ref().and_then(|p|p.mysql.as_ref()), "redis":expanded.as_ref().and_then(|p|p.redis.as_ref()), "http":expanded.as_ref().and_then(|p|p.http.as_ref()), "async_api":expanded.as_ref().map(|p| &p.async_api), "effect_identity":expanded.as_ref().map(|p| &p.fingerprints),
            "declaration_changes":declaration_changes,
            "checks":{"full_source_inventory":true,"immutable_attempt_and_witnesses":!matches!(self.identity,manifest::ExecutionIdentity::Attribution(_)),"policy_compare_and_swap":true,
                "source_field_types":true,"unselected_fields_and_arguments":true,"independent_and_derived_roles_separate":true},
            "diff":crate::config::rule_document::whole_file_diff(&self.policy, &self.original, &self.updated),
            "does_not_prove":"Offline Source validation or derived delivery is not independent Target behavior or successful genuine Replay."})
    }
}

pub(super) fn apply(
    root: &Path,
    state: &mut RewriteState,
    outer: RewriteRulePlanRecord,
) -> Result<RewriteRuleReport> {
    let record = outer
        .unified
        .as_ref()
        .context("pending plan has no unified contract")?;
    ensure!(
        record.apply_started,
        "unified apply requires the durable coordinator intent"
    );
    record.ensure_current(root, state)?;
    let previous_execution = super::fingerprint::replay_identity(root)?;
    crate::config::edit::write_atomic(&record.policy, record.updated.as_bytes())?;
    let mut report = record.report(true);
    if record.is_api_issue() {
        report["target_replay_drift_at_apply"] =
            json!(state.replay_identity.as_ref() != Some(&previous_execution));
    }
    state.rule_plan = None;
    if record.original != record.updated {
        if record.is_batch() {
            batch::request_replay(state, &record.original, &record.updated, &outer.id)?;
        } else {
            impact::request_replays(state, &record.original, &record.updated, &outer.id)?;
        }
        if record
            .preflight
            .obligations
            .contains(&crate::config::native_policy::SourceObligation::AttributionReview)
        {
            state.dependency_review.recording_run_id = None;
            state.dependency_review.revision += 1;
        }
        if record.is_api_issue()
            && impact::affects_api(&record.original, &record.updated, &state.api)?
        {
            super::rule_replay::request(state);
        }
        impact::rebase_unchanged(
            root,
            state,
            &record.original,
            &record.updated,
            &previous_execution,
        )?;
        super::dependency_review::refresh_receipts(root, state)?;
        if record.preflight.needs_recording() {
            let mut scopes = record.preflight.capture_scopes.clone();
            if scopes.is_empty() {
                scopes.insert(
                    state.api.clone(),
                    record.source_proofs.summary(&record.rule_ids),
                );
            }
            super::verification_obligations::request_capture(state, &scopes, &outer.id)?;
        }
    }
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: outer.id,
        issue_id: outer.issue_id,
        traffic_e2e_report: report,
        next_command: action::next_command(root),
    })
}

/// Persist this marker with RewriteStore before changing the policy. A crash
/// after the write can recognize the exact authorized updated bytes on retry.
pub(super) fn begin_apply(
    root: &Path,
    state: &mut RewriteState,
    plan_id: &str,
) -> Result<UnifiedRulePlanRecord> {
    let mut record = super::rule::pending_plan_for_apply(state, plan_id)?
        .unified
        .context("pending unified rule plan unavailable")?;
    record.ensure_current(root, state).with_context(|| {
        format!("rule plan {plan_id} failed revalidation; use `backend-rewrite rule recover {plan_id}` to retire stale evidence")
    })?;
    record.apply_started = true;
    state.rule_plan.as_mut().unwrap().unified = Some(record.clone());
    if record.original != record.updated
        && record.is_api_issue()
        && impact::affects_api(&record.original, &record.updated, &state.api)?
    {
        super::rule_replay::request(state);
    }
    Ok(record)
}

pub(super) fn rollback(record: &UnifiedRulePlanRecord) -> Result<()> {
    let current = fs::read_to_string(&record.policy)?;
    if current == record.original {
        return Ok(());
    }
    ensure!(
        current == record.updated,
        "cannot roll back policy changed by another writer; retain the durable pending apply intent"
    );
    crate::config::edit::write_atomic(&record.policy, record.original.as_bytes())
}

pub(super) fn stale(root: &Path, state: &RewriteState, record: &UnifiedRulePlanRecord) -> bool {
    record.ensure_current(root, state).is_err()
}
