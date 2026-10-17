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
    worker,
};
use crate::policy::{PolicyRule, TrafficPolicy, compile_policy, parse_policy};

pub(super) mod discovery;
mod manifest;
mod preflight;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct RewriteUnifiedRulePlanOptions {
    pub file: PathBuf,
    pub evidence_id: String,
}

fn parse_proposal(input: &str) -> Result<TrafficPolicy> {
    let value: serde_yaml::Value = serde_yaml::from_str(input)
        .context("expected a rule, rule list, or traffic-policy/v1 document")?;
    let document = if value.get("rules").is_some() || value.get("format").is_some() {
        serde_yaml::from_value::<TrafficPolicy>(value)
            .context("invalid traffic-policy/v1 proposal")?
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
}

pub fn plan_rewrite_unified_rule(
    context: RewriteContext,
    options: RewriteUnifiedRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let (root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_evidence_id(&root, &state, &options.evidence_id)
        .context("rule evidence is stale or belongs to no concurrent API work item")?;
    let _scope = super::rule_plans::events::lock_api(&root, &api)?;
    super::rule_plans::events::ensure_not_replaying(&root, &api)?;
    // Planning publishes an independent event, never a replacement of the
    // coordinator's in-flight snapshot. Other APIs may keep replaying.
    let expected = inventory::scoped(&state, Some(&api.parse()?))?;
    worker::ensure_api_confirmed(&state, &api, "planning a unified traffic rule")?;
    let report = inventory::with_slice_mut(&mut state, &api, |state| plan(&root, state, options))?;
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
) -> Result<RewriteRuleReport> {
    let issue = state
        .active_issue
        .as_ref()
        .context("rule plan requires an active issue")?;
    ensure!(
        matches!(
            issue.kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        ),
        "unified value rules require response or dependency evidence"
    );
    for command in evidence::commands(root, state) {
        if let Ok(report) = evidence::query(root, state, &command.query_id)
            && report.evidence_id == options.evidence_id
        {
            evidence::policy_freshness::ensure_plannable(&report)?;
            break;
        }
    }
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
    let mut proposed = parse_proposal(&input)?;
    ensure!(
        !proposed.rules.is_empty(),
        "rule proposal must contain explicit Source-proven rules"
    );
    for proposal in &mut proposed.rules {
        match proposal {
            PolicyRule::Value(rule) => {
                if let Some(api) = &rule.selector.api {
                    ensure!(
                        api == &state.api,
                        "rule plan must retain the exact active prepared API scope"
                    );
                } else {
                    rule.selector.api = Some(state.api.clone());
                }
            }
            PolicyRule::Native(rule) => {
                if let Some(api) = &rule.selector.api {
                    ensure!(
                        api == &state.api,
                        "native rule plan must retain the exact active prepared API scope"
                    );
                }
                // Global acquisition/ownership/sharing effects retain the empty
                // outer selector required by their typed domain compiler.
            }
        }
    }
    let (_, config) = crate::e2e_run::resolve_project(root)?;
    let original = fs::read_to_string(&config.replay_policy)?;
    let mut document = parse_policy(&original).context(
        "unified authoring requires a traffic-policy/v1 policy; no legacy fallback is used",
    )?;
    if let Some(revision) = &document.source_revision {
        ensure!(
            proposed
                .source_revision
                .as_ref()
                .is_none_or(|r| r == revision),
            "proposal Source revision conflicts with the active policy"
        );
        proposed.source_revision = Some(revision.clone());
        proposed = crate::policy::expand_policy(&proposed)?;
    }
    let rule_ids = proposed
        .rules
        .iter()
        .map(|r| r.id().to_owned())
        .collect::<BTreeSet<_>>();
    let mut changed = false;
    for rule in proposed.rules {
        ensure!(
            document
                .rules
                .iter()
                .find(|current| current.id() == rule.id())
                .is_none_or(|current| current == &rule),
            "existing rule ID changes scope, effect, contract or proof; use a new explicitly reviewed rule ID"
        );
        if document.rules.iter().any(|current| current == &rule) {
            continue;
        }
        document.rules.push(rule);
        changed = true;
    }
    let compiled = compile_policy(&document)?;
    let current = crate::validate_replay_policy(&config.replay_policy)?;
    ensure!(
        state.replay_identity.as_ref() == Some(&fingerprint::replay_identity(root)?),
        "Target code, startup inputs or policy changed since genuine Replay; run fresh Replay before planning"
    );
    let identity = manifest::ExecutionIdentity::current(root, state)?;
    let mut bundle = manifest::Bundle::load(root, state, &current.fingerprint)?;
    let preflight = preflight::verify(root, state, &mut bundle, &compiled, &rule_ids)?;
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
    };
    let id = format!(
        "plan-{}",
        fingerprint::id(&[
            &state.workflow_id,
            &issue.id,
            &options.evidence_id,
            &serde_json::to_string(&record)?
        ])
        .trim_start_matches("fnv1a64:")
    );
    let issue_id = issue.id.clone();
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

    fn ensure_current(&self, root: &Path, state: &RewriteState) -> Result<()> {
        self.ensure_policy_current()?;
        ensure!(
            manifest::ExecutionIdentity::current(root, state)? == self.identity,
            "Target/Source/engine/attempt identity changed after planning"
        );
        for artifact in &self.artifacts {
            if artifact.path != self.policy {
                artifact.verify()?;
            }
        }
        let compiled = compile_policy(&parse_policy(&self.updated)?)?;
        self.preflight.ensure_current(root, &compiled)?;
        Ok(())
    }

    fn report(&self, applied: bool) -> serde_json::Value {
        let expanded = parse_policy(&self.updated)
            .and_then(|p| compile_policy(&p))
            .ok();
        let rules = parse_policy(&self.updated).ok().map(|p| {
            p.rules
                .into_iter()
                .filter(|r| self.rule_ids.contains(r.id()))
                .collect::<Vec<_>>()
        });
        json!({"kind":"unified", "status":if !self.changed() && applied {"applied_no_change"} else if !self.changed() {"planned_no_change"} else if applied && self.preflight.needs_recording() {"applied_pending_recording"} else if applied {"applied_pending_replay"} else {self.preflight.status()},
            "applied":applied, "changed":self.original != self.updated,
            "rule_ids":self.rule_ids, "preflight":self.preflight,
            "requires_fresh_replay":self.changed(), "requires_fresh_recording":self.changed() && self.preflight.needs_recording(), "verified":false,
            "policy":self.policy, "evidence_artifacts":self.artifacts.len(),
            "expanded_rules":rules, "effect_identity":expanded.as_ref().map(|p| &p.fingerprints),
            "checks":{"full_source_inventory":true,"immutable_attempt_and_witnesses":true,"policy_compare_and_swap":true,
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
    worker::ensure_api_confirmed(state, &state.api, "applying a unified traffic rule")?;
    let record = outer
        .unified
        .as_ref()
        .context("pending plan has no unified contract")?;
    ensure!(
        record.apply_started,
        "unified apply requires the durable coordinator intent"
    );
    record.ensure_current(root, state)?;
    crate::config::edit::write_atomic(&record.policy, record.updated.as_bytes())?;
    let report = record.report(true);
    state.rule_plan = None;
    if record.original != record.updated {
        super::rule_replay::request(state);
        if record.preflight.needs_recording() {
            let policy = parse_policy(&record.updated)?;
            let proof = policy
                .rules
                .iter()
                .filter(|rule| record.rule_ids.contains(rule.id()))
                .map(|rule| format!("{}: {}", rule.proof().source, rule.proof().fact))
                .collect::<Vec<_>>()
                .join("\n");
            super::dependency_rule::schedule_cache_snapshot_refresh(
                root,
                state,
                super::model::RewriteDependencyRuleAppliedRecord {
                    plan_id: outer.id.clone(),
                    issue_id: outer.issue_id.clone(),
                    evidence_id: outer.evidence_id.clone(),
                    api: state.api.clone(),
                    rule_name: record
                        .rule_ids
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    source_evidence: proof,
                },
            )?;
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
pub(super) fn begin_apply(root: &Path, state: &mut RewriteState) -> Result<UnifiedRulePlanRecord> {
    let record = state
        .rule_plan
        .as_ref()
        .and_then(|p| p.unified.as_ref())
        .context("pending unified rule plan unavailable")?;
    record.ensure_current(root, state)?;
    let mut record = record.clone();
    record.apply_started = true;
    state.rule_plan.as_mut().unwrap().unified = Some(record.clone());
    if record.original != record.updated {
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

pub(super) fn invalidate_global(state: &mut RewriteState) {
    for slice in std::iter::once(&mut state.active_slice).chain(state.parked_slices.values_mut()) {
        slice.e2e_current = false;
        slice.target_fingerprint = None;
    }
    for api in &mut state.api_inventory {
        api.e2e_current = false;
        api.verified_target_fingerprint = None;
    }
}
