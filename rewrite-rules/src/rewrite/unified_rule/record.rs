//! Revalidate an immutable plan and project its report.
use super::manifest::{ArtifactMethods, ExecutionIdentityMethods};
use super::{RewriteState, declaration_changes, impact, manifest, preflight::PreflightMethods};
use crate::{
    execution_identity as fingerprint,
    policy::{compile_policy, parse_policy},
};
use anyhow::{Result, ensure};
use serde_json::json;
use std::{fs, path::Path};
use traffic_rewrite_model::rewrite::UnifiedRulePlanRecord;

pub trait UnifiedRulePlanRecordMethods: Sized {
    fn is_batch(&self) -> bool;
    fn is_api_issue(&self) -> bool;
    fn applying(&self) -> bool;
    fn changed(&self) -> bool;
    fn ensure_policy_current(&self) -> Result<()>;
    fn ensure_policy_baseline(&self, root: &Path) -> Result<()>;
    fn ensure_current(&self, root: &Path, state: &RewriteState) -> Result<()>;
    fn report(&self, applied: bool) -> serde_json::Value;
}

impl UnifiedRulePlanRecordMethods for UnifiedRulePlanRecord {
    fn is_batch(&self) -> bool {
        self.identity.is_batch()
    }
    fn is_api_issue(&self) -> bool {
        self.identity.method_api().is_some()
    }
    fn applying(&self) -> bool {
        self.apply_started
    }

    fn changed(&self) -> bool {
        self.original != self.updated
    }

    fn ensure_policy_current(&self) -> Result<()> {
        let current = fs::read_to_string(&self.policy)?;
        ensure!(
            current == self.original || self.apply_started && current == self.updated,
            "policy changed after planning; recover the plan and run fresh Replay"
        );
        Ok(())
    }

    fn ensure_policy_baseline(&self, root: &Path) -> Result<()> {
        ensure!(
            fingerprint::policy_file(root)? == self.policy,
            "configured policy path changed after planning"
        );
        self.ensure_policy_current()
    }

    fn ensure_current(&self, root: &Path, state: &RewriteState) -> Result<()> {
        self.ensure_policy_baseline(root)?;
        for artifact in &self.artifacts {
            if artifact.path != self.policy {
                artifact.verify()?;
            }
        }
        ensure!(
            self.identity.revalidate(root, state)? == self.identity,
            "Target/Source/engine/attempt identity changed after planning"
        );
        let compiled = compile_policy(&parse_policy(&self.updated)?)?;
        self.source_proofs.verify(&compiled)?;
        self.preflight
            .ensure_current(root, &compiled, self.evidence_validation_started)?;
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
