//! Construct an immutable unified plan from admitted evidence and Source proofs.
use super::attribution::IdentityMethods;
use super::manifest::{ArtifactMethods, ExecutionIdentityMethods};
use super::preflight::PreflightMethods;
use super::source_proof;
use super::{
    RewriteState, attribution, batch, change, declarations, manifest, ownership, preflight,
    proposal, proposal_context,
};
use crate::execution_identity as fingerprint;
use crate::policy::{compile_policy, parse_policy};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use traffic_rewrite_model::rewrite::UnifiedRulePlanRecord;

#[derive(Debug, Clone)]
pub struct RewriteUnifiedRulePlanOptions {
    pub file: PathBuf,
    pub evidence_id: String,
}

pub fn build(
    root: &Path,
    state: &RewriteState,
    file: &Path,
    batch_scope: bool,
    attribution_scope: bool,
) -> Result<UnifiedRulePlanRecord> {
    let proposal = manifest::Artifact::capture(file)?;
    ensure!(
        proposal.length <= 1024 * 1024,
        "rule proposal exceeds 1 MiB"
    );
    let input = fs::read_to_string(file)?;
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
        ownership::proposal_context(&input, &document, state)?
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
        ownership::validate_proposal(proposed)?;
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
        ownership::validate_change(&before, &compiled)?;
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
    Ok(UnifiedRulePlanRecord {
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
        evidence_validation_started: None,
    })
}
