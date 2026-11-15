//! Engine-issued acceptance reuses real execution without inventing consumption.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path};
use uuid::Uuid;

use super::{model::AcceptanceReceipt, source};
use crate::dependency::attribution::DependencyOwner;
use crate::rewrite::model::{RewriteApiStatus, RewritePhase, RewriteState};

pub(super) struct ActualAttempt {
    pub attempt: u64,
    pub execution_identity: String,
    pub report_sha256: String,
    pub session_id: String,
    pub unused: BTreeSet<Uuid>,
    report: Value,
}

impl ActualAttempt {
    pub(super) fn missing_sequences(&self, source: &source::SourceSnapshot) -> BTreeSet<Uuid> {
        let sequences: BTreeSet<_> = self.report["dependency_sequence_missing"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|missing| missing["expected"]["dependency_sequence"].as_u64())
            .collect();
        source
            .exchanges
            .iter()
            .filter(|(id, exchange)| {
                self.unused.contains(*id) && sequences.contains(&exchange.capture.sequence)
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

pub(super) fn actual(
    root: &Path,
    state: &RewriteState,
    source: &source::SourceSnapshot,
) -> Result<ActualAttempt> {
    ensure!(
        state
            .attempts
            .last()
            .is_some_and(|attempt| attempt.engine_fingerprint.as_deref()
                == Some(crate::build_info::ENGINE_FINGERPRINT)),
        "attribution acceptance requires an actual attempt from the current engine build"
    );
    ensure!(
        state
            .attempts
            .last()
            .is_some_and(super::super::replay_admission::dependency_only),
        "unused attribution acceptance requires passing responses and complete actual Replay with dependency-only failures"
    );
    claim_actual(root, state, source)
}

/// Reporting disputed ownership requires real unused evidence, not a passing
/// response or an implementer's proof of who actually owns the occurrence.
pub(super) fn claim_actual(
    root: &Path,
    state: &RewriteState,
    source: &source::SourceSnapshot,
) -> Result<ActualAttempt> {
    let attempt = state
        .attempts
        .last()
        .context("API has no real Replay attempt")?;
    let execution_identity = super::super::fingerprint::replay_identity(root)?;
    ensure!(
        state.replay_identity.as_deref() == Some(&execution_identity),
        "Target inputs or runtime contract changed since real Replay"
    );
    let context = crate::E2eRunContext {
        target_root: root.into(),
        case_source: state.case_source.clone().context("Source absent")?,
        run_key: None,
    };
    let group = state
        .group_id
        .as_deref()
        .context("focused API group absent")?;
    let summary = crate::e2e_run::finalized_focused_attempt_summary(context.clone(), group)?;
    ensure!(
        summary.attempt == attempt.attempt,
        "unused evidence belongs to another attempt"
    );
    let evidence = crate::e2e_run::resolve_e2e_response_rule_evidence(context, group)?;
    let bytes = fs::read(&evidence.replay)?;
    let mut report: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        report["finalized"] == true && report["active_case_id"].is_null(),
        "attribution requires finalized real Replay evidence"
    );
    filter_cases(&mut report, &summary.selected_case_ids);
    let unused = source::unused(source, &report, &summary.selected_case_ids)?;
    Ok(ActualAttempt {
        attempt: attempt.attempt,
        execution_identity,
        report_sha256: source::digest(&bytes),
        session_id: report["session_id"]
            .as_str()
            .context("Replay session identity absent")?
            .into(),
        unused,
        report,
    })
}

pub(super) fn filter_cases(value: &mut Value, selected: &BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for value in fields.values_mut() {
                filter_cases(value, selected);
            }
        }
        Value::Array(values) => {
            values.retain(|event| {
                event["case_id"]
                    .as_str()
                    .is_none_or(|case| selected.contains(case))
            });
            for value in values {
                filter_cases(value, selected);
            }
        }
        _ => {}
    }
}

fn foreign_owner(source: &source::SourceSnapshot, owner: &DependencyOwner, api: &str) -> bool {
    match owner {
        DependencyOwner::Case { origin_case_id, .. } => {
            source.apis.get(origin_case_id).is_some_and(|owner| {
                crate::rewrite::api_selector::public_api(owner)
                    != crate::rewrite::api_selector::public_api(api)
            })
        }
        DependencyOwner::Process { .. } | DependencyOwner::Startup { .. } => true,
        DependencyOwner::Shutdown { .. } | DependencyOwner::Unattributed { .. } => false,
    }
}

fn project_unused(
    value: &mut Value,
    source: &source::SourceSnapshot,
    excluded: &BTreeSet<Uuid>,
    protocol: &str,
) -> Result<()> {
    let Some(fields) = value.as_object_mut() else {
        return Ok(());
    };
    for (field, child) in fields {
        if field == "unused_case"
            || field == "unused_case_exchanges"
            || field == "unused_case_http_exchanges"
        {
            let protocol = if field == "unused_case_http_exchanges" {
                "http"
            } else if field == "unused_case_exchanges" {
                "mysql"
            } else {
                protocol
            };
            if let Some(events) = child.as_array_mut() {
                let mut retained = Vec::with_capacity(events.len());
                for event in std::mem::take(events) {
                    if !excluded.contains(&source::resolve_unused(source, protocol, &event)?) {
                        retained.push(event);
                    }
                }
                *events = retained;
            }
        } else {
            project_unused(child, source, excluded, field)?;
        }
    }
    Ok(())
}

pub(super) fn reconcile(
    root: &Path,
    state: &mut RewriteState,
    source: &source::SourceSnapshot,
) -> Result<Vec<String>> {
    let active_rules = super::rules::fingerprints(&super::rules::load(root)?)?;
    let mut accepted = Vec::new();
    let apis = state
        .dependency_review
        .claims
        .values()
        .filter(|claim| claim.recording_run_id == state.recording_run_id)
        .map(|claim| claim.method_api.clone())
        .collect::<BTreeSet<_>>();
    for api in apis {
        if super::super::verification_obligations::blocks_api(
            &state.dependency_review.obligations,
            &api,
        ) {
            continue;
        }
        let selected = super::super::inventory::scoped(state, Some(&api.parse()?))?;
        if selected.rule_replay_pending || selected.rule_plan.is_some() {
            continue;
        }
        let Ok(mut actual) = actual(root, &selected, source) else {
            continue;
        };
        if actual.unused.is_empty() {
            continue;
        }
        let mut proof_ids = BTreeSet::new();
        let fully_proved = actual.unused.iter().all(|id| {
            state
                .dependency_review
                .decisions
                .get(id)
                .is_some_and(|decision| {
                    super::rules::current(decision, &active_rules)
                        && foreign_owner(source, &decision.owner, &api)
                        && {
                            proof_ids.insert(decision.proof_id.clone());
                            true
                        }
                })
        });
        if !fully_proved {
            continue;
        }
        project_unused(&mut actual.report, source, &actual.unused, "mysql")?;
        if crate::protocols::replay::report::evidence::report_has_case_dirty_events(&actual.report)
        {
            continue;
        }
        let remaining =
            crate::protocols::replay::report::evidence::build_dependency_evidence(&actual.report);
        if remaining
            .case_event_counts
            .values()
            .any(|counts| counts.values().any(|count| *count > 0))
            || !actual.report["dependency_hypothesis_coverage_error"].is_null()
            || !remaining.egress_rejections.is_empty()
            || remaining.omitted_egress_cases > 0
            || actual.report["replay_policy"]["unused_applicable_dependency_rule_ids"]
                .as_array()
                .is_some_and(|rules| !rules.is_empty())
            || actual.report["case_execution_failures"]
                .as_array()
                .is_some_and(|failures| !failures.is_empty())
        {
            continue;
        }
        let receipt = AcceptanceReceipt {
            engine_fingerprint: crate::build_info::ENGINE_FINGERPRINT.into(),
            verdict: "ai-verified".into(),
            api: crate::rewrite::api_selector::public_api(&api).into(),
            method_api: api.clone(),
            recording_run_id: state.recording_run_id.clone(),
            source_revision: selected
                .source_revision
                .clone()
                .context("Source revision absent")?,
            source_inventory_id: source.identity.clone(),
            attempt: actual.attempt,
            session_id: actual.session_id,
            report_sha256: actual.report_sha256,
            execution_identity: actual.execution_identity,
            proof_ids,
            excluded_unused: actual.unused,
            batch_verified: false,
        };
        super::super::inventory::with_slice_mut(state, &api, |slice| {
            slice.phase = RewritePhase::SliceComplete;
            slice.e2e_current = true;
            slice.active_issue = None;
            slice.target_fingerprint =
                Some(super::super::fingerprint::repository_fingerprint(root)?);
            Ok(())
        })?;
        state
            .dependency_review
            .receipts
            .insert(api.clone(), receipt);
        let active = state.api == api;
        if let Some(item) = state.api_inventory.iter_mut().find(|item| item.api == api) {
            item.e2e_current = true;
            if !active {
                item.status = RewriteApiStatus::Complete;
            }
            item.verified_target_fingerprint =
                Some(super::super::fingerprint::repository_fingerprint(root)?);
        }
        accepted.push(api);
    }
    Ok(accepted)
}

pub(super) fn receipt_current(root: &Path, state: &RewriteState, api: &str) -> Result<bool> {
    let Some(receipt) = state.dependency_review.receipts.get(api) else {
        return Ok(false);
    };
    if receipt.engine_fingerprint != crate::build_info::ENGINE_FINGERPRINT
        || receipt.recording_run_id != state.recording_run_id
        || Some(receipt.source_revision.as_str()) != state.source_revision.as_deref()
        || receipt.source_inventory_id != source::inventory_identity(state)?
        || receipt.execution_identity != super::super::fingerprint::replay_identity(root)?
        || super::super::verification_obligations::blocks_api(
            &state.dependency_review.obligations,
            api,
        )
    {
        return Ok(false);
    }
    if state
        .attempts
        .last()
        .is_none_or(|attempt| attempt.attempt != receipt.attempt)
    {
        return Ok(false);
    }
    let active_rules = super::rules::fingerprints(&super::rules::load(root)?)?;
    Ok(receipt.excluded_unused.iter().all(|id| {
        state
            .dependency_review
            .decisions
            .get(id)
            .is_some_and(|decision| {
                receipt.proof_ids.contains(&decision.proof_id)
                    && super::rules::current(decision, &active_rules)
            })
    }))
}

pub(super) fn invalidate_receipts(root: &Path, state: &mut RewriteState) -> Result<()> {
    let active_rules = super::rules::fingerprints(&super::rules::load(root)?)?;
    let inventory_id = state
        .case_source
        .as_ref()
        .map(|_| source::inventory_identity(state))
        .transpose()?;
    let stale = state
        .dependency_review
        .receipts
        .iter()
        .filter(|(_, receipt)| {
            Some(receipt.source_inventory_id.as_str()) != inventory_id.as_deref()
                || receipt.excluded_unused.iter().any(|id| {
                    state
                        .dependency_review
                        .decisions
                        .get(id)
                        .is_none_or(|decision| {
                            !receipt.proof_ids.contains(&decision.proof_id)
                                || !super::rules::current(decision, &active_rules)
                        })
                })
        })
        .map(|(api, _)| api.clone())
        .collect::<Vec<_>>();
    for api in stale {
        state.dependency_review.receipts.remove(&api);
        super::super::inventory::with_slice_mut(state, &api, |slice| {
            slice.phase = RewritePhase::ApiPending;
            slice.e2e_current = false;
            Ok(())
        })?;
        if let Some(item) = state.api_inventory.iter_mut().find(|item| item.api == api) {
            item.status = RewriteApiStatus::Pending;
            item.e2e_current = false;
            item.verified_target_fingerprint = None;
        }
    }
    Ok(())
}

pub(super) fn verify_obligation(root: &Path, state: &mut RewriteState, id: &str) -> Result<String> {
    use crate::rewrite::verification_obligations::{VerificationRequirement, VerificationScope};
    let obligation = state
        .dependency_review
        .obligations
        .get(id)
        .context("verification obligation does not exist")?
        .clone();
    ensure!(
        obligation.pending(),
        "verification obligation is already completed"
    );
    let VerificationScope::Api { api, method, .. } = &obligation.scope else {
        return super::batch_verification::verify(root, state, id);
    };
    if let Ok(session) = super::batch_verification::verify(root, state, id) {
        return Ok(session);
    }
    let method_api = method
        .as_ref()
        .map(|method| format!("{method} {api}"))
        .context("verification requires a concrete original method contract")?;
    let selected = crate::rewrite::inventory::scoped(state, Some(&method_api.parse()?))?;
    ensure!(
        selected.e2e_current
            && selected
                .attempts
                .last()
                .is_some_and(|attempt| attempt.passed),
        "origin obligation requires a current genuinely passing Replay, not an attribution receipt"
    );
    ensure!(
        selected.replay_identity.as_ref()
            == Some(&crate::rewrite::fingerprint::replay_identity(root)?),
        "origin execution inputs changed"
    );
    let context = crate::E2eRunContext {
        target_root: root.into(),
        case_source: selected.case_source.clone().context("Source absent")?,
        run_key: None,
    };
    let group = selected
        .group_id
        .as_deref()
        .context("origin API group absent")?;
    let summary = crate::e2e_run::finalized_focused_attempt_summary(context.clone(), group)?;
    ensure!(
        summary.passed
            && summary.attempt == selected.attempts.last().expect("actual attempt").attempt,
        "origin evidence does not match the current passing attempt"
    );
    let evidence = crate::e2e_run::resolve_e2e_response_rule_evidence(context, group)?;
    let report: Value = serde_json::from_slice(&fs::read(evidence.replay)?)?;
    ensure!(
        report["finalized"] == true,
        "origin Replay did not finalize"
    );
    if obligation.requirement == VerificationRequirement::Capture {
        ensure!(
            state.recording_run_id != obligation.baseline_recording_run_id,
            "capture obligation needs genuinely new Source evidence"
        );
        let source = source::load(state)?;
        ensure!(
            source.apis.values().any(|owner| owner == &method_api),
            "new recording has no complete origin input"
        );
    } else {
        let snapshot =
            crate::rewrite::dependency_attribution_snapshot(root, &state.recording_run_id)?;
        ensure!(
            report["dependency_attribution_snapshot"].as_str() == Some(&snapshot),
            "origin Replay did not execute the current frozen attribution scope"
        );
    }
    let session = report["session_id"]
        .as_str()
        .context("origin actual session identity absent")?
        .to_owned();
    state
        .dependency_review
        .obligations
        .get_mut(id)
        .expect("known obligation")
        .completed_by_session = Some(session.clone());
    Ok(session)
}
