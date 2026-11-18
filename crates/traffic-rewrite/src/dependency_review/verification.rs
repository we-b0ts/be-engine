//! Coordinator dispatch of explicit origin verification.
use super::source;
use crate::model::RewriteState;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{fs, path::Path};
pub(super) use traffic_rewrite_attribution::verification::{
    actual, claim_actual, filter_cases, invalidate_receipts, receipt_current, reconcile,
};

pub(super) fn verify_obligation(root: &Path, state: &mut RewriteState, id: &str) -> Result<String> {
    use crate::verification_obligations::{VerificationRequirement, VerificationScope};
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
    let selected = crate::inventory::scoped(state, Some(&method_api.parse()?))?;
    ensure!(
        selected.e2e_current
            && selected
                .attempts
                .last()
                .is_some_and(|attempt| attempt.passed),
        "origin obligation requires a current genuinely passing Replay, not an attribution receipt"
    );
    ensure!(
        selected.replay_identity.as_ref() == Some(&crate::fingerprint::replay_identity(root)?),
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
        let snapshot = crate::dependency_attribution_snapshot(root, &state.recording_run_id)?;
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
