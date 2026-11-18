//! Authenticated actual Replay evidence for ownership claims and acceptance.
use crate::{attribution_projection::filter_cases, model::RewriteState};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path};
use traffic_rewrite_rules::rewrite::dependency_review::source;
use uuid::Uuid;

pub struct ActualAttempt {
    pub attempt: u64,
    pub execution_identity: String,
    pub report_sha256: String,
    pub session_id: String,
    pub unused: BTreeSet<Uuid>,
    report: Value,
}

impl ActualAttempt {
    pub fn missing_sequences(&self, source: &source::SourceSnapshot) -> BTreeSet<Uuid> {
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

/// Reporting disputed ownership requires real unused evidence, not a passing
/// response or an implementer's proof of who actually owns the occurrence.
pub fn claim_actual(
    root: &Path,
    state: &RewriteState,
    source: &source::SourceSnapshot,
) -> Result<ActualAttempt> {
    let attempt = state
        .attempts
        .last()
        .context("API has no real Replay attempt")?;
    let execution_identity = crate::fingerprint::replay_identity(root)?;
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

impl ActualAttempt {
    /// Project independently proved foreign unused occurrences, preserving every other failure.
    pub fn without_unused_is_clean(&mut self, source: &source::SourceSnapshot) -> Result<bool> {
        project_unused(&mut self.report, source, &self.unused, "mysql")?;
        if crate::protocols::replay::report::evidence::report_has_case_dirty_events(&self.report) {
            return Ok(false);
        }
        let remaining =
            crate::protocols::replay::report::evidence::build_dependency_evidence(&self.report);
        if remaining
            .case_event_counts
            .values()
            .any(|counts| counts.values().any(|count| *count > 0))
            || !self.report["dependency_hypothesis_coverage_error"].is_null()
            || !remaining.egress_rejections.is_empty()
            || remaining.omitted_egress_cases > 0
            || self.report["replay_policy"]["unused_applicable_dependency_rule_ids"]
                .as_array()
                .is_some_and(|rules| !rules.is_empty())
            || self.report["case_execution_failures"]
                .as_array()
                .is_some_and(|failures| !failures.is_empty())
        {
            return Ok(false);
        }
        Ok(true)
    }
}
