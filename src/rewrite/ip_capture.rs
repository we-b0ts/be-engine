//! The defect submission preflight for caller-reported IP acquisition gaps.
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::json;

use super::evidence_model::RewriteEvidenceReport;
use super::model::{RewriteIssueKind, RewritePhase, RewriteState};
use super::{evidence, recorder_capture, response_url_evidence};

#[derive(Debug, Clone, Serialize)]
pub struct RewriteIpCaptureReport {
    pub accepted: bool,
    pub kind: String,
    pub summary: String,
    pub required_inputs: Vec<String>,
    pub evidence: RewriteEvidenceReport,
}

pub(super) fn investigate(
    target_root: &Path,
    state: &mut RewriteState,
    evidence_id: &str,
    source_ref: &str,
    case_id: String,
    endpoint: String,
    origin: String,
) -> Result<RewriteIpCaptureReport> {
    let issue = recorder_capture::capture_issue(state)?;
    recorder_capture::validate_plan_evidence(target_root, state, &issue.id, evidence_id)?;
    recorder_capture::validate_single_line("IP source reference", source_ref)?;
    let address: SocketAddr = endpoint
        .parse()
        .context("unrecorded IP requires a literal IP:port endpoint")?;
    ensure!(
        address.port() != 0,
        "unrecorded IP endpoint requires a nonzero port"
    );
    ensure!(
        matches!(
            origin.as_str(),
            "unknown" | "http-response" | "static" | "other"
        ),
        "IP origin must be unknown, http-response, static, or other"
    );
    ensure!(
        state.recorder_capture_plan.is_none(),
        "a recorder capture plan is pending; execute status action.commands.apply before reporting another IP"
    );
    state
        .active_issue
        .as_mut()
        .context("issue disappeared")?
        .recorder_capture_diagnosis = Some(json!({
        "kind":"unrecorded_ip", "case_id":case_id, "endpoint":address.to_string(),
        "origin":origin, "source_ref":source_ref, "reported_by":"target_analysis",
        "baseline":state.case_source,
    }));
    let command = evidence::commands(target_root, state)
        .into_iter()
        .find(|command| command.query_id.ends_with("-ip-capture"))
        .context("IP capture evidence command missing")?;
    let report = evidence::query(target_root, state, &command.query_id)?;
    let (kind, summary, required) = disposition(&report.facts);
    state.bump();
    Ok(RewriteIpCaptureReport {
        accepted: false,
        kind: kind.to_string(),
        summary: summary.to_string(),
        required_inputs: required,
        evidence: report,
    })
}

fn disposition(facts: &serde_json::Value) -> (&'static str, &'static str, Vec<String>) {
    match facts["reported"]["origin"].as_str() {
        Some("http-response") if has_unconfigured_candidates(facts) => (
            "recorder_capture_required",
            "A recorded JSON URL matches the reported IP. Plan/apply its response rewrite and verify a fresh recording before submitting a system defect.",
            vec!["source file:line and symbol proving consumption of the selected response pointer".into()],
        ),
        Some("http-response") if !facts["http_response_url_candidates"].as_array().is_none_or(Vec::is_empty) => (
            "capture_rule_verification_required",
            "A matching rewrite rule is already configured. Inspect whether the failing recording loaded it; use plan/apply to refresh an older baseline. A remaining defect report must cite the fresh recording and required engine change.",
            vec!["fresh recording evidence and why the configured rule did not capture the dependency".into()],
        ),
        Some("static") => ("source_configuration_required", "Trace the static endpoint to source configuration or a source mock; JSON response rewriting does not apply.", vec!["source configuration or hardcoded call location and its required source-side change".into()]),
        Some("other") => ("source_investigation_required", "Document the address acquisition mechanism and why existing capture mechanisms cannot represent it before submitting a capability gap.", vec!["source acquisition mechanism and unsupported capture requirement".into()]),
        _ => ("source_investigation_required", "Identify the IP origin and inspect the exact upstream response and dependencies; an IP omission report alone does not establish a system defect.", vec!["--ip-origin http-response|static|other".into(), "source file:line and symbol tracing the IP origin; exact upstream response and pointer when applicable".into()]),
    }
}

fn has_unconfigured_candidates(facts: &serde_json::Value) -> bool {
    facts["http_response_url_candidates"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|candidate| {
            candidate["configured_rules"]
                .as_array()
                .is_none_or(Vec::is_empty)
        })
}

pub(super) fn ensure_before_system_repair(
    target_root: &Path,
    state: &RewriteState,
    kind: &str,
) -> Result<()> {
    if !matches!(kind, "recorder_capability_gap" | "replay_capability_gap") {
        return Ok(());
    }
    ensure!(
        state.recorder_capture_plan.is_none(),
        "a recorder capture plan is pending; execute status action.commands.apply and verify the refreshed recording before submitting a system defect"
    );
    let Some(reported) = state
        .active_issue
        .as_ref()
        .and_then(|issue| issue.recorder_capture_diagnosis.as_ref())
    else {
        return Ok(());
    };
    ensure!(
        reported["origin"] != "unknown",
        "IP origin is unresolved; update route --cause unrecorded-ip with source proof before submitting a system defect"
    );
    if reported["origin"] == "http-response" {
        let facts = response_url_evidence::facts(target_root, state)?;
        ensure!(
            !has_unconfigured_candidates(&facts),
            "the reported IP has supported JSON response rewrite candidates; execute the ip_capture evidence planner and apply, then verify a fresh recording before submitting a system defect"
        );
    }
    ensure!(
        state.phase == RewritePhase::ImplementationRequired
            && state.active_issue.as_ref().is_some_and(|issue| matches!(
                issue.kind,
                RewriteIssueKind::Response
                    | RewriteIssueKind::Dependency
                    | RewriteIssueKind::Comparison
                    | RewriteIssueKind::Replay
            )),
        "IP capture investigation has no active verification issue"
    );
    Ok(())
}
