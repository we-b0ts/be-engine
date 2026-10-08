//! Report expired rule evidence before offering authoring commands; never mutate state.
use super::*;
use crate::replay::ReplayEvidencePolicyFreshness;

pub(super) fn attach(
    root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    query: &str,
    facts: &mut Value,
) -> Result<Option<String>> {
    if !matches!(query, QUERY_DIRTY_CLUSTERS | QUERY_REPRESENTATIVES)
        || !matches!(
            issue.kind,
            RewriteIssueKind::Response
                | RewriteIssueKind::Replay
                | RewriteIssueKind::Dependency
                | RewriteIssueKind::Comparison
        )
    {
        return Ok(None);
    }
    let current = crate::validate_replay_policy(&root.join(".traffic-e2e/verification.yaml"))?;
    let freshness = if issue.kind == RewriteIssueKind::Comparison {
        let report_path = root
            .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("comparison-recordings")
            .join(
                state
                    .comparison_run_id
                    .as_ref()
                    .context("comparison evidence has no run")?,
            )
            .join("comparison-report.json");
        match std::fs::read(report_path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(anyhow::Error::from))
        {
            Ok(report) => ReplayEvidencePolicyFreshness::new(
                report["policy_fingerprint"].as_str(),
                &current.fingerprint,
            ),
            Err(error) => ReplayEvidencePolicyFreshness::unavailable(
                &current.fingerprint,
                format!("{error:#}"),
            ),
        }
    } else {
        match e2e_context(root, state).and_then(|context| {
            Ok(crate::e2e_run::query_rule_policy_freshness(
                context,
                group_id(state)?,
                &current.fingerprint,
            ))
        }) {
            Ok(freshness) => freshness,
            Err(error) => ReplayEvidencePolicyFreshness::unavailable(
                &current.fingerprint,
                format!("{error:#}"),
            ),
        }
    };
    project(root, state, facts, &freshness)
}

fn project(
    root: &Path,
    state: &RewriteState,
    facts: &mut Value,
    freshness: &ReplayEvidencePolicyFreshness,
) -> Result<Option<String>> {
    let mut value = serde_json::to_value(freshness)?;
    value["api"] = json!(super::super::api_selector::public_api(&state.api));
    value["recording_run_id"] = json!(state.recording_run_id);
    if freshness.requires_fresh_replay {
        value["refresh_command"] = serde_json::to_value(
            super::super::action::next_command_for_selected_api(root, state, &state.api),
        )?;
    }
    facts["policy_freshness"] = value;
    Ok(freshness.requires_fresh_replay.then(|| {
        "The rule evidence is stale or lacks the current verification policy identity. Use policy_freshness.refresh_command through the coordinator and follow its review/scheduling gates to run fresh verification with the existing recording. Then query new evidence and plan the rule. Changing evidence IDs or selectors does not refresh Replay; no new recording is required.".into()
    }))
}

pub(in crate::rewrite) fn ensure_plannable(report: &RewriteEvidenceReport) -> Result<()> {
    let value = &report.facts["policy_freshness"];
    if value["requires_fresh_replay"] != true {
        return Ok(());
    }
    ReplayEvidencePolicyFreshness::new(
        value["evidence_policy_fingerprint"].as_str(),
        value["current_policy_fingerprint"]
            .as_str()
            .unwrap_or("unavailable"),
    )
    .ensure_current("rule evidence")
    .with_context(|| {
        format!(
            "use the coordinator refresh_command returned by evidence {}",
            report.evidence_id
        )
    })
}

pub(super) fn refresh_hint(
    root: &Path,
    facts: &Value,
) -> Option<super::super::evidence_model::RewriteRuleHint> {
    (facts["policy_freshness"]["requires_fresh_replay"] == true).then(|| {
        super::super::evidence_model::RewriteRuleHint {
            capability: "fresh_replay".into(),
            rule: "policy_freshness".into(),
            hint: "verification.yaml changed since this evidence, or its policy identity is unavailable. Follow policy_freshness.refresh_command and the coordinator gates, reuse the existing recordings, then obtain new evidence before planning. This is an evidence freshness requirement, not a missing engine capability or recording-version incompatibility.".into(),
            help: facts["policy_freshness"]["api"].as_str().map_or_else(
                || super::super::action::next_command(root),
                |api| super::super::action::next_command_for_api(root, api)),
        }
    })
}

#[cfg(test)]
mod tests;
