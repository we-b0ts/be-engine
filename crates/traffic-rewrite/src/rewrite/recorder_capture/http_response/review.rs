use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};

use super::{RewriteHttpResponseCapturePlanOptions, rules};
use crate::rewrite::{
    action,
    model::{RewriteHttpResponseCaptureReport, RewriteState},
};

pub(super) fn report(
    target_root: &Path,
    state: &RewriteState,
    options: &RewriteHttpResponseCapturePlanOptions,
    candidates: &[Value],
) -> Result<RewriteHttpResponseCaptureReport> {
    let app = crate::AppConfig::load(super::super::project_config(target_root))?;
    rules::validate_requested(&app, &options.rule)?;
    let path = super::super::source_traffic_policy_path(target_root)?;
    let policy =
        crate::config::SourceTrafficPolicyConfig::parse(&std::fs::read_to_string(&path)?, &path)?;
    let existing: Vec<_> = app.http_response_rewrite.rules.iter()
        .filter(|rule| rules::related(rule, &options.rule))
        .map(|rule| json!({
            "name": rule.authorities.first(), "path_pattern": format!("{} {}", rule.methods.join(","), rules::path(rule)),
            "status_codes": rule.status_codes, "content_types": rule.content_types,
            "managed": policy.http_response_rewrite.contains(rule),
        })).collect();
    let current_path = candidates
        .iter()
        .find(|candidate| {
            candidate["case_id"] == options.case_id
                && candidate["response_id"] == options.response_id
        })
        .map(|candidate| &candidate["path"]);
    let mut arguments = vec!["recorder-capture".into(), "plan-http-response".into()];
    for (flag, value) in [
        ("--evidence-id", options.evidence_id.as_str()),
        ("--case-id", options.case_id.as_str()),
        ("--response-id", options.response_id.as_str()),
        ("--name", options.rule.authorities[0].as_str()),
    ] {
        arguments.extend([flag.into(), value.into()]);
    }
    arguments.extend([
        "--path-pattern".into(),
        format!("{} {}", options.rule.methods[0], rules::path(&options.rule)),
    ]);
    for pointer in &options.rule.pointers {
        arguments.extend(["--pointer".into(), pointer.clone()]);
    }
    Ok(
        RewriteHttpResponseCaptureReport::PathPatternReviewRequired {
            issue_id: state
                .active_issue
                .as_ref()
                .expect("validated active issue")
                .id
                .clone(),
            api: state.api.clone(),
            evidence_id: options.evidence_id.clone(),
            pattern_review: json!({
                "authority": options.rule.authorities[0], "method": options.rule.methods[0],
            "pointer": options.rule.pointers[0], "current_path": current_path,
            "requested_path_pattern": format!("{} {}", options.rule.methods[0], rules::path(&options.rule)),
                "existing_rules": existing,
                "instruction": "Check source path construction, including the first rule. Existing rules share authority, method and pointers; review their paths to decide whether to merge. Choose an exact path or pattern, then explicitly add --pattern-checked and a brief --source-evidence note when rerunning next_command. The engine does not infer dynamic IDs or path similarity.",
                "source_evidence_hint": "One short note is enough, e.g. sandbox_id is dynamic; use /sandboxes/* and consume base_url. No proof format is required.",
            }),
            // Confirmation is deliberately not prefilled in generated commands.
            next_command: action::command(target_root, arguments, Vec::new()),
        },
    )
}
