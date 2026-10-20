//! Issue-bound cursors for protected HTTP request diagnostics and body pages.
use super::*;
use crate::replay::http_request_diagnosis::{self, Query};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) fn parse(
    state: &RewriteState,
    issue: &RewriteIssue,
    id: &str,
) -> Option<(Query, Option<String>)> {
    let base = query_id(state, issue, QUERY_HTTP_REQUESTS);
    if id == base {
        return Some((Query::Failures { offset: 0 }, None));
    }
    let suffix = id.strip_prefix(&format!("{base}-"))?;
    let (binding, cursor) = suffix.split_once('-')?;
    if binding.len() != 64
        || !binding.bytes().all(|byte| byte.is_ascii_hexdigit())
        || cursor.len() > 512
    {
        return None;
    }
    let query = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor).ok()?).ok()?;
    Some((query, Some(format!("sha256:{binding}"))))
}

pub(super) fn facts(
    root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    id: &str,
) -> Result<Value> {
    let (query, binding) = parse(state, issue, id).context("HTTP evidence cursor is invalid")?;
    let evidence =
        crate::resolve_e2e_response_rule_evidence(e2e_context(root, state)?, group_id(state)?)?;
    let mut facts =
        http_request_diagnosis::query(&evidence.replay, &state.api, &query, binding.as_deref())?;
    let binding = facts["report_sha256"]
        .as_str()
        .context("HTTP evidence report identity is missing")?
        .to_owned();
    attach_commands(root, state, issue, &binding, &mut facts)?;
    facts["recording_run_id"] = json!(state.recording_run_id);
    facts["attempt"] = json!(issue.attempt);
    Ok(facts)
}

fn attach_commands(
    root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    binding: &str,
    value: &mut Value,
) -> Result<()> {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if key.ends_with("_query") && !value.is_null() {
                    let query: Query = serde_json::from_value(value.clone())?;
                    let id = format!(
                        "{}-{}-{}",
                        query_id(state, issue, QUERY_HTTP_REQUESTS),
                        binding.trim_start_matches("sha256:"),
                        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&query)?)
                    );
                    *value = json!({"query_id":id,"command":super::super::action::command(root,
                    vec!["evidence".into(),id],vec![])});
                } else {
                    attach_commands(root, state, issue, binding, value)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                attach_commands(root, state, issue, binding, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;
