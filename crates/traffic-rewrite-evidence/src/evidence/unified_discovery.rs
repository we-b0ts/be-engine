//! Bind discovery continuations to the same active issue as initial queries.
use super::*;
use crate::unified_rule::discovery::Cursor;

pub fn identifier(state: &RewriteState, issue: &RewriteIssue, cursor: Cursor) -> String {
    query_id(
        state,
        issue,
        &format!("{QUERY_UNIFIED_RULE_CANDIDATES}_cursor_{}", cursor.encode()),
    )
}

pub fn parse(state: &RewriteState, issue: &RewriteIssue, requested: &str) -> Option<Cursor> {
    if requested.len() > 512 {
        return None;
    }
    if requested == query_id(state, issue, QUERY_UNIFIED_RULE_CANDIDATES) {
        return Some(Cursor::initial(state));
    }
    let (_, encoded) = requested.rsplit_once("-cursor-")?;
    let cursor = Cursor::parse(encoded)?;
    (identifier(state, issue, cursor) == requested).then_some(cursor)
}

pub fn facts(
    root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    requested: &str,
) -> Result<Value> {
    let cursor = parse(state, issue, requested).context("stale rule discovery continuation")?;
    let mut facts = super::super::unified_rule::discovery::facts(root, state, cursor)?;
    for (key, public) in [
        ("next_page_cursor", "next_page"),
        ("next_scan_cursor", "next_scan"),
    ] {
        let encoded = facts["pagination"]
            .as_object_mut()
            .and_then(|pagination| pagination.remove(key));
        let Some(encoded) = encoded.as_ref().and_then(Value::as_str) else {
            continue;
        };
        let cursor = Cursor::parse(encoded).context("invalid rule discovery continuation")?;
        let query = identifier(state, issue, cursor);
        facts["pagination"][public] = json!({
            "query_id":query,
            "command":super::super::action::command(root, vec!["evidence".into(), query], vec![])
        });
    }
    Ok(facts)
}

pub fn evidence_id(requested: &str, facts: &Value) -> Result<String> {
    let digest = fingerprint::id(&[requested, &serde_json::to_string(facts)?]);
    let digest = digest.trim_start_matches("fnv1a64:");
    Ok(if requested.contains("-unified-rule-candidates-cursor-") {
        format!("evidence-discovery:{requested}:{digest}")
    } else {
        format!("evidence-{digest}")
    })
}

pub fn report_for_id(
    root: &Path,
    state: &RewriteState,
    evidence: &str,
    attribution: AttributionInformation,
) -> Option<RewriteEvidenceReport> {
    if evidence.len() > 512 {
        return None;
    }
    let (requested, _) = evidence
        .strip_prefix("evidence-discovery:")?
        .rsplit_once(':')?;
    let issue = state.active_issue.as_ref()?;
    parse(state, issue, requested)?;
    let report = super::query(root, state, requested, attribution).ok()?;
    (report.evidence_id == evidence).then_some(report)
}
