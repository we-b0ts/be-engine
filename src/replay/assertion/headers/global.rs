//! Global header formats participate alongside body identity observations.
use super::*;
pub(super) fn compare(
    source: Option<&HeaderMapSnapshot>,
    target: Option<&HeaderMapSnapshot>,
    policy: &crate::policy::HttpPolicy,
    times: super::super::RequestTimes,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    let (Some(source), Some(target)) = (source, target) else {
        return Ok(());
    };
    let comparison = crate::value_contract::http_headers::compare(
        source,
        target,
        policy,
        crate::value_contract::json::AnchorClocks {
            case: times,
            dependency: times,
            ..Default::default()
        },
    )?;
    let before = crate::value_contract::http_headers::canonical(source)?;
    let after = crate::value_contract::http_headers::canonical(target)?;
    let failed = comparison
        .differences
        .iter()
        .filter_map(|difference| difference.pointer.strip_prefix('/'))
        .filter_map(|pointer| pointer.split('/').next())
        .map(|name| name.replace("~1", "/").replace("~0", "~"))
        .collect::<BTreeSet<_>>();
    for name in policy.headers.keys() {
        let pointer = format!("$headers/{name}");
        report
            .differences
            .retain(|difference| difference.pointer != pointer);
        if failed.contains(name) || (!comparison.passed() && failed.is_empty()) {
            let kind = match (before.contains_key(name), after.contains_key(name)) {
                (true, false) => ResponseDifferenceKind::HeaderMissingActual,
                (false, true) => ResponseDifferenceKind::HeaderUnexpectedActual,
                _ => ResponseDifferenceKind::HeaderValueMismatch,
            };
            report
                .differences
                .push(ResponseDifference::header(name, kind));
        }
    }
    if comparison.passed() {
        report.identity_pairs.extend(comparison.identity_pairs());
        report.applied_header_rule_ids.extend(comparison.evaluated);
    } else {
        report
            .unused_applicable_header_rule_ids
            .extend(comparison.evaluated);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
