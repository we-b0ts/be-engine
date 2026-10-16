//! Primary-response adapter for the same value contracts used by dependencies.
use super::*;
use crate::policy::{CompiledRule, Surface};
use crate::value_contract::json::AnchorClocks;
#[cfg(test)]
mod tests;

pub(super) fn selected<'a>(
    loaded: &'a LoadedReplayPolicy,
    request: &RecordedRequest,
    path: &str,
) -> Result<Vec<&'a CompiledRule>> {
    let Some(compiled) = &loaded.compiled else {
        return Ok(vec![]);
    };
    let source_body = request
        .body
        .as_ref()
        .map(|body| decode_body(body, "immutable Source request"))
        .transpose()?
        .and_then(|body| crate::json_value::parse(&body));
    Ok(compiled
        .rules
        .iter()
        .filter(|rule| {
            rule.rule.surface == Surface::ApiResponse
                && rule.rule.selector.matches_api(&request.method, path)
                && rule.rule.when.as_ref().is_none_or(|when| {
                    source_body
                        .as_ref()
                        .is_some_and(|body| when.matches_body(body))
                })
        })
        .collect())
}

pub(super) fn compare(
    rules: &[&CompiledRule],
    source: &AssertionBody,
    target: &AssertionBody,
    times: RequestTimes,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    let codec = crate::value_contract::encoded::merged_codec(rules)?;
    let comparison = crate::value_contract::encoded::compare(
        source.body(),
        target.body(),
        rules,
        AnchorClocks {
            case: times,
            ..Default::default()
        },
    )?;
    report.body_codec = match codec {
        crate::policy::Codec::Json => ResponseBodyCodec::Json,
        crate::policy::Codec::Protobuf(_) => ResponseBodyCodec::Protobuf,
    };
    report.applied_body_rule_ids.extend(comparison.evaluated);
    for diff in comparison.differences {
        let mut difference = ResponseDifference::body_value_mismatch();
        difference.pointer = diff.pointer;
        report.differences.push(difference);
    }
    if let Some(difference) = source.type_difference(target) {
        report.differences.push(difference);
    }
    if !source.gateway_metadata_matches(target) {
        report
            .differences
            .push(ResponseDifference::gateway_metadata_mismatch());
    }
    Ok(())
}
