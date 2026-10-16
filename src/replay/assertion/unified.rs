//! Primary-response adapter for the same value contracts used by dependencies.
use super::*;
use crate::policy::{CompiledRule, Surface};
use crate::value_contract::json::{AnchorClocks, Field};
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
    ensure!(
        rules.iter().all(|rule| rule.rule.codec.is_json()),
        "selected response codec has no installed value adapter"
    );
    let source_value = crate::json_value::parse(source.body())
        .context("response contract requires complete unique-member Source JSON")?;
    let target_value = crate::json_value::parse(target.body())
        .context("response contract requires complete unique-member actual Target JSON")?;
    let fields = rules
        .iter()
        .flat_map(|rule| {
            rule.rule
                .contract
                .iter()
                .map(move |(pointer, contract)| Field {
                    rule_id: &rule.rule.id,
                    pointer,
                    contract,
                })
        })
        .collect::<Vec<_>>();
    let comparison = crate::value_contract::json::compare(
        &source_value,
        &target_value,
        &fields,
        AnchorClocks {
            case: times,
            ..Default::default()
        },
    );
    report.body_codec = ResponseBodyCodec::Json;
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
