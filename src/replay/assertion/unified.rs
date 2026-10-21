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
    Ok(applicable(loaded, request, path)?
        .into_iter()
        .filter(|rule| rule.rule.slot == crate::policy::Slot::Body)
        .collect())
}

pub(super) fn selected_interaction<'a>(
    loaded: &'a LoadedReplayPolicy,
    request: &RecordedRequest,
    path: &str,
) -> Result<Vec<&'a CompiledRule>> {
    Ok(applicable(loaded, request, path)?
        .into_iter()
        .filter(|rule| matches!(rule.rule.slot, crate::policy::Slot::SseData(_)))
        .collect())
}

fn applicable<'a>(
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
    let (source_payload, target_payload) = if matches!(codec, crate::policy::Codec::Protobuf(_)) {
        super::protobuf::payload_pair(source.body(), target.body())?
    } else {
        (source.body(), target.body())
    };
    let comparison = crate::value_contract::encoded::compare(
        source_payload,
        target_payload,
        rules,
        AnchorClocks {
            case: times,
            dependency: times,
            ..Default::default()
        },
    )?;
    report.body_codec = match codec {
        crate::policy::Codec::Json => ResponseBodyCodec::Json,
        crate::policy::Codec::Protobuf(_) => ResponseBodyCodec::Protobuf,
    };
    report.applied_body_rule_ids.extend(comparison.evaluated);
    for diff in comparison.differences {
        report.differences.push(contract_difference(diff));
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

/// Preserve domain diagnostics without exposing payloads or private key errors.
pub(super) fn contract_difference(
    diff: crate::value_contract::json::Difference,
) -> ResponseDifference {
    use ResponseDifferenceKind as K;
    let mut difference = ResponseDifference::body_value_mismatch();
    difference.pointer = diff.pointer;
    let jwt = [
        K::JwtAlgorithmMismatch,
        K::JwtSignatureInvalid,
        K::JwtClaimsMismatch,
        K::JwtTimeMismatch,
        K::JwtNonceMismatch,
        K::JwtUrlMismatch,
        K::JwtExpiryMismatch,
        K::JwtInvalid,
        K::TimeReferenceMissing,
    ];
    difference.kind = jwt
        .into_iter()
        .find(|kind| diff.reason.contains(&format!("{kind:?}")))
        .unwrap_or_else(|| match diff.reason.as_str() {
            "authenticated nonce bijection changed" => K::JwtNonceMismatch,
            "field presence changed" => K::MissingActual,
            "unexpected field" => K::UnexpectedActual,
            "array cardinality changed" => K::ArrayLengthMismatch,
            "generated contract rejected value: InvalidType" => K::GeneratedFieldNotScalar,
            "unordered requires two arrays" => K::UnorderedFieldNotArray,
            "unordered multiset changed" => K::UnorderedArrayContentMismatch,
            "joined collection requires two strings" => K::UnorderedJoinedStringFieldNotString,
            "joined multiset changed" => K::UnorderedJoinedStringContentMismatch,
            reason
                if reason.contains("ReferenceMissing")
                    || reason == "time relation requires independent source and target anchors" =>
            {
                K::TimeReferenceMissing
            }
            reason
                if reason.contains("OutsideWindow")
                    || reason == "timestamp is outside the fixed five-second anchor window" =>
            {
                K::TimestampOutsideRequestWindow
            }
            reason
                if reason.contains("DeltaMismatch")
                    || reason.contains("RelationshipMismatch")
                    || reason == "time difference does not preserve the anchor difference"
                    || reason == "time parameter relationship changed" =>
            {
                K::DurationDeltaMismatch
            }
            reason
                if reason.contains("NumericCategoryChanged")
                    || reason.contains("InvalidValue")
                    || reason == "timestamp numeric category changed"
                    || reason == "invalid time value" =>
            {
                K::TimeFieldInvalid
            }
            _ => K::ValueMismatch,
        });
    difference
}
