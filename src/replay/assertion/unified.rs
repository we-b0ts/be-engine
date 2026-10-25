//! Primary-response adapter for the same value contracts used by dependencies.
use super::*;
use crate::value_contract::json::AnchorClocks;
#[cfg(test)]
mod global_tests;
#[cfg(test)]
mod tests;

pub(super) fn compare(
    global: Option<&crate::policy::CompiledJsonPolicy>,
    source: &AssertionBody,
    target: &AssertionBody,
    times: RequestTimes,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    let global = global.context("global JSON field strategy missing")?;
    let (source_payload, target_payload) = (source.body(), target.body());
    let clocks = AnchorClocks {
        case: times,
        dependency: times,
        ..Default::default()
    };
    let comparison = crate::value_contract::global::compare(
        source_payload,
        target_payload,
        global,
        &[],
        clocks,
    )?;
    report.identity_pairs.extend(comparison.identity_pairs());
    report.body_codec = if crate::json_value::parse(source_payload).is_some() {
        ResponseBodyCodec::Json
    } else {
        ResponseBodyCodec::ExactBytes
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
