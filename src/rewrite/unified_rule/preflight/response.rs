//! Primary status acceptance is separate from rule evidence and publication.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnvalidatedTargetWitness {
    case_id: String,
    surface: String,
    reason: String,
    source_status: u16,
    target_status: u16,
}

pub(super) fn target_pair(
    request: &Value,
    source: &Value,
    target: &Value,
    case: &str,
    result: &mut Preflight,
) -> Result<Option<crate::primary_protocol::assertion::ResponsePayloadPair>> {
    let pair = crate::primary_protocol::assertion::response_rule_payload_pair(
        request,
        source,
        Some(target),
    )?;
    if let Some((source_status, target_status)) = pair.status_difference {
        result
            .unvalidated_target_witnesses
            .insert(UnvalidatedTargetWitness {
                case_id: case.into(),
                surface: "api.response".into(),
                reason: "response_status_differs".into(),
                source_status,
                target_status,
            });
        return Ok(None);
    }
    Ok(Some(pair))
}
