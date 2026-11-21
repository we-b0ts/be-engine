//! Application control operations for private response relationships and provenance.
use super::*;
use crate::value_contract::identities::IdentityPair;

pub(super) fn control(
    owner: &RequestContracts,
    case: Option<&str>,
    command: &str,
    parameters: &BTreeMap<String, traffic_value::Value>,
) -> Result<Option<Value>> {
    match command {
        "response_time_copies" => {
            let case = case.context("response provenance requires the active case")?;
            Ok(Some(
                serde_json::json!({"ok":true,"time_copies":owner.delivered_time_copies(case)}),
            ))
        }
        "response_identities" => {
            let case = case.context("response relationships require the active case")?;
            let pairs: Vec<IdentityPair> = parameters
                .get("identity_pairs")
                .map(|pairs| serde_json::from_value(serde_json::to_value(pairs)?))
                .transpose()?
                .unwrap_or_default();
            ensure!(
                pairs.len() <= crate::value_contract::response_constraints::MAX_PAIRS,
                "response identity constraint bound exceeded"
            );
            owner.validate_response_identity_formats(&pairs)?;
            owner.commit_identity(owner.preview_identity_pairs(case, &pairs)?)?;
            Ok(Some(serde_json::json!({"ok":true})))
        }
        _ => Ok(None),
    }
}
